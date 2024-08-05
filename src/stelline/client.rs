#![allow(clippy::type_complexity)]
use std::boxed::Box;
use std::collections::HashMap;
use std::future::{ready, Future};
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;
use std::vec::Vec;

use bytes::Bytes;
#[cfg(all(feature = "std", test))]
use mock_instant::thread_local::MockClock;
use tracing::{debug, info_span, trace};
use tracing_subscriber::EnvFilter;

use crate::base::iana::{Opcode, OptionCode};
use crate::base::opt::{ComposeOptData, OptData};
use crate::base::{Message, MessageBuilder};
use crate::net::client::request::{
    ComposeRequest, ComposeRequestMulti, Error, GetResponse, GetResponseMulti, RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti,
};
use crate::stelline::matches::match_multi_msg;
use crate::zonefile::inplace::Entry::Record;

use super::matches::match_msg;
use super::parse_stelline::{Entry, Reply, Stelline, StepType};

use super::channel::DEF_CLIENT_ADDR;

//----------- StellineError ---------------------------------------------------

#[derive(Debug)]
pub struct StellineError<'a> {
    _stelline: &'a Stelline,
    step_value: &'a CurrStepValue,
    cause: StellineErrorCause,
}

impl<'a> std::fmt::Display for StellineError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Stelline test failed at step {} with error: {}",
            self.step_value, self.cause
        ))
    }
}

impl<'a> StellineError<'a> {
    pub fn from_cause(
        stelline: &'a Stelline,
        step_value: &'a CurrStepValue,
        cause: StellineErrorCause,
    ) -> Self {
        Self {
            _stelline: stelline,
            step_value,
            cause,
        }
    }
}

//----------- StellineErrorCause ----------------------------------------------

#[derive(Debug)]
pub enum StellineErrorCause {
    ClientError(Error),
    MismatchedAnswer,
    MissingResponse,
    MissingStepEntry,
    MissingClient,
    AnswerTimedOut,
}

impl From<Error> for StellineErrorCause {
    fn from(err: Error) -> Self {
        Self::ClientError(err)
    }
}

impl std::fmt::Display for StellineErrorCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StellineErrorCause::ClientError(err) => {
                f.write_fmt(format_args!("Client error: {err}"))
            }
            StellineErrorCause::MismatchedAnswer => {
                f.write_str("Mismatched answer")
            }
            StellineErrorCause::MissingClient => {
                f.write_str("Missing client")
            }
            StellineErrorCause::MissingResponse => {
                f.write_str("Missing response")
            }
            StellineErrorCause::MissingStepEntry => {
                f.write_str("Missing step entry")
            }
            StellineErrorCause::AnswerTimedOut => {
                f.write_str("Timed out waiting for answer")
            }
        }
    }
}

//----------- do_client_simple() ----------------------------------------------

// This function handles the client part of a Stelline script. If works only
// with SendRequest and is used to test the various client transport
// implementations. This frees do_client of supporting SendRequest.
pub async fn do_client_simple<R: SendRequest<RequestMessage<Vec<u8>>>>(
    stelline: &Stelline,
    step_value: &CurrStepValue,
    request: R,
) {
    async fn inner<R: SendRequest<RequestMessage<Vec<u8>>>>(
        stelline: &Stelline,
        step_value: &CurrStepValue,
        request: R,
    ) -> Result<(), StellineErrorCause> {
        let mut resp: Option<Message<Bytes>> = None;

        // Assume steps are in order. Maybe we need to define that.
        for step in &stelline.scenario.steps {
            let span =
                info_span!("step", "{}:{}", step.step_value, step.step_type);
            let _guard = span.enter();

            debug!("Processing step");
            step_value.set(step.step_value);
            match step.step_type {
                StepType::Query => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;
                    let reqmsg = entry2reqmsg(entry);
                    let mut req = request.send_request(reqmsg);
                    resp = Some(req.get_response().await?);

                    trace!(?resp);
                }
                StepType::CheckAnswer => {
                    let answer = resp
                        .take()
                        .ok_or(StellineErrorCause::MissingResponse)?;
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;
                    if !match_msg(entry, &answer, true) {
                        return Err(StellineErrorCause::MismatchedAnswer);
                    }
                }
                StepType::TimePasses => {
                    let duration =
                        Duration::from_secs(step.time_passes.unwrap());
                    tokio::time::advance(duration).await;
                    /*
                    #[cfg(feature = "mock-time")]
                    MockClock::advance_system_time(duration);
                    */
                }
                StepType::Traffic
                | StepType::CheckTempfile
                | StepType::Assign => todo!(),
            }
        }

        Ok(())
    }

    init_logging();

    let name = stelline
        .name
        .rsplit_once('/')
        .unwrap_or(("", &stelline.name))
        .1;
    let span = tracing::info_span!("stelline", "{}", name);
    let _guard = span.enter();
    if let Err(cause) = inner(stelline, step_value, request).await {
        panic!("{}", StellineError::from_cause(stelline, step_value, cause));
    }
}

//----------- Dispatcher -----------------------------------------------------

pub struct Dispatcher(
    Option<Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>>,
);

impl Dispatcher {
    pub fn with_client<T>(client: T) -> Self
    where
        T: SendRequest<RequestMessage<Vec<u8>>> + 'static,
    {
        Self(Some(Rc::new(Box::new(client))))
    }

    pub fn with_rc_boxed_client(
        client: Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>,
    ) -> Self {
        Self(Some(client))
    }

    pub fn without_client() -> Self {
        Self(None)
    }

    pub fn dispatch(
        &self,
        entry: &Entry,
    ) -> Result<Box<dyn GetResponse + Send + Sync>, StellineErrorCause> {
        if let Some(dispatcher) = &self.0 {
            let reqmsg = entry2reqmsg(entry);
            trace!(?reqmsg);
            return Ok(dispatcher.send_request(reqmsg));
        }

        Err(StellineErrorCause::MissingClient)
    }
}

//----------- DispatcherMulti -------------------------------------------------

pub struct DispatcherMulti(
    Option<Rc<Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>>>,
);

impl DispatcherMulti {
    pub fn with_client<T>(client: T) -> Self
    where
        T: SendRequestMulti<RequestMessageMulti<Vec<u8>>> + 'static,
    {
        Self(Some(Rc::new(Box::new(client))))
    }

    pub fn with_rc_boxed_client(
        client: Rc<Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>>,
    ) -> Self {
        Self(Some(client))
    }

    pub fn without_client() -> Self {
        Self(None)
    }

    pub fn dispatch(
        &self,
        entry: &Entry,
    ) -> Result<Box<dyn GetResponseMulti + Send + Sync>, StellineErrorCause> {
        if let Some(dispatcher) = &self.0 {
            let reqmsg = entry2reqmsg_multi(entry);
            trace!(?reqmsg);
            return Ok(dispatcher.send_request(reqmsg));
        }

        Err(StellineErrorCause::MissingClient)
    }
}

//----------- ClientFactory --------------------------------------------------

pub trait ClientFactory {
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = Dispatcher>>>;

    fn is_suitable(&self, _entry: &Entry) -> bool {
        true
    }

    fn discard(&mut self, entry: &Entry);
}

//----------- ClientFactoryMulti ----------------------------------------------

pub trait ClientFactoryMulti {
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = DispatcherMulti>>>;

    fn is_suitable(&self, _entry: &Entry) -> bool {
        true
    }

    fn discard(&mut self, entry: &Entry);
}

//----------- SingleClientFactoryMulti ----------------------------------------

pub struct SingleClientFactoryMulti(
    Rc<Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>>,
);

impl SingleClientFactoryMulti {
    pub fn new(
        client: impl SendRequestMulti<RequestMessageMulti<Vec<u8>>> + 'static,
    ) -> Self {
        Self(Rc::new(Box::new(client)))
    }
}

impl ClientFactoryMulti for SingleClientFactoryMulti {
    fn get(
        &mut self,
        _entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = DispatcherMulti>>> {
        Box::pin(ready(DispatcherMulti::with_rc_boxed_client(self.0.clone())))
    }

    fn discard(&mut self, _entry: &Entry) {
        // Cannot discard the only client we have, nothing to do.
    }
}

//----------- PerClientAddressClientFactory -----------------------------------

pub struct PerClientAddressClientFactory<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    clients_by_address:
        HashMap<IpAddr, Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>>,
    factory_func: F,
    is_suitable_func: S,
}

impl<F, S> PerClientAddressClientFactory<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    pub fn new(factory_func: F, is_suitable_func: S) -> Self {
        Self {
            clients_by_address: Default::default(),
            factory_func,
            is_suitable_func,
        }
    }
}

impl<F, S> ClientFactory for PerClientAddressClientFactory<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = Dispatcher>>> {
        // Use an existing connection if one for the same client address
        // already exists, otherwise create a new one.
        let client_addr = entry.client_addr.unwrap_or(DEF_CLIENT_ADDR);

        let client = self
            .clients_by_address
            .entry(client_addr)
            .or_insert_with_key(|addr| {
                Rc::new((self.factory_func)(addr, entry))
            })
            .clone();

        Box::pin(ready(Dispatcher::with_rc_boxed_client(client)))
    }

    fn discard(&mut self, entry: &Entry) {
        let client_addr = entry.client_addr.unwrap_or(DEF_CLIENT_ADDR);
        let _ = self.clients_by_address.remove(&client_addr);
    }

    fn is_suitable(&self, entry: &Entry) -> bool {
        (self.is_suitable_func)(entry)
    }
}

//----------- PerClientAddressClientFactoryMulti ------------------------------

pub struct PerClientAddressClientFactoryMulti<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    clients_by_address:
        HashMap<IpAddr, Rc<Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>>>,
    factory_func: F,
    is_suitable_func: S,
}

impl<F, S> PerClientAddressClientFactoryMulti<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    pub fn new(factory_func: F, is_suitable_func: S) -> Self {
        Self {
            clients_by_address: Default::default(),
            factory_func,
            is_suitable_func,
        }
    }
}

impl<F, S> ClientFactoryMulti for PerClientAddressClientFactoryMulti<F, S>
where
    F: Fn(&IpAddr, &Entry) -> Box<dyn SendRequestMulti<RequestMessageMulti<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = DispatcherMulti>>> {
        // Use an existing connection if one for the same client address
        // already exists, otherwise create a new one.
        let client_addr = entry.client_addr.unwrap_or(DEF_CLIENT_ADDR);

        let client = self
            .clients_by_address
            .entry(client_addr)
            .or_insert_with_key(|addr| {
                Rc::new((self.factory_func)(addr, entry))
            })
            .clone();

        Box::pin(ready(DispatcherMulti::with_rc_boxed_client(client)))
    }

    fn discard(&mut self, entry: &Entry) {
        let client_addr = entry.client_addr.unwrap_or(DEF_CLIENT_ADDR);
        let _ = self.clients_by_address.remove(&client_addr);
    }

    fn is_suitable(&self, entry: &Entry) -> bool {
        (self.is_suitable_func)(entry)
    }
}

//----------- QueryTailoredClientFactory -------------------------------------

pub struct QueryTailoredClientFactory {
    factories: Vec<Box<dyn ClientFactory>>,
}

impl QueryTailoredClientFactory {
    pub fn new(factories: Vec<Box<dyn ClientFactory>>) -> Self {
        Self { factories }
    }
}

impl ClientFactory for QueryTailoredClientFactory {
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = Dispatcher>>> {
        for f in &mut self.factories {
            if f.is_suitable(entry) {
                return Box::pin(f.get(entry));
            }
        }

        Box::pin(ready(Dispatcher::without_client()))
    }

    fn discard(&mut self, entry: &Entry) {
        for f in &mut self.factories {
            if f.is_suitable(entry) {
                f.discard(entry);
            }
        }
    }
}

//----------- QueryTailoredClientFactoryMulti ---------------------------------

pub struct QueryTailoredClientFactoryMulti {
    factories: Vec<Box<dyn ClientFactoryMulti>>,
}

impl QueryTailoredClientFactoryMulti {
    pub fn new(factories: Vec<Box<dyn ClientFactoryMulti>>) -> Self {
        Self { factories }
    }
}

impl ClientFactoryMulti for QueryTailoredClientFactoryMulti {
    fn get(
        &mut self,
        entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = DispatcherMulti>>> {
        for f in &mut self.factories {
            if f.is_suitable(entry) {
                return Box::pin(f.get(entry));
            }
        }

        Box::pin(ready(DispatcherMulti::without_client()))
    }

    fn discard(&mut self, entry: &Entry) {
        for f in &mut self.factories {
            if f.is_suitable(entry) {
                f.discard(entry);
            }
        }
    }
}

//----------- do_client() ----------------------------------------------------

// This function handles the client part of a Stelline script. It is meant
// to test server code. This code need refactoring. The do_client_simple
// function takes care of supporting SendRequest, so no need to support that
// here. UDP support can be made simplere by removing any notion of a
// connection and associating a source address with every request. TCP
// suport can be made simpler because the test code does not have to be
// careful about the TcpKeepalive option and just keep the connection open.
pub async fn do_client<'a, T: ClientFactory>(
    stelline: &'a Stelline,
    step_value: &'a CurrStepValue,
    client_factory: T,
) {
    async fn inner<T: ClientFactory>(
        stelline: &Stelline,
        step_value: &CurrStepValue,
        mut client_factory: T,
    ) -> Result<(), StellineErrorCause> {
        let mut last_sent_request: Option<
            Box<dyn GetResponse + Sync + Send>,
        > = None;

        #[cfg(all(feature = "std", test))]
        {
            trace!("Setting mock system time to zero.");
            MockClock::set_system_time(Duration::ZERO);
        }

        // Assume steps are in order. Maybe we need to define that.
        for step in &stelline.scenario.steps {
            let span =
                info_span!("step", "{}:{}", step.step_value, step.step_type);
            let _guard = span.enter();

            debug!("Processing step");
            step_value.set(step.step_value);
            match step.step_type {
                StepType::Query => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;

                    // Dispatch the request to a suitable client.
                    let mut send_request =
                        client_factory.get(entry).await.dispatch(entry);

                    // If the client is no longer connected, discard it and
                    // try again with a new client.
                    if let Err(StellineErrorCause::ClientError(
                        Error::ConnectionClosed,
                    )) = send_request
                    {
                        client_factory.discard(entry);
                        send_request =
                            client_factory.get(entry).await.dispatch(entry);
                    }

                    last_sent_request = Some(send_request?);
                }
                StepType::CheckAnswer => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;

                    let Some(mut send_request) = last_sent_request else {
                        return Err(StellineErrorCause::MissingResponse);
                    };

                    // NOTE: Calling .get_response() on a non-streaming
                    // request will only work once at the time of writing, the
                    // dgram client implementation will fail if called a
                    // second time with error that the future has already been
                    // awaited. Either the streaming response mechanism needs
                    // to be implemented differently, or all client
                    // implementations need to be safe to call for a
                    // subsequent response.

                    if entry
                        .matches
                        .as_ref()
                        .map(|v| v.extra_packets)
                        .unwrap_or_default()
                    {
			// We should not be here. No stream response in do_client.
			todo!();
                    } else {
                        let num_expected_answers = entry
                            .sections
                            .as_ref()
                            .map(|section| section.answer.len())
                            .unwrap_or_default();

                        for idx in 0..num_expected_answers {
                            trace!(
                                "Awaiting answer {}/{num_expected_answers}...",
                                idx + 1
                            );
                            let resp = tokio::time::timeout(
                                Duration::from_secs(3),
                                send_request.get_response(),
                            )
                            .await
                            .map_err(|_| {
                                StellineErrorCause::AnswerTimedOut
                            })??;
                            trace!("Received answer.");
                            trace!(?resp);
                            if !match_multi_msg(
                                entry, idx, &resp, true, &mut None,
                            ) {
                                return Err(
                                    StellineErrorCause::MismatchedAnswer,
                                );
                            }
                        }
                    }

                    last_sent_request = None;
                }
                StepType::TimePasses => {
                    let duration =
                        Duration::from_secs(step.time_passes.unwrap());
                    tokio::time::advance(duration).await;
                    #[cfg(all(feature = "std", test))]
                    {
                        trace!(
                            "Advancing mock system time by {} seconds...",
                            duration.as_secs()
                        );
                        MockClock::advance_system_time(duration);
                    }
                }
                StepType::Traffic
                | StepType::CheckTempfile
                | StepType::Assign => todo!(),
            }
        }

        Ok(())
    }

    init_logging();

    let name = stelline
        .name
        .rsplit_once('/')
        .unwrap_or(("", &stelline.name))
        .1;
    let span = tracing::info_span!("stelline", "{}", name);
    let _guard = span.enter();
    if let Err(cause) = inner(stelline, step_value, client_factory).await {
        panic!("{}", StellineError::from_cause(stelline, step_value, cause));
    }
}

//----------- do_client_multi() -----------------------------------------------

// This function handles the client part of a Stelline script. It is meant
// to test server code. This code need refactoring. The do_client_simple
// function takes care of supporting SendRequest, so no need to support that
// here. UDP support can be made simplere by removing any notion of a
// connection and associating a source address with every request. TCP
// suport can be made simpler because the test code does not have to be
// careful about the TcpKeepalive option and just keep the connection open.
pub async fn do_client_multi<'a, T: ClientFactoryMulti>(
    stelline: &'a Stelline,
    step_value: &'a CurrStepValue,
    client_factory: T,
) {
    async fn inner<T: ClientFactoryMulti>(
        stelline: &Stelline,
        step_value: &CurrStepValue,
        mut client_factory: T,
    ) -> Result<(), StellineErrorCause> {
        let mut last_sent_request: Option<
            Box<dyn GetResponseMulti + Sync + Send>,
        > = None;

        #[cfg(all(feature = "std", test))]
        {
            trace!("Setting mock system time to zero.");
            MockClock::set_system_time(Duration::ZERO);
        }

        // Assume steps are in order. Maybe we need to define that.
        for step in &stelline.scenario.steps {
            let span =
                info_span!("step", "{}:{}", step.step_value, step.step_type);
            let _guard = span.enter();

            debug!("Processing step");
            step_value.set(step.step_value);
            match step.step_type {
                StepType::Query => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;

                    // Dispatch the request to a suitable client.
                    let mut send_request =
                        client_factory.get(entry).await.dispatch(entry);

                    // If the client is no longer connected, discard it and
                    // try again with a new client.
                    if let Err(StellineErrorCause::ClientError(
                        Error::ConnectionClosed,
                    )) = send_request
                    {
                        client_factory.discard(entry);
                        send_request =
                            client_factory.get(entry).await.dispatch(entry);
                    }

                    last_sent_request = Some(send_request?);
                }
                StepType::CheckAnswer => {
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(StellineErrorCause::MissingStepEntry)?;

                    let Some(mut send_request) = last_sent_request else {
                        return Err(StellineErrorCause::MissingResponse);
                    };

                    // NOTE: Calling .get_response() on a non-streaming
                    // request will only work once at the time of writing, the
                    // dgram client implementation will fail if called a
                    // second time with error that the future has already been
                    // awaited. Either the streaming response mechanism needs
                    // to be implemented differently, or all client
                    // implementations need to be safe to call for a
                    // subsequent response.

                    if entry
                        .matches
                        .as_ref()
                        .map(|v| v.extra_packets)
                        .unwrap_or_default()
                    {
                        // This assumes that the client used for the test knows
                        // how to detect the last response in a set of
                        // responses, e.g. the xfr client knows how to detect
                        // the last response in an AXFR/IXFR response set.
                        trace!("Awaiting an unknown number of answers");
                        let mut entry = entry.clone();
                        loop {
                            let resp = tokio::time::timeout(
                                Duration::from_secs(3),
                                send_request.get_response(),
                            )
                            .await
                            .map_err(|_| {
                                StellineErrorCause::AnswerTimedOut
                            })??;
                            trace!("Received answer.");
                            trace!(?resp);

                            let mut out_entry = Some(vec![]);
                            match_multi_msg(
                                &entry,
                                0,
                                &resp,
                                true,
                                &mut out_entry,
                            );
                            let num_rrs_remaining_after = out_entry
                                .as_ref()
                                .map(|entries| entries.len())
                                .unwrap_or_default();
                            if let Some(section) = &mut entry.sections {
                                section.answer[0] = out_entry.unwrap();
                            }
                            trace!("Answer RRs remaining = {num_rrs_remaining_after}");

                            if send_request.is_stream_complete() {
                                trace!("Stream complete");
                                if !entry.sections.as_ref().unwrap().answer[0]
                                    .is_empty()
                                {
                                    return Err(
                                        StellineErrorCause::MismatchedAnswer,
                                    );
                                } else {
                                    break;
                                }
                            }
                        }
                    } else {
                        let num_expected_answers = entry
                            .sections
                            .as_ref()
                            .map(|section| section.answer.len())
                            .unwrap_or_default();

                        for idx in 0..num_expected_answers {
                            trace!(
                                "Awaiting answer {}/{num_expected_answers}...",
                                idx + 1
                            );
                            let resp = tokio::time::timeout(
                                Duration::from_secs(3),
                                send_request.get_response(),
                            )
                            .await
                            .map_err(|_| {
                                StellineErrorCause::AnswerTimedOut
                            })??;
                            trace!("Received answer.");
                            trace!(?resp);
                            if !match_multi_msg(
                                entry, idx, &resp, true, &mut None,
                            ) {
                                return Err(
                                    StellineErrorCause::MismatchedAnswer,
                                );
                            }
                        }

                        if num_expected_answers > 1 {
                            send_request.stream_complete().unwrap();
                        }
                    }

                    last_sent_request = None;
                }
                StepType::TimePasses => {
                    let duration =
                        Duration::from_secs(step.time_passes.unwrap());
                    tokio::time::advance(duration).await;
                    #[cfg(all(feature = "std", test))]
                    {
                        trace!(
                            "Advancing mock system time by {} seconds...",
                            duration.as_secs()
                        );
                        MockClock::advance_system_time(duration);
                    }
                }
                StepType::Traffic
                | StepType::CheckTempfile
                | StepType::Assign => todo!(),
            }
        }

        Ok(())
    }

    init_logging();

    let name = stelline
        .name
        .rsplit_once('/')
        .unwrap_or(("", &stelline.name))
        .1;
    let span = tracing::info_span!("stelline", "{}", name);
    let _guard = span.enter();
    if let Err(cause) = inner(stelline, step_value, client_factory).await {
        panic!("{}", StellineError::from_cause(stelline, step_value, cause));
    }
}

/// Setup logging of events reported by domain and the test suite.
///
/// Use the RUST_LOG environment variable to override the defaults.
///
/// E.g. To enable debug level logging:
///   RUST_LOG=DEBUG
///
/// Or to log only the steps processed by the Stelline client:
///   RUST_LOG=net_server::net::stelline::client=DEBUG
///
/// Or to enable trace level logging but not for the test suite itself:
///   RUST_LOG=TRACE,net_server=OFF
fn init_logging() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();
}

fn entry2reqmsg(entry: &Entry) -> RequestMessage<Vec<u8>> {
    let sections = entry.sections.as_ref().unwrap();
    let mut msg = MessageBuilder::new_vec().question();
    if let Some(opcode) = entry.opcode {
        msg.header_mut().set_opcode(opcode);
    }
    for q in &sections.question {
        msg.push(q).unwrap();
    }
    let msg = msg.answer();
    for _a in &sections.answer[0] {
        todo!();
    }
    let mut msg = msg.authority();
    for zone_file_entry in &sections.authority {
        if let Record(rec) = zone_file_entry {
            msg.push(rec).unwrap();
        }
    }
    let mut msg = msg.additional();
    for zone_file_entry in &sections.additional.zone_entries {
        if let Record(rec) = zone_file_entry {
            msg.push(rec).unwrap();
        }
    }
    let reply: Reply = match &entry.reply {
        Some(reply) => reply.clone(),
        None => Default::default(),
    };
    let header = msg.header_mut();
    header.set_rd(reply.rd);
    header.set_ad(reply.ad);
    header.set_cd(reply.cd);
    let msg = msg.into_message();

    let mut reqmsg = RequestMessage::new(msg);
    if !entry
        .matches
        .as_ref()
        .map(|v| v.mock_client)
        .unwrap_or_default()
    {
        reqmsg.set_dnssec_ok(reply.fl_do);
    }
    if reply.notify {
        reqmsg.header_mut().set_opcode(Opcode::NOTIFY);
    }

    let edns_bytes = &sections.additional.edns_bytes;
    if !edns_bytes.is_empty() {
        let raw_opt = RawOptData { bytes: edns_bytes };
        reqmsg.add_opt(&raw_opt).unwrap();
    }

    reqmsg
}

fn entry2reqmsg_multi(entry: &Entry) -> RequestMessageMulti<Vec<u8>> {
    let sections = entry.sections.as_ref().unwrap();
    let mut msg = MessageBuilder::new_vec().question();
    if let Some(opcode) = entry.opcode {
        msg.header_mut().set_opcode(opcode);
    }
    for q in &sections.question {
        msg.push(q).unwrap();
    }
    let msg = msg.answer();
    for _a in &sections.answer[0] {
        todo!();
    }
    let mut msg = msg.authority();
    for zone_file_entry in &sections.authority {
        if let Record(rec) = zone_file_entry {
            msg.push(rec).unwrap();
        }
    }
    let mut msg = msg.additional();
    for zone_file_entry in &sections.additional.zone_entries {
        if let Record(rec) = zone_file_entry {
            msg.push(rec).unwrap();
        }
    }
    let reply: Reply = match &entry.reply {
        Some(reply) => reply.clone(),
        None => Default::default(),
    };
    let header = msg.header_mut();
    header.set_rd(reply.rd);
    header.set_ad(reply.ad);
    header.set_cd(reply.cd);
    let msg = msg.into_message();

    let mut reqmsg = RequestMessageMulti::new(msg);
    if !entry
        .matches
        .as_ref()
        .map(|v| v.mock_client)
        .unwrap_or_default()
    {
        reqmsg.set_dnssec_ok(reply.fl_do);
    }
    if reply.notify {
        reqmsg.header_mut().set_opcode(Opcode::NOTIFY);
    }

    let edns_bytes = &sections.additional.edns_bytes;
    if !edns_bytes.is_empty() {
        let raw_opt = RawOptData { bytes: edns_bytes };
        reqmsg.add_opt(&raw_opt).unwrap();
    }

    reqmsg
}

#[derive(Debug)]
pub struct CurrStepValue {
    v: Mutex<u64>,
}

impl CurrStepValue {
    pub fn new() -> Self {
        Self { v: 0.into() }
    }
    fn set(&self, v: u64) {
        let mut self_v = self.v.lock().unwrap();
        *self_v = v;
    }
    pub fn get(&self) -> u64 {
        *(self.v.lock().unwrap())
    }
}

impl Default for CurrStepValue {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for CurrStepValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.get()))
    }
}

//----------- RawOptData -----------------------------------------------------

struct RawOptData<'a> {
    bytes: &'a [u8],
}

impl<'a> OptData for RawOptData<'a> {
    fn code(&self) -> OptionCode {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap()).into()
    }
}

impl<'a> ComposeOptData for RawOptData<'a> {
    fn compose_len(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    fn compose_option<Target: octseq::OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.bytes[4..])
    }
}
