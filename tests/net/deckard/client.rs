#![allow(clippy::type_complexity)]

use crate::net::deckard::matches::match_msg;
use crate::net::deckard::parse_deckard::{Deckard, Entry, Reply, StepType};
use crate::net::deckard::parse_query;
use bytes::Bytes;

use domain::base::iana::Opcode;
use domain::base::opt::{ComposeOptData, OptData};
use domain::base::{Message, MessageBuilder};
use domain::net::client::request::{
    ComposeRequest, Error, RequestMessage, SendRequest,
};
use std::collections::HashMap;
use std::future::{ready, Future};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Mutex;
use std::time::Duration;
use tracing::{debug, info_span, trace};
use tracing_subscriber::EnvFilter;

#[cfg(feature = "mock-time")]
use mock_instant::MockClock;

use super::channel::DEF_CLIENT_ADDR;

//----------- DeckardError ---------------------------------------------------

#[derive(Debug)]
pub struct DeckardError<'a> {
    _deckard: &'a Deckard,
    step_value: &'a CurrStepValue,
    cause: DeckardErrorCause,
}

impl<'a> std::fmt::Display for DeckardError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Deckard test failed at step {} with error: {}",
            self.step_value, self.cause
        ))
    }
}

impl<'a> DeckardError<'a> {
    pub fn from_cause(
        deckard: &'a Deckard,
        step_value: &'a CurrStepValue,
        cause: DeckardErrorCause,
    ) -> Self {
        Self {
            _deckard: deckard,
            step_value,
            cause,
        }
    }
}

//----------- DeckardErrorCause ----------------------------------------------

#[derive(Debug)]
pub enum DeckardErrorCause {
    ClientError(domain::net::client::request::Error),
    MismatchedAnswer,
    MissingResponse,
    MissingStepEntry,
    MissingClient,
}

impl From<domain::net::client::request::Error> for DeckardErrorCause {
    fn from(err: domain::net::client::request::Error) -> Self {
        Self::ClientError(err)
    }
}

impl std::fmt::Display for DeckardErrorCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeckardErrorCause::ClientError(err) => {
                f.write_fmt(format_args!("Client error: {err}"))
            }
            DeckardErrorCause::MismatchedAnswer => {
                f.write_str("Mismatched answer")
            }
            DeckardErrorCause::MissingClient => f.write_str("Missing client"),
            DeckardErrorCause::MissingResponse => {
                f.write_str("Missing response")
            }
            DeckardErrorCause::MissingStepEntry => {
                f.write_str("Missing step entry")
            }
        }
    }
}

//----------- Dispatcher -----------------------------------------------------

pub struct Dispatcher(
    Option<Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>>,
);

impl Dispatcher {
    #[allow(dead_code)]
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

    pub async fn dispatch(
        &self,
        entry: &Entry,
    ) -> Result<Option<Message<Bytes>>, DeckardErrorCause> {
        if let Some(dispatcher) = &self.0 {
            let reqmsg = entry2reqmsg(entry);
            trace!(?reqmsg);
            let mut req = dispatcher.send_request(reqmsg);
            return Ok(Some(req.get_response().await?));
        }

        Err(DeckardErrorCause::MissingClient)
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

//----------- SingleClientFactory --------------------------------------------

pub struct SingleClientFactory(
    Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>,
);

impl SingleClientFactory {
    #[allow(dead_code)]
    pub fn new(
        client: impl SendRequest<RequestMessage<Vec<u8>>> + 'static,
    ) -> Self {
        Self(Rc::new(Box::new(client)))
    }
}

impl ClientFactory for SingleClientFactory {
    fn get(
        &mut self,
        _entry: &Entry,
    ) -> Pin<Box<dyn Future<Output = Dispatcher>>> {
        Box::pin(ready(Dispatcher::with_rc_boxed_client(self.0.clone())))
    }

    fn discard(&mut self, _entry: &Entry) {
        // Cannot discard the only client we have, nothing to do.
    }
}

//----------- PerClientAddressClientFactory ----------------------------------

pub struct PerClientAddressClientFactory<F, S>
where
    F: Fn(&IpAddr) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    clients_by_address:
        HashMap<IpAddr, Rc<Box<dyn SendRequest<RequestMessage<Vec<u8>>>>>>,
    factory_func: F,
    is_suitable_func: S,
}

impl<F, S> PerClientAddressClientFactory<F, S>
where
    F: Fn(&IpAddr) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
    S: Fn(&Entry) -> bool,
{
    #[allow(dead_code)]
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
    F: Fn(&IpAddr) -> Box<dyn SendRequest<RequestMessage<Vec<u8>>>>,
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
            .or_insert_with_key(|addr| Rc::new((self.factory_func)(addr)))
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

//----------- QueryTailoredClientFactory -------------------------------------

pub struct QueryTailoredClientFactory {
    factories: Vec<Box<dyn ClientFactory>>,
}

impl QueryTailoredClientFactory {
    #[allow(dead_code)]
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

//----------- do_client() ----------------------------------------------------

pub async fn do_client<'a, T: ClientFactory>(
    deckard: &'a Deckard,
    step_value: &'a CurrStepValue,
    client_factory: T,
) {
    async fn inner<T: ClientFactory>(
        deckard: &Deckard,
        step_value: &CurrStepValue,
        mut client_factory: T,
    ) -> Result<(), DeckardErrorCause> {
        let mut resp: Option<Message<Bytes>> = None;

        // Assume steps are in order. Maybe we need to define that.
        for step in &deckard.scenario.steps {
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
                        .ok_or(DeckardErrorCause::MissingStepEntry)?;

                    // Dispatch the request to a suitable client.
                    let mut res =
                        client_factory.get(entry).await.dispatch(entry).await;

                    // If the client is no longer connected, discard it and
                    // try again with a new client.
                    if let Err(DeckardErrorCause::ClientError(
                        Error::ConnectionClosed,
                    )) = res
                    {
                        client_factory.discard(entry);
                        res = client_factory
                            .get(entry)
                            .await
                            .dispatch(entry)
                            .await;
                    }

                    resp = res?;

                    trace!(?resp);
                }
                StepType::CheckAnswer => {
                    let answer = resp
                        .take()
                        .ok_or(DeckardErrorCause::MissingResponse)?;
                    let entry = step
                        .entry
                        .as_ref()
                        .ok_or(DeckardErrorCause::MissingStepEntry)?;
                    if !match_msg(entry, &answer, true) {
                        return Err(DeckardErrorCause::MismatchedAnswer);
                    }
                }
                StepType::TimePasses => {
                    let duration =
                        Duration::from_secs(step.time_passes.unwrap());
                    tokio::time::advance(duration).await;
                    #[cfg(feature = "mock-time")]
                    MockClock::advance_system_time(duration);
                }
                StepType::Traffic
                | StepType::CheckTempfile
                | StepType::Assign => todo!(),
            }
        }

        Ok(())
    }

    init_logging();

    let name = deckard
        .name
        .rsplit_once('/')
        .unwrap_or(("", &deckard.name))
        .1;
    let span = tracing::info_span!("deckard", "{}", name);
    let _guard = span.enter();
    if let Err(cause) = inner(deckard, step_value, client_factory).await {
        panic!("{}", DeckardError::from_cause(deckard, step_value, cause));
    }
}

/// Setup logging of events reported by domain and the test suite.
///
/// Use the RUST_LOG environment variable to override the defaults.
///
/// E.g. To enable debug level logging:
///   RUST_LOG=DEBUG
///
/// Or to log only the steps processed by the Deckard client:
///   RUST_LOG=net_server::net::deckard::client=DEBUG
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
    for q in &sections.question {
        let question = match q {
            parse_query::Entry::QueryRecord(question) => question,
            _ => todo!(),
        };
        msg.push(question).unwrap();
    }
    let msg = msg.answer();
    for _a in &sections.answer {
        todo!();
    }
    let msg = msg.authority();
    for _a in &sections.authority {
        todo!();
    }
    let mut msg = msg.additional();
    for _a in &sections.additional.zone_entries {
        todo!();
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
    reqmsg.set_dnssec_ok(reply.fl_do);
    if reply.notify {
        reqmsg.header_mut().set_opcode(Opcode::Notify);
    }

    let edns_bytes = &sections.additional.edns_bytes;
    if !edns_bytes.is_empty() {
        let raw_opt = RawOptData { bytes: edns_bytes };
        reqmsg.add_opt(&raw_opt).unwrap();
    }

    if let Some(client_addr) = entry.client_addr {
        reqmsg.set_source_address(SocketAddr::new(client_addr, 0));
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
    fn code(&self) -> domain::base::iana::OptionCode {
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
