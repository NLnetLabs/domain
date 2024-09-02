//! TODO
#![cfg(all(feature = "tsig", feature = "unstable-client-transport"))]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use core::ops::DerefMut;

use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use tracing::{debug, trace, warn};

use crate::base::message::CopyRecordsError;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::Message;
use crate::base::StaticCompressor;
use crate::net::client::request::{
    ComposeRequest, ComposeRequestMulti, Error, GetResponse,
    GetResponseMulti, SendRequest, SendRequestMulti,
};
use crate::rdata::tsig::Time48;
use crate::tsig::{ClientSequence, ClientTransaction, Key};

/// TODO
#[derive(Clone, Debug)]
enum TsigClient<K> {
    /// TODO
    Transaction(ClientTransaction<K>),
    // TODO
    //Sequence(ClientSequence<K>),
}

/// TODO
#[derive(Clone, Debug)]
enum TsigClientMulti<K> {
    /// TODO
    //Transaction(ClientTransaction<K>),

    /// TODO
    Sequence(ClientSequence<K>),
}

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// TODO
pub struct Connection<Upstream, K> {
    /// Upstream transport to use for requests.
    ///
    /// This should be the final transport, there should be no further
    /// modification to the request before it is sent to the recipient.
    upstream: Arc<Upstream>,

    /// TODO
    key: Option<K>,
}

impl<Upstream, K> Connection<Upstream, K> {
    /// TODO
    pub fn new(key: Option<K>, upstream: Upstream) -> Self {
        Self {
            upstream: Arc::new(upstream),
            key,
        }
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream, K> SendRequest<CR> for Connection<Upstream, K>
where
    CR: ComposeRequest + 'static,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR, K>>
        + Send
        + Sync
        + 'static,
    K: Clone + AsRef<Key> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::<CR, Upstream, K>::new(
            request_msg,
            self.key.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ SendRequestMulti ----------------------------------------------------

/*
impl<CR, Upstream, K> SendRequestMulti<CR> for Connection<Upstream, K>
where
    CR: ComposeRequestMulti + 'static,
    Upstream: SendRequestMulti<AuthenticatedRequestMessage<CR, K>>
        + Send
        + Sync
        + 'static,
    K: Clone + AsRef<Key> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(RequestMulti::<CR, Upstream, K>::new(
            request_msg,
            self.key.clone(),
            self.upstream.clone(),
        ))
    }
}
*/

impl<CR, Upstream, K> SendRequestMulti<CR> for Connection<Upstream, K>
where
    CR: ComposeRequestMulti + 'static,
    Upstream: SendRequestMulti<AuthenticatedRequestMessageMulti<CR, K>>
        + Send
        + Sync
        + 'static,
    K: Clone + AsRef<Key> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(RequestMulti::<CR, Upstream, K>::new(
            request_msg,
            self.key.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream, K>
where
    CR: ComposeRequest,
{
    /// State of the request.
    state: RequestState<K>,

    /// The request message.
    request_msg: Option<CR>,

    /// TODO
    key: Option<K>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,
}

impl<CR, Upstream, K> Request<CR, Upstream, K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR, K>> + Send + Sync,
    K: Clone + AsRef<Key>,
    Self: GetResponse,
{
    /// Create a new Request object.
    fn new(request_msg: CR, key: Option<K>, upstream: Arc<Upstream>) -> Self {
        Self {
            state: RequestState::Init,
            request_msg: Some(request_msg),
            key,
            upstream,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        let res = loop {
            match &mut self.state {
                RequestState::Init => {
                    let tsig_client = Arc::new(std::sync::Mutex::new(None));

                    // TODO: TSIG sign the request, and send the signed version
                    // upstream.
                    let msg = AuthenticatedRequestMessage {
                        request: self.request_msg.take().unwrap(),
                        key: self.key.clone(),
                        signer: tsig_client.clone(),
                    };

                    trace!("Sending request upstream...");
                    let request = self.upstream.send_request(msg);
                    self.state =
                        RequestState::GetResponse(request, tsig_client);
                    continue;
                }

                RequestState::GetResponse(request, tsig_client) => {
                    trace!("Receiving response");
                    let response = request.get_response().await;
                    if self.key.is_some() {
                        assert!(tsig_client.lock().unwrap().is_some());
                    }

                    // TSIG validation
                    match response {
                        Ok(msg) => {
                            let mut modifiable_msg = Message::from_octets(
                                msg.as_slice().to_vec(),
                            )?;

                            let mut locked = tsig_client.lock().unwrap();
                            match locked.deref_mut() {
                                Some(TsigClient::Transaction(client)) => {
                                    trace!(
                                        "Validating TSIG for single reply"
                                    );
                                    client
                                        .answer(
                                            &mut modifiable_msg,
                                            Time48::now(),
                                        )
                                        .map_err(|err| {
                                            Error::Authentication(err)
                                        })?;
                                }

                                _ => {
                                    trace!("Response is not signed, nothing to do");
                                }
                            }

                            let out_vec = modifiable_msg.into_octets();
                            let out_bytes = Bytes::from(out_vec);
                            let out_msg =
                                Message::<Bytes>::from_octets(out_bytes)?;
                            break Ok(out_msg);
                        }

                        Err(err) => break Err(err),
                    }
                }
            }
        };

        res
    }
}

impl<CR, Upstream, K> Debug for Request<CR, Upstream, K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR, K>>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request").finish()
    }
}

impl<CR, Upstream, K> GetResponse for Request<CR, Upstream, K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR, K>> + Send + Sync,
    K: Clone + AsRef<Key> + Send + Sync,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Message<Bytes>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ RequestMulti ---------------------------------------------------

/// The state of a request that is executed.
pub struct RequestMulti<CR, Upstream, K>
where
    CR: ComposeRequestMulti,
{
    /// State of the request.
    state: RequestStateMulti<K>,

    /// The request message.
    request_msg: Option<CR>,

    /// TODO
    key: Option<K>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,
}

impl<CR, Upstream, K> RequestMulti<CR, Upstream, K>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<AuthenticatedRequestMessageMulti<CR, K>>
        + Send
        + Sync,
    K: Clone + AsRef<Key>,
    Self: GetResponseMulti,
{
    /// Create a new Request object.
    fn new(request_msg: CR, key: Option<K>, upstream: Arc<Upstream>) -> Self {
        Self {
            state: RequestStateMulti::Init,
            request_msg: Some(request_msg),
            key,
            upstream,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(
        &mut self,
    ) -> Result<Option<Message<Bytes>>, Error> {
        let res = loop {
            match &mut self.state {
                RequestStateMulti::Init => {
                    let tsig_client = Arc::new(std::sync::Mutex::new(None));

                    // TODO: TSIG sign the request, and send the signed version
                    // upstream.
                    let msg = AuthenticatedRequestMessageMulti {
                        request: self.request_msg.take().unwrap(),
                        key: self.key.clone(),
                        signer: tsig_client.clone(),
                    };

                    trace!("Sending request upstream...");
                    let request = self.upstream.send_request(msg);
                    self.state =
                        RequestStateMulti::GetResponse(request, tsig_client);
                    continue;
                }

                RequestStateMulti::GetResponse(request, tsig_client) => {
                    let response = request.get_response().await;
                    if response.is_ok() && self.key.is_some() {
                        assert!(tsig_client.lock().unwrap().is_some());
                    }

                    // TSIG validation
                    match response {
                        Ok(msg) => {
                            let msg = match msg {
                                Some(msg) => msg,
                                None => {
                                    match &mut self.state {
                                        RequestStateMulti::Init => {
                                            debug!("Ignoring attempt to complete TSIG stream that hasn't been read from yet.");
                                        }

                                        RequestStateMulti::GetResponse(
                                            ref mut _request,
                                            _tsig_client,
                                        ) => {
                                            self.state =
                                                RequestStateMulti::Complete;
                                        }

                                        RequestStateMulti::Complete => {
                                            debug!("Ignoring attempt to complete TSIG stream that is already complete.");
                                        }
                                    }
                                    break Ok(None);
                                }
                            };
                            let mut modifiable_msg = Message::from_octets(
                                msg.as_slice().to_vec(),
                            )?;

                            let mut locked = tsig_client.lock().unwrap();
                            match locked.deref_mut() {
                                Some(TsigClientMulti::Sequence(client)) => {
                                    trace!(
                                        "Validating TSIG for sequence reply"
                                    );
                                    client
                                        .answer(
                                            &mut modifiable_msg,
                                            Time48::now(),
                                        )
                                        .map_err(|err| {
                                            Error::Authentication(err)
                                        })?;
                                }

                                _ => {
                                    trace!("Response is not signed, nothing to do");
                                }
                            }

                            let out_vec = modifiable_msg.into_octets();
                            let out_bytes = Bytes::from(out_vec);
                            let out_msg =
                                Message::<Bytes>::from_octets(out_bytes)?;
                            break Ok(Some(out_msg));
                        }

                        Err(err) => break Err(err),
                    }
                }

                RequestStateMulti::Complete => {
                    break Err(Error::StreamReceiveError);
                }
            }
        };

        trace!("Leaving");
        res
    }
}

impl<CR, Upstream, K> Debug for RequestMulti<CR, Upstream, K>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<AuthenticatedRequestMessageMulti<CR, K>>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request").finish()
    }
}

impl<CR, Upstream, K> GetResponseMulti for RequestMulti<CR, Upstream, K>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<AuthenticatedRequestMessageMulti<CR, K>>
        + Send
        + Sync,
    K: Clone + AsRef<Key> + Send + Sync,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<Message<Bytes>>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ RequestState ---------------------------------------------------
/// States of the state machine in get_response_impl
enum RequestState<K> {
    /// Initial state, perform a cache lookup.
    Init,

    /// Wait for a response and insert the response in the cache.
    GetResponse(
        Box<dyn GetResponse + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ),
}

//------------ RequestStateMulti ----------------------------------------------
/// States of the state machine in get_response_impl
enum RequestStateMulti<K> {
    /// Initial state, perform a cache lookup.
    Init,

    /// Wait for a response and insert the response in the cache.
    GetResponse(
        Box<dyn GetResponseMulti + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClientMulti<K>>>>,
    ),

    /// TODO
    Complete,
}

//------------ AuthenticatedRequestMessage ------------------------------------

/// TODO
#[derive(Debug)]
pub struct AuthenticatedRequestMessage<CR, K>
where
    CR: Send + Sync,
{
    /// TODO
    request: CR,

    /// TODO
    key: Option<K>,

    /// TODO
    signer: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
}

impl<CR, K> ComposeRequest for AuthenticatedRequestMessage<CR, K>
where
    CR: ComposeRequest,
    K: Clone + Debug + Send + Sync + AsRef<Key>,
{
    // Used by the stream transport.
    fn append_message<Target: Composer>(
        &self,
        target: Target,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        let mut target = self.request.append_message(target)?;

        if let Some(key) = &self.key {
            let client = {
                trace!(
                    "Signing single request transaction with key '{}'",
                    key.as_ref().name()
                );
                TsigClient::Transaction(
                    ClientTransaction::request(
                        key.clone(),
                        &mut target,
                        Time48::now(),
                    )
                    .unwrap(),
                )
            };

            *self.signer.lock().unwrap() = Some(client);
        } else {
            trace!("No signing key was configured for this request, nothing to do");
        }

        Ok(target)
    }

    fn to_vec(&self) -> Result<Vec<u8>, Error> {
        let msg = self.to_message()?;
        Ok(msg.as_octets().clone())
    }

    fn to_message(&self) -> Result<Message<Vec<u8>>, Error> {
        let mut target = StaticCompressor::new(Vec::new());

        self.append_message(&mut target)?;

        // It would be nice to use .builder() here. But that one deletes all
        // sections. We have to resort to .as_builder() which gives a
        // reference and then .clone()
        let msg = Message::from_octets(target.into_target()).expect(
            "Message should be able to parse output from MessageBuilder",
        );
        Ok(msg)
    }

    fn header(&self) -> &crate::base::Header {
        self.request.header()
    }

    fn header_mut(&mut self) -> &mut crate::base::Header {
        self.request.header_mut()
    }

    fn set_udp_payload_size(&mut self, value: u16) {
        self.request.set_udp_payload_size(value)
    }

    fn is_streaming(&self) -> bool {
        self.request.is_streaming()
    }

    fn set_dnssec_ok(&mut self, value: bool) {
        self.request.set_dnssec_ok(value)
    }

    fn add_opt(
        &mut self,
        opt: &impl crate::base::opt::ComposeOptData,
    ) -> Result<(), crate::base::opt::LongOptData> {
        self.request.add_opt(opt)
    }

    fn is_answer(&self, answer: &Message<[u8]>) -> bool {
        self.request.is_answer(answer)
    }

    fn dnssec_ok(&self) -> bool {
        self.request.dnssec_ok()
    }
}

//------------ AuthenticatedRequestMessageMulti -------------------------------

/// TODO
#[derive(Debug)]
pub struct AuthenticatedRequestMessageMulti<CR, K>
where
    CR: Send + Sync,
{
    /// TODO
    request: CR,

    /// TODO
    key: Option<K>,

    /// TODO
    signer: Arc<std::sync::Mutex<Option<TsigClientMulti<K>>>>,
}

impl<CR, K> AuthenticatedRequestMessageMulti<CR, K>
where
    CR: ComposeRequestMulti + Send + Sync,
    K: Clone + Debug + Send + Sync + AsRef<Key>,
{
    /// Create new message based on the changes to the base message.
    fn to_message_impl(&self) -> Result<Message<Vec<u8>>, Error> {
        let target = StaticCompressor::new(Vec::new());

        let target = self.append_message(target)?;

        // It would be nice to use .builder() here. But that one deletes all
        // sections. We have to resort to .as_builder() which gives a
        // reference and then .clone()
        let result = target.as_builder().clone();
        let msg = Message::from_octets(result.finish().into_target()).expect(
            "Message should be able to parse output from MessageBuilder",
        );
        Ok(msg)
    }
}

impl<CR, K> ComposeRequestMulti for AuthenticatedRequestMessageMulti<CR, K>
where
    CR: ComposeRequestMulti,
    K: Clone + Debug + Send + Sync + AsRef<Key>,
{
    // Used by the stream transport.
    fn append_message<Target: Composer>(
        &self,
        target: Target,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        trace!("append_message()");
        let mut target = self.request.append_message(target)?;

        if let Some(key) = &self.key {
            let client = {
                trace!(
                    "Signing streaming request sequence with key '{}'",
                    key.as_ref().name()
                );
                TsigClientMulti::Sequence(
                    ClientSequence::request(
                        key.clone(),
                        &mut target,
                        Time48::now(),
                    )
                    .unwrap(),
                )
            };

            *self.signer.lock().unwrap() = Some(client);
        } else {
            trace!("No signing key was configured for this request, nothing to do");
        }

        Ok(target)
    }

    fn to_message(&self) -> Result<Message<Vec<u8>>, Error> {
        self.to_message_impl()
    }

    fn header(&self) -> &crate::base::Header {
        self.request.header()
    }

    fn header_mut(&mut self) -> &mut crate::base::Header {
        self.request.header_mut()
    }

    fn set_udp_payload_size(&mut self, value: u16) {
        self.request.set_udp_payload_size(value)
    }

    fn set_dnssec_ok(&mut self, value: bool) {
        self.request.set_dnssec_ok(value)
    }

    fn add_opt(
        &mut self,
        opt: &impl crate::base::opt::ComposeOptData,
    ) -> Result<(), crate::base::opt::LongOptData> {
        self.request.add_opt(opt)
    }

    fn is_answer(&self, answer: &Message<[u8]>) -> bool {
        self.request.is_answer(answer)
    }

    fn is_streaming(&self) -> bool {
        self.request.is_streaming()
    }

    fn dnssec_ok(&self) -> bool {
        self.request.dnssec_ok()
    }
}
