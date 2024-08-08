//! A transport that signs requests and verifies response signatures.
//!
//! This module implements an [RFC 8945] Secret Key Transaction Authentication
//! for DNS (TSIG) client transport.
//!
//! This client cannot be used on its own, instead it must be used with an
//! upstream transport. The upstream transport must build the message then
//! send it without modifying it as that could invalidate the signature. The
//! upstream transport must also not modify the response as that could cause
//! signature verification to fail.
//!
//! [RFC 8945]: https://www.rfc-editor.org/rfc/rfc8945.html
#![cfg(all(feature = "tsig", feature = "unstable-client-transport"))]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use core::convert::AsRef;
use core::ops::DerefMut;

use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use octseq::Octets;
use tracing::{debug, trace, warn};

use crate::base::message::CopyRecordsError;
use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::Composer;
use crate::base::{Message, StaticCompressor};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::rdata::tsig::Time48;
use crate::tsig::{ClientSequence, ClientTransaction, Key, ValidationError};

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// A connection that TSIG signs requests and verifies upstream responses.
pub struct Connection<Upstream, K> {
    /// Upstream transport to use for requests.
    ///
    /// This should be the final transport, there should be no further
    /// modification to the request before it is sent to the recipient.
    upstream: Arc<Upstream>,

    /// The TSIG key to sign with.
    ///
    /// If None, signing will be skipped.
    key: Option<K>,
}

impl<Upstream, K> Connection<Upstream, K> {
    /// Create a new TSIG transport with default configuration.
    ///
    /// Requests will be signed with the given key, if any, then sent via the
    /// provided upstream transport.
    pub fn new(key: Option<K>, upstream: Upstream) -> Self {
        Self {
            upstream: Arc::new(upstream),
            key,
        }
    }
}

//--- SendRequest

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

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
struct Request<CR, Upstream, K>
where
    CR: ComposeRequest,
{
    /// State of the request.
    state: RequestState<K>,

    /// The request message.
    request_msg: Option<CR>,

    /// The key to sign the request with.
    ///
    /// If None, no signing will be done.
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
        let mut mark_as_complete = false;

        let res = loop {
            match &mut self.state {
                RequestState::Init => {
                    let tsig_client = Arc::new(std::sync::Mutex::new(None));

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

                            let mut client = tsig_client.lock().unwrap();
                            if let Some(client) = client.deref_mut() {
                                client
                                    .answer(
                                        &mut modifiable_msg,
                                        Time48::now(),
                                    )
                                    .map_err(Error::Authentication)?;
                            }

                            if request.is_stream_complete() {
                                mark_as_complete = true;
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

                RequestState::Complete => {
                    break Err(Error::StreamReceiveError);
                }
            }
        };

        if mark_as_complete {
            self.stream_complete()?;
        }

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

    fn stream_complete(&mut self) -> Result<(), Error> {
        match &mut self.state {
            RequestState::Init => {
                debug!("Ignoring attempt to complete TSIG stream that hasn't been read from yet.");
            }

            RequestState::GetResponse(ref mut request, tsig_client) => {
                if let Some(client) = tsig_client.lock().unwrap().take() {
                    trace!("Completing TSIG sequence");
                    client.done().map_err(Error::Authentication)?;
                    request.stream_complete()?;
                }

                self.state = RequestState::Complete;
            }

            RequestState::Complete => {
                debug!("Ignoring attempt to complete TSIG stream that is already complete.");
            }
        }

        Ok(())
    }

    fn is_stream_complete(&self) -> bool {
        matches!(self.state, RequestState::Complete)
    }
}

//------------ RequestState ---------------------------------------------------

/// States of the state machine in get_response_impl
enum RequestState<K> {
    /// Initial state, prepare the request for signing.
    Init,

    /// Wait for a response and verify it.
    GetResponse(
        Box<dyn GetResponse + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ),

    /// The response has been received.
    Complete,
}

//------------ AuthenticatedRequestMessage ------------------------------------

/// A wrapper around a [`ComposeRequest`] impl that signs the request.
#[derive(Debug)]
pub struct AuthenticatedRequestMessage<CR, K>
where
    CR: Send + Sync,
{
    /// The request to sign.
    request: CR,

    /// The key to sign the request with.
    ///
    /// If None, signing will be skipped.
    key: Option<K>,

    /// The TSIG signing client.
    ///
    /// Used to sign the request and verify the response.
    ///
    /// If None, signing was skipped because no key was supplied.
    signer: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
}

impl<CR, K> ComposeRequest for AuthenticatedRequestMessage<CR, K>
where
    CR: ComposeRequest,
    K: Clone + Debug + Send + Sync + AsRef<Key>,
{
    /// Writes the message to a provided composer.
    ///
    /// Use [`to_message()`] instead if you can. This function should only be
    /// used to supply the target to write to. This client MUST be the final
    /// modifier of the message before it is finished. Modifying the built
    /// message using the returned builder could invalidate the TSIG message
    /// signature.
    ///
    /// [`to_message()`]: Self::to_message
    fn to_message_builder<Target: Composer>(
        &self,
        target: Target,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        let mut target = self.request.to_message_builder(target)?;

        if let Some(key) = &self.key {
            let client = TsigClient::request(
                key.clone(),
                &mut target,
                Time48::now(),
                self.request.is_streaming(),
            )
            .unwrap();

            *self.signer.lock().unwrap() = Some(client);
        } else {
            trace!("No signing key was configured for this request, nothing to do");
        }

        Ok(target)
    }

    fn to_vec(&self) -> Result<std::vec::Vec<u8>, Error> {
        let msg = self.to_message()?;
        Ok(msg.into_octets())
    }

    fn to_message(&self) -> Result<Message<std::vec::Vec<u8>>, Error> {
        let target = StaticCompressor::new(Vec::new());

        let builder = self.to_message_builder(target)?;

        let msg = Message::from_octets(builder.finish().into_target())
            .expect(
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

//------------ TsigClient -----------------------------------------------------

/// An asbtraction layer over [`ClientTransaction`] and [`ClientSequence`].
#[derive(Clone, Debug)]
enum TsigClient<K> {
    /// TSIG Client transaction state.
    Transaction(ClientTransaction<K>),

    /// TSIG client sequence state.
    Sequence(ClientSequence<K>),
}

impl<K: AsRef<Key>> TsigClient<K> {
    /// Creates a TSIG client for a request.
    pub fn request<Target: Composer>(
        key: K,
        msg: &mut AdditionalBuilder<Target>,
        now: Time48,
        streaming: bool,
    ) -> Result<Self, PushError> {
        let client = if streaming {
            Self::Sequence(ClientSequence::request(key, msg, now)?)
        } else {
            Self::Transaction(ClientTransaction::request(key, msg, now)?)
        };

        Ok(client)
    }

    /// Validates an answer.
    pub fn answer<Octs: Octets + AsMut<[u8]> + ?Sized>(
        &mut self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), ValidationError> {
        match self {
            TsigClient::Transaction(c) => c.answer(message, now),
            TsigClient::Sequence(c) => c.answer(message, now),
        }
    }

    /// Validates the end of the sequence.
    pub fn done(self) -> Result<(), ValidationError> {
        match self {
            TsigClient::Transaction(_) => Ok(()),
            TsigClient::Sequence(c) => c.done(),
        }
    }
}
