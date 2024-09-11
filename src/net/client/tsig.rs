//! A TSIG signing & verifying passthrough transport.
//!
//! This module provides a transport that wraps the [high-level support for
//! signing message exchanges with TSIG][crate::tsig], thereby authenticating
//! them.
//!
//! # Usage
//!
//! 1. Create a signing [Key].
//! 2. Create a [Connection] that wraps an upstream connection and uses the
//!    key.
//! 3. [Send a request][Connection::send_request] using the connection.
//! 4. [Receive the response][Request::get_response] or responses.
//!
//! # How it works
//!
//! Requests are automatically signed with the given key and response
//! signatures are automatically verified. On verification failure
//! [Error::ValidationError][crate::net::client::request::Error] will be
//! returned.
//!
//! <div class="warning">
//!
//! TSIG verification is a destructive process. It will alter the response
//! stripping out the TSIG RR contained within the additional section and
//! decrementing the DNS message header ARCOUNT accordingly. It may also
//! adjust the mesage ID, in conformance with [RFC
//! 8945](https://www.rfc-editor.org/rfc/rfc8945.html#name-dns-message).
//!
//! If you wish to receive the response TSIG RR intact, do **NOT** use this
//! transport. Instead process the response records manually using a normal
//! transport.
//!
//! </div>
//!
//! # Requirements
//!
//! This transport works with any upstream transports so long as they don’t
//! modify the message once signed nor modify the response before it can be
//! verified.
//!
//! Failing to do so will result in signature verification failure. For
//! requests this will occur at the receiving server. For responses this will
//! result in [`GetResponse`][crate::net::client::request::GetResponse]
//! rerturning [Error::ValidationError][crate::net::client::request::Error].
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
use octseq::Octets;
use tracing::trace;

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

/// A wrapper around [`ClientTransaction`] and [`ClientSequence`].
///
/// This wrapper allows us to write calling code once that invokes methods on
/// the TSIG signer/validator which have the same name and purpose for single
/// response vs multiple response streams, yet have distinct Rust types and so
/// must be called on the correct type, without needing to know at the call
/// site which of the distinct types it actually is.
#[derive(Clone, Debug)]
enum TsigClient<K> {
    /// A [`ClientTransaction`] for signing a request and validating a single
    /// response.
    Transaction(ClientTransaction<K>),

    /// A [`ClientSequence`] for signing a request and validating a single
    /// response.
    Sequence(ClientSequence<K>),
}

impl<K> TsigClient<K>
where
    K: AsRef<Key>,
{
    /// A helper wrapper around [`ClientTransaction::answer`] and
    /// [`ClientSequence::answer`] that allows the appropriate method to be
    /// invoked without needing to know which type it actually is.
    pub fn answer<Octs>(
        &mut self,
        message: &mut Message<Octs>,
        now: Time48,
    ) -> Result<(), Error>
    where
        Octs: Octets + AsMut<[u8]> + ?Sized,
    {
        match self {
            TsigClient::Transaction(client) => client.answer(message, now),
            TsigClient::Sequence(client) => client.answer(message, now),
        }
        .map_err(Error::Authentication)
    }

    /// A helper method that allows [`ClientSequence::done`] to be called
    /// without knowing or caring if the underlying type is actually
    /// [`ClientTransaction`] instead (which doesn't have a `done()` method).
    ///
    /// Invoking this method on a [`ClientTransaction`] is harmless and has no
    /// effect.
    fn done(self) -> Result<(), Error> {
        match self {
            TsigClient::Transaction(_) => {
                // Nothing to do.
                Ok(())
            }
            TsigClient::Sequence(client) => {
                client.done().map_err(Error::Authentication)
            }
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A TSIG signing and verifying transport.
///
/// This transport signs requests and verifies responses using a provided key
/// and upstream transport. For more information see the [module
/// docs][crate::net::client::tsig].
#[derive(Clone)]
pub struct Connection<Upstream, K> {
    /// Upstream transport to use for requests.
    ///
    /// The upstream transport(s) **MUST NOT** modify the request before it is
    /// sent nor modify the response before this transport can verify it.
    upstream: Arc<Upstream>,

    /// TODO
    key: K,
}

impl<Upstream, K> Connection<Upstream, K> {
    /// Create a new tsig transport.
    ///
    /// After creating the transport call `send_request` via the
    /// [`SendRequest`] or [`SendRequestMulti`] traits to send signed messages
    /// and verify signed responses.
    pub fn new(key: K, upstream: Upstream) -> Self {
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
    Upstream: SendRequest<RequestMessage<CR, K>> + Send + Sync + 'static,
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

impl<CR, Upstream, K> SendRequestMulti<CR> for Connection<Upstream, K>
where
    CR: ComposeRequestMulti + 'static,
    Upstream: SendRequestMulti<RequestMessage<CR, K>> + Send + Sync + 'static,
    K: Clone + AsRef<Key> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(Request::<CR, Upstream, K>::new_multi(
            request_msg,
            self.key.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ Forwarder ------------------------------------------------------

/// A function that can forward a request via an upstream transport.
///
/// This type is generic over whether the [`RequestMessage`] being sent was
/// sent via the [`ComposeRequest`] trait or the  [`ComposeRequestMulti`]
/// trait, which allows common logic to be used for both despite the different
/// trait bounds required to work with them.
type Forwarder<Upstream, CR, K> = fn(
    &Upstream,
    RequestMessage<CR, K>,
    Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
) -> RequestState<K>;

/// Forward a request that should result in a single response.
///
/// This function forwards a [`RequestMessage`] to an upstream transport using
/// a client that can only accept a single response, i.e. was sent via the
/// [`ComposeRequest`] trait.
fn forwarder<CR, K, Upstream>(
    upstream: &Upstream,
    msg: RequestMessage<CR, K>,
    tsig_client: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
) -> RequestState<K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<RequestMessage<CR, K>> + Send + Sync,
{
    RequestState::GetResponse(upstream.send_request(msg), tsig_client)
}

/// Forward a request that may result in multiple responses.
///
/// This function forwards a [`RequestMessage`] to an upstream transport using
/// a client that can accept multiple responses, i.e. was sent via the
/// [`ComposeRequestMulti`] trait.
fn forwarder_multi<CR, K, Upstream>(
    upstream: &Upstream,
    msg: RequestMessage<CR, K>,
    tsig_client: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
) -> RequestState<K>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<RequestMessage<CR, K>> + Send + Sync,
{
    RequestState::GetResponseMulti(upstream.send_request(msg), tsig_client)
}

//------------ Request --------------------------------------------------------

/// The state and related properties of an in-progress request.
struct Request<CR, Upstream, K> {
    /// State of the request.
    state: RequestState<K>,

    /// The request message.
    ///
    /// Initially Some, consumed when sent.
    request_msg: Option<CR>,

    /// The TSIG key used to sign the request.
    key: K,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,
}

impl<CR, Upstream, K> Request<CR, Upstream, K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<RequestMessage<CR, K>> + Send + Sync,
    K: Clone + AsRef<Key>,
    Self: GetResponse,
{
    /// Create a new Request object.
    fn new(request_msg: CR, key: K, upstream: Arc<Upstream>) -> Self {
        Self {
            state: RequestState::Init,
            request_msg: Some(request_msg),
            key,
            upstream,
        }
    }
}

impl<CR, Upstream, K> Request<CR, Upstream, K>
where
    CR: Sync + Send,
    K: Clone + AsRef<Key>,
{
    /// Create a new Request object.
    fn new_multi(request_msg: CR, key: K, upstream: Arc<Upstream>) -> Self {
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
    async fn get_response_impl(
        &mut self,
        upstream_sender: Forwarder<Upstream, CR, K>,
    ) -> Result<Option<Message<Bytes>>, Error> {
        let (response, tsig_client) = loop {
            match &mut self.state {
                RequestState::Init => {
                    let tsig_client = Arc::new(std::sync::Mutex::new(None));

                    let msg = RequestMessage::new(
                        self.request_msg.take().unwrap(),
                        self.key.clone(),
                        tsig_client.clone(),
                    );

                    trace!("Sending request upstream...");
                    self.state =
                        upstream_sender(&self.upstream, msg, tsig_client);
                    continue;
                }

                RequestState::GetResponse(request, tsig_client) => {
                    let response = request.get_response().await?;
                    break (Some(response), tsig_client);
                }

                RequestState::GetResponseMulti(request, tsig_client) => {
                    let response = request.get_response().await?;
                    break (response, tsig_client);
                }

                RequestState::Complete => {
                    return Err(Error::StreamReceiveError);
                }
            }
        };

        let res = Self::validate_response(response, tsig_client)?;

        if res.is_none() {
            self.state = RequestState::Complete;
        }

        Ok(res)
    }

    /// Perform TSIG validation on the result of receiving a response.
    ///
    /// If no response were received, validation must still be performed in
    /// order to verify that the final message that was received was signed
    /// correctly. This cannot be done when receiving the final response as we
    /// only know that it is final by trying and failing (which may involve
    /// waiting) to receive another response.
    ///
    /// This function therefore takes an optional response message and a
    /// [`TsigClient`]. The process of validating that the final response was
    /// valid will consume the given [`TsigClient`].
    ///
    /// Note: Validation is a destructive process, as it strips the TSIG RR
    /// out of the response. The given response message is consumed, altered
    /// and returned.
    ///
    /// Returns:
    /// - `Ok(Some)` when returning a successfully validated response.
    /// - `Ok(None)` when the end of a responses stream was successfully validated.
    /// - `Err` if validation or some other error occurred.
    fn validate_response(
        response: Option<Message<Bytes>>,
        tsig_client: &mut Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ) -> Result<Option<Message<Bytes>>, Error> {
        let res = match response {
            None => {
                let client = tsig_client.lock().unwrap().take().unwrap();
                client.done()?;
                None
            }

            Some(msg) => {
                let mut modifiable_msg =
                    Message::from_octets(msg.as_slice().to_vec())?;

                if let Some(client) = tsig_client.lock().unwrap().deref_mut()
                {
                    trace!("Validating TSIG for sequence reply");
                    client.answer(&mut modifiable_msg, Time48::now())?;
                }

                let out_vec = modifiable_msg.into_octets();
                let out_bytes = Bytes::from(out_vec);
                let out_msg = Message::<Bytes>::from_octets(out_bytes)?;
                Some(out_msg)
            }
        };

        Ok(res)
    }
}

//-- Debug

impl<CR, Upstream, K> Debug for Request<CR, Upstream, K> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request").finish()
    }
}

//--- GetResponse

impl<CR, Upstream, K> GetResponse for Request<CR, Upstream, K>
where
    CR: ComposeRequest,
    Upstream: SendRequest<RequestMessage<CR, K>> + Send + Sync,
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
        Box::pin(async move {
            // Unwrap the one and only response, we don't need the multiple
            // response handling ability of [`Request::get_response_impl`].
            self.get_response_impl(forwarder).await.map(|v| v.unwrap())
        })
    }
}

//--- GetResponseMulti

impl<CR, Upstream, K> GetResponseMulti for Request<CR, Upstream, K>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<RequestMessage<CR, K>> + Send + Sync,
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
        Box::pin(self.get_response_impl(forwarder_multi))
    }
}

//------------ RequestState ---------------------------------------------------

/// State machine used by [`Request::get_response_impl`].
///
/// Possible flows:
///   - Init -> GetResponse
///   - Init -> GetResponseMulti -> Complete
enum RequestState<K> {
    /// Initial state, waiting to sign and send the request.
    Init,

    /// Waiting for a response to verify.
    GetResponse(
        Box<dyn GetResponse + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ),

    /// Wait for multiple responses to verify.
    GetResponseMulti(
        Box<dyn GetResponseMulti + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ),

    /// The last of multiple responses was received and verified.
    ///
    /// Note: This state can only be entered when processing a sequence of
    /// responses, i.e. using [`GetResponseMulti`]. When using [`GetResponse`]
    /// this state will not be enetered because it only calls
    /// [`Request::get_response_impl`] once.
    Complete,
}

//------------ RequestMessage -------------------------------------------------

/// A message that can be sent using a [`Connection`].
///
/// This type implements the [`ComposeRequest`] and [`ComposeRequestMulti`]
/// traits and thus is compatible with the [`SendRequest`] and
/// [`SendRequestMulti`] traits implemented by [`Connection`].
///
/// This type stores the message to be sent and implements the
/// [`ComposeRequest`] and [`ComposeRequestMulti`] traits so that when the
/// upstream transport accesses the message via the traits that we can at that
/// point sign the request.
///
/// Signing it earlier is not possible as the upstream transport may modify
/// the request prior to sending it, e.g. to assign a message ID or to add
/// EDNS options, and signing **MUST** be the last modification made to the
/// message prior to sending.
#[derive(Debug)]
pub struct RequestMessage<CR, K>
where
    CR: Send + Sync,
{
    /// The actual request to sign.
    request: CR,

    /// The TSIG key to sign the request with.
    key: K,

    /// The TSIG signer state.
    ///
    /// This must be kept here as it is created only when signing the request
    /// and is needed later when verifying responses.
    ///
    /// Note: It is wrapped inside an [`Arc<Mutex<T>>`] because the signing is
    /// done in [`Request::get_response_impl`] which returns a [`Future`] and
    /// the compiler has no way of knowing whether or not a second call to
    /// [`Request::get_response_impl`] could be made concurrently with an
    /// earlier invocation which has not yet completed its progression through
    /// its async state machine, and could be "woken up" in parallel on a
    /// different thread thus requiring that access to the signer be made
    /// thread safe via a locking mechanism like [`Mutex`].
    signer: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
}

impl<CR, K> RequestMessage<CR, K>
where
    CR: Send + Sync,
{
    /// Creates a new [`RequestMessage`].
    fn new(
        request: CR,
        key: K,
        signer: Arc<std::sync::Mutex<Option<TsigClient<K>>>>,
    ) -> Self
    where
        CR: Sync + Send,
        K: Clone + AsRef<Key>,
    {
        Self {
            request,
            key,
            signer,
        }
    }
}

impl<CR, K> ComposeRequest for RequestMessage<CR, K>
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

        let client = {
            trace!(
                "Signing single request transaction with key '{}'",
                self.key.as_ref().name()
            );
            TsigClient::Transaction(
                ClientTransaction::request(
                    self.key.clone(),
                    &mut target,
                    Time48::now(),
                )
                .unwrap(),
            )
        };

        *self.signer.lock().unwrap() = Some(client);

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

impl<CR, K> ComposeRequestMulti for RequestMessage<CR, K>
where
    CR: ComposeRequestMulti,
    K: Clone + Debug + Send + Sync + AsRef<Key>,
{
    // Used by the stream transport.
    fn append_message<Target: Composer>(
        &self,
        target: Target,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        let mut target = self.request.append_message(target)?;

        trace!(
            "Signing streaming request sequence with key '{}'",
            self.key.as_ref().name()
        );
        let client = TsigClient::Sequence(
            ClientSequence::request(
                self.key.clone(),
                &mut target,
                Time48::now(),
            )
            .unwrap(),
        );

        *self.signer.lock().unwrap() = Some(client);

        Ok(target)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::iana::Rcode;
    use crate::base::message_builder::QuestionBuilder;
    use crate::base::{MessageBuilder, Name, Rtype};
    use crate::tsig::{
        Algorithm, KeyName, KeyStore, ServerSequence, ServerTransaction,
        ValidationError,
    };
    use core::future::ready;
    use core::str::FromStr;

    #[tokio::test]
    async fn single_signed_valid_response() {
        do_single_response(false).await;
    }

    #[tokio::test]
    async fn single_signed_invalid_response() {
        do_single_response(true).await;
    }

    async fn do_single_response(invalidate_signature: bool) {
        // Make a query message that would be expected to result in a single
        // reply.
        let msg = mk_request_msg(Rtype::A);

        // Wrap that message into a request message compatible with a
        // transport capable of receving a single response.
        let req =
            crate::net::client::request::RequestMessage::new(msg).unwrap();

        // Make a TSIG key to sign the request with.
        let key = mk_tsig_key();

        // Make a mock upstream that will "send" the request and receives a
        // mock TSIG signed response back.
        let upstream =
            Arc::new(MockUpstream::new(key.clone(), invalidate_signature));

        // Wrap the request message into a TSIG signing request with a signing
        // key and upstream transport.
        let mut req = Request::new(req, key, upstream);

        // "Send" the request and receive the validated mock response.
        let res = req.get_response().await;

        assert_eq!(res.is_err(), invalidate_signature);

        if let Ok(res) = res {
            // Verify that the mock response has had its TSIG RR stripped out
            // during validation.
            assert_eq!(res.header_counts().arcount(), 0, "TSIG RR should have been removed from the additional section during response processing");
        }
    }

    #[tokio::test]
    async fn multiple_signed_valid_responses() {
        do_multiple_responses(false, false).await
    }

    #[tokio::test]
    async fn multiple_signed_responses_with_one_invalid() {
        do_multiple_responses(true, false).await
    }

    #[tokio::test]
    async fn multiple_signed_valid_responses_and_a_final_unsigned_response() {
        do_multiple_responses(false, true).await
    }

    async fn do_multiple_responses(
        invalidate_signature: bool,
        dont_sign_last_response: bool,
    ) {
        // Make a query message that would be expected to result in multiple
        // replies.
        let msg = mk_request_msg(Rtype::AXFR);

        // Wrap that message into a request message compatible with a
        // transport capable of receving multiple responses.
        let req = crate::net::client::request::RequestMessageMulti::new(msg)
            .unwrap();

        // Make a TSIG key to sign the request with.
        let key = mk_tsig_key();

        // Make a mock upstream that will "send" the request and receive
        // multiple mock TSIG signed responses back.
        let upstream = Arc::new(MockUpstreamMulti::new(
            key.clone(),
            invalidate_signature,
            dont_sign_last_response,
        ));

        // Wrap the request message into a TSIG signing request with a signing
        // key and upstream transport.
        let mut req = Request::new_multi(req, key, upstream);

        // "Send" the request and receive the first validated mock response.
        let res = req
            .get_response()
            .await
            .unwrap()
            .expect("First response is missing");

        // Verify that the mock response has had its TSIG RR stripped out
        // during validation.
        assert_eq!(res.header_counts().arcount(), 0, "TSIG RR should have been removed from the additional section during response processing");

        // Receive the second mock response, which may have been deliberately
        // invalidated.
        let res = req.get_response().await;

        if invalidate_signature {
            assert!(
                matches!(
                    res,
                    Err(Error::Authentication(ValidationError::BadSig))
                ),
                "Expected error BadSig but the result was: {res:?}"
            );
        } else {
            assert!(res.is_ok(), "Unexpected error message: {res:?}");
        }

        if let Ok(res) = res {
            let res = res.expect("Second response is missing");

            // Verify that the mock response has had its TSIG RR stripped out
            // during validation.
            assert_eq!(res.header_counts().arcount(), 0, "TSIG RR should have been removed from the additional section during response processing");

            // Receive the third and final mock response, which may have been
            // deliberately not signed, in order to test whether or not we
            // are correctly calling `ClientSequence::done()` to catch this
            // case. This shouldn't fail at this point however as apparently
            // it's only caught when .done() is called when no more responses
            // are received.
            let res = req
                .get_response()
                .await
                .unwrap()
                .expect("Third response is missing");

            // Verify that the mock response has had its TSIG RR stripped out
            // during validation, or it was never added during response
            // generation.
            if dont_sign_last_response {
                assert_eq!(res.header_counts().arcount(), 0, "TSIG RR should never have been added to the additional section during response generation");
            } else {
                assert_eq!(res.header_counts().arcount(), 0, "TSIG RR should have been removed from the additional section during response processing");
            }

            if dont_sign_last_response {
                // Attempt to receive another response but discover that the
                // last response was not signed as it should have been.
                assert!(
                    matches!(req.get_response().await, Err(Error::Authentication(ValidationError::TooManyUnsigned))),
                    "Receiving another response should have failed because the last response should have lacked a signature"
                );
            } else {
                // Attempt to receive another response but discover that this
                // is the end of the response sequence.
                assert!(
                    req.get_response().await.unwrap().is_none(),
                    "There should not be a fourth response"
                );
            }
        }
    }

    // Make a query for the given RTYPE.
    fn mk_request_msg(rtype: Rtype) -> QuestionBuilder<Vec<u8>> {
        let mut msg = MessageBuilder::new_vec();
        msg.header_mut().set_rd(true);
        msg.header_mut().set_ad(true);
        let mut msg = msg.question();
        msg.push((Name::vec_from_str("example.com").unwrap(), rtype))
            .unwrap();
        msg
    }

    // Make a TSIG key for signing test requests and responses with.
    fn mk_tsig_key() -> Arc<Key> {
        // Create a signing key.
        let key_name = KeyName::from_str("demo-key").unwrap();
        let secret = crate::utils::base64::decode::<Vec<u8>>(
            "zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8=",
        )
        .unwrap();
        Arc::new(
            Key::new(Algorithm::Sha256, &secret, key_name, None, None)
                .unwrap(),
        )
    }

    //------------ MockGetResponse --------------------------------------------

    #[derive(Debug)]
    struct MockGetResponse<CR, KS> {
        request_msg: CR,
        key_store: KS,
        invalidate_signature: bool,
    }

    impl<CR, KS> MockGetResponse<CR, KS> {
        fn new(
            request_msg: CR,
            key_store: KS,
            invalidate_signature: bool,
        ) -> Self {
            Self {
                request_msg,
                key_store,
                invalidate_signature,
            }
        }
    }

    //--- GetResponse

    impl<CR: ComposeRequest + Debug, KS: Debug + KeyStore> GetResponse
        for MockGetResponse<CR, KS>
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
            let mut req = self.request_msg.to_message().unwrap();

            // Create a TSIG signer for a single response based on the
            // received request.
            let tsig = ServerTransaction::request(
                &self.key_store,
                &mut req,
                Time48::now(),
            )
            .unwrap()
            .unwrap();

            // Generate a mock response to the request.
            let builder = MessageBuilder::new_bytes();
            let builder = builder.start_answer(&req, Rcode::NOERROR).unwrap();
            let mut builder = builder.additional();

            // Sign the response.
            tsig.answer(&mut builder, Time48::now()).unwrap();

            if self.invalidate_signature {
                // Invalidate the signature.
                builder.header_mut().set_rcode(Rcode::SERVFAIL);
            }

            // Generate the wire format response message and sanity check it
            // before returning it.
            let res = builder.into_message();
            assert_eq!(res.header_counts().arcount(), 1, "Constructed response lacks a TSIG RR in the additional section");
            Box::pin(ready(Ok(res)))
        }
    }

    //------------ MockGetResponseMulti ---------------------------------------

    #[derive(Debug)]
    struct MockGetResponseMulti<CR, KS> {
        request_msg: CR,
        key_store: KS,
        sent_request: Option<Message<Vec<u8>>>,
        num_responses_generated: usize,
        signer: Option<ServerSequence<KS>>,
        invalidate_signature: bool,
        dont_sign_last_response: bool,
    }

    impl<CR, KS> MockGetResponseMulti<CR, KS> {
        fn new(
            request_msg: CR,
            key_store: KS,
            invalidate_signature: bool,
            dont_sign_last_response: bool,
        ) -> Self {
            Self {
                request_msg,
                key_store,
                sent_request: None,
                num_responses_generated: 0,
                signer: None,
                invalidate_signature,
                dont_sign_last_response,
            }
        }
    }

    //--- GetResponseMulti

    impl<CR, KS> GetResponseMulti for MockGetResponseMulti<CR, KS>
    where
        CR: ComposeRequestMulti + Debug,
        KS: Debug + KeyStore<Key = KS> + AsRef<Key>,
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
            // Generate a sequence of at most 3 responses.
            if self.num_responses_generated == 3 {
                return Box::pin(ready(Ok(None)));
            }

            self.num_responses_generated += 1;

            // When first receiving the request, generate a TSIG signer for a
            // multiple response sequence based on the received request.
            let mut tsig = match self.signer.take() {
                Some(tsig) => tsig,
                None => {
                    let mut req = self.request_msg.to_message().unwrap();

                    let tsig = ServerSequence::request(
                        &self.key_store,
                        &mut req,
                        Time48::now(),
                    )
                    .unwrap()
                    .unwrap();

                    // Store the signer, we'll need it to sign subsequent
                    // responses.
                    self.sent_request = Some(req);

                    tsig
                }
            };

            // Generate a mock response to the request.
            let req = self.sent_request.as_ref().unwrap();
            let builder = MessageBuilder::new_bytes();
            let builder = builder.start_answer(req, Rcode::NOERROR).unwrap();
            let mut builder = builder.additional();

            // Decide whether to sign and/or invalidate the response.
            let (sign, invalidate) = match self.num_responses_generated {
                1 => (true, false),
                2 => (true, self.invalidate_signature),
                3 => (!self.dont_sign_last_response, false),
                _ => unreachable!(),
            };

            eprintln!(
                "Response {}: sign={}, invalidate={}",
                self.num_responses_generated, sign, invalidate
            );

            // Sign the response (we might strip the signature out below).
            if sign {
                tsig.answer(&mut builder, Time48::now()).unwrap();
            }

            // Put the signer back in storage for the next response.
            self.signer = Some(tsig);

            if invalidate {
                // Invalidate the signature.
                builder.header_mut().set_rcode(Rcode::SERVFAIL);
            }

            // Generate the wire format response message and sanity check it
            // before returning it.
            let res = builder.into_message();
            if sign {
                assert_eq!(res.header_counts().arcount(), 1, "Constructed response lacks a TSIG RR in the additional section");
                let rec = res.additional().unwrap().next().unwrap().unwrap();
                assert_eq!(rec.rtype(), Rtype::TSIG);
            }
            Box::pin(ready(Ok(Some(res))))
        }
    }

    //------------ MockUpstream -----------------------------------------------

    struct MockUpstream {
        key: Arc<Key>,
        invalidate_signature: bool,
    }

    impl MockUpstream {
        fn new(key: Arc<Key>, invalidate_signature: bool) -> Self {
            Self {
                key,
                invalidate_signature,
            }
        }
    }

    //--- SendRequest

    impl<CR: ComposeRequest + Debug + Send + Sync + 'static> SendRequest<CR>
        for MockUpstream
    {
        fn send_request(
            &self,
            request_msg: CR,
        ) -> Box<dyn GetResponse + Send + Sync> {
            Box::new(MockGetResponse::new(
                request_msg,
                self.key.clone(),
                self.invalidate_signature,
            ))
        }
    }

    //------------ MockUpstreamMulti ------------------------------------------

    struct MockUpstreamMulti {
        key: Arc<Key>,
        invalidate_signature: bool,
        dont_sign_last_response: bool,
    }
    impl MockUpstreamMulti {
        fn new(
            key: Arc<Key>,
            invalidate_signature: bool,
            dont_sign_last_response: bool,
        ) -> Self {
            Self {
                key,
                invalidate_signature,
                dont_sign_last_response,
            }
        }
    }

    impl<CR> SendRequestMulti<CR> for MockUpstreamMulti
    where
        CR: ComposeRequestMulti + Debug + Send + Sync + 'static,
    {
        fn send_request(
            &self,
            request_msg: CR,
        ) -> Box<dyn GetResponseMulti + Send + Sync> {
            Box::new(MockGetResponseMulti::new(
                request_msg,
                self.key.clone(),
                self.invalidate_signature,
                self.dont_sign_last_response,
            ))
        }
    }
}
