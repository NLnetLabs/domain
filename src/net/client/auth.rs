//! TODO
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use core::ops::DerefMut;

use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use tracing::{debug, trace, warn};

use crate::base::message::CopyRecordsError;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::Message;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::rdata::tsig::Time48;
use crate::tsig::{ClientSequence, ClientTransaction, Key};

/// TODO
#[derive(Clone, Debug)]
enum TsigClient {
    /// TODO
    Transaction(ClientTransaction<Arc<Key>>),

    /// TODO
    Sequence(ClientSequence<Arc<Key>>),
}

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// TODO
pub struct Connection<Upstream> {
    /// Upstream transport to use for requests.
    ///
    /// This should be the final transport, there should be no further
    /// modification to the request before it is sent to the recipient.
    upstream: Arc<Upstream>,

    /// TODO
    key: Option<Arc<Key>>,
}

impl<Upstream> Connection<Upstream> {
    /// TODO
    pub fn new(key: Option<Arc<Key>>, upstream: Upstream) -> Self {
        Self {
            upstream: Arc::new(upstream),
            key,
        }
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream> SendRequest<CR> for Connection<Upstream>
where
    CR: ComposeRequest + 'static,
    Upstream:
        SendRequest<AuthenticatedRequestMessage<CR>> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::<CR, Upstream>::new(
            request_msg,
            self.key.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR>>,
{
    /// State of the request.
    state: RequestState,

    /// The request message.
    request_msg: Option<CR>,

    /// TODO
    key: Option<Arc<Key>>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,
}

impl<CR, Upstream> Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR>> + Send + Sync,
{
    /// Create a new Request object.
    fn new(
        request_msg: CR,
        key: Option<Arc<Key>>,
        upstream: Arc<Upstream>,
    ) -> Self {
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

                    // TODO: TSIG sign the request, and send the signed version
                    // upstream.
                    let msg = AuthenticatedRequestMessage {
                        request: self.request_msg.take().unwrap(),
                        key: self.key.clone(),
                        signer: tsig_client.clone(),
                    };

                    trace!("Sending auth request upstream...");
                    let request = self.upstream.send_request(msg);
                    self.state =
                        RequestState::GetResponse(request, tsig_client);
                    continue;
                }

                RequestState::GetResponse(request, tsig_client) => {
                    trace!("Receiving response to auth request");
                    let response = request.get_response().await;
                    assert!(tsig_client.lock().unwrap().is_some());

                    // TSIG validation
                    match response {
                        Ok(msg) => {
                            let mut modifiable_msg = Message::from_octets(
                                msg.as_slice().to_vec(),
                            )?;

                            debug!("Doing TSIG validation");
                            {
                                let mut locked = tsig_client.lock().unwrap();
                                match locked.deref_mut() {
                                    Some(TsigClient::Transaction(client)) => {
                                        trace!("Validating TSIG for single reply");
                                        client
                                            .answer(
                                                &mut modifiable_msg,
                                                Time48::now(),
                                            )
                                            .map_err(|err| {
                                                Error::Authentication(err)
                                            })?;
                                        mark_as_complete = true;
                                    }
                                    Some(TsigClient::Sequence(client)) => {
                                        trace!("Validating TSIG for sequence reply");
                                        client
                                            .answer(
                                                &mut modifiable_msg,
                                                Time48::now(),
                                            )
                                            .map_err(|err| {
                                                Error::Authentication(err)
                                            })?;
                                    }
                                    _ => unreachable!(),
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

                RequestState::Complete => {
                    break Err(Error::StreamReceiveError);
                }
            }
        };

        if mark_as_complete {
            self.state = RequestState::Complete;
        }

        res
    }
}

impl<CR, Upstream> Debug for Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR>>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

impl<CR, Upstream> GetResponse for Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<AuthenticatedRequestMessage<CR>> + Send + Sync,
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
                let client = tsig_client.lock().unwrap().take().unwrap();

                if let TsigClient::Sequence(client) = client {
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
enum RequestState {
    /// Initial state, perform a cache lookup.
    Init,

    /// Wait for a response and insert the response in the cache.
    GetResponse(
        Box<dyn GetResponse + Send + Sync>,
        Arc<std::sync::Mutex<Option<TsigClient>>>,
    ),

    /// TODO
    Complete,
}

//------------ AuthenticatedRequestMessage ------------------------------------

/// TODO
#[derive(Debug)]
pub struct AuthenticatedRequestMessage<CR: Send + Sync> {
    /// TODO
    request: CR,

    /// TODO
    key: Option<Arc<Key>>,

    /// TODO
    signer: Arc<std::sync::Mutex<Option<TsigClient>>>,
}

impl<CR: ComposeRequest> ComposeRequest for AuthenticatedRequestMessage<CR> {
    // Used by the stream transport.
    fn append_message<Target: Composer>(
        &self,
        target: Target,
    ) -> Result<AdditionalBuilder<Target>, CopyRecordsError> {
        trace!("auth::AuthenticatedRequestMessage<CR>::append_message()");
        let mut target = self.request.append_message(target)?;

        if let Some(key) = &self.key {
            trace!("has TSIG key");
            let client = if self.request.is_streaming() {
                trace!("auth: is_streaming=true");
                TsigClient::Sequence(
                    ClientSequence::request(
                        key.clone(),
                        &mut target,
                        Time48::now(),
                    )
                    .unwrap(),
                )
            } else {
                trace!("auth: is_streaming=false");
                trace!("auth: signing message:");
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
            trace!("lacks TSIG key");
        }

        Ok(target)
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
