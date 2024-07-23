//! TSIG message authentication middleware.

use core::convert::Infallible;
use core::future::{ready, Ready};
use core::marker::PhantomData;
use core::ops::{ControlFlow, DerefMut};

use std::sync::Arc;
use std::vec::Vec;

use futures::stream::{once, Once, Stream};
use octseq::{Octets, OctetsFrom};
use tracing::{error, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode, TsigRcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, ParsedName, Question, Rtype, StreamTarget};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::tsig::Time48;
use crate::tsig::{
    self, KeyName, KeyStore, ServerSequence, ServerTransaction,
};

use super::stream::{MiddlewareStream, PostprocessingStream};

//------------ TsigMiddlewareSvc ----------------------------------------------

/// TSIG message authentication middlware.
///
/// This middleware service validates TSIG signatures on incoming requests, if
/// any, and adds TSIG signatures to responses to signed requests.
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [8945] | TBD     |
///
/// [8945]: https://datatracker.ietf.org/doc/rfc8945/
#[derive(Clone, Debug)]
pub struct TsigMiddlewareSvc<RequestOctets, NextSvc, KS>
where
    KS: Clone + KeyStore,
{
    next_svc: NextSvc,

    key_store: KS,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, NextSvc, KS> TsigMiddlewareSvc<RequestOctets, NextSvc, KS>
where
    KS: Clone + KeyStore,
{
    /// Creates an empty processor instance.
    #[must_use]
    pub fn new(next_svc: NextSvc, key_store: KS) -> Self {
        Self {
            next_svc,
            key_store,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, NextSvc, KS> TsigMiddlewareSvc<RequestOctets, NextSvc, KS>
where
    RequestOctets:
        Octets + OctetsFrom<Vec<u8>> + Send + Sync + 'static + Unpin,
    NextSvc: Service<RequestOctets, Option<KeyName>>,
    NextSvc::Target: Composer + Default + Send + Sync + 'static,
    NextSvc::Future: Unpin,
    KS: Clone + KeyStore,
    Infallible: From<<RequestOctets as octseq::OctetsFrom<Vec<u8>>>::Error>,
{
    #[allow(clippy::type_complexity)]
    fn preprocess(
        req: &Request<RequestOctets>,
        key_store: &KS,
    ) -> ControlFlow<
        AdditionalBuilder<StreamTarget<NextSvc::Target>>,
        Option<(
            Request<RequestOctets, Option<KeyName>>,
            TsigSigner<KS::Key>,
        )>,
    > {
        if let Some(q) = Self::get_relevant_question(req.message()) {
            let octets = req.message().as_slice().to_vec();
            let mut mut_msg = Message::from_octets(octets).unwrap();

            match tsig::ServerTransaction::request(
                key_store,
                &mut mut_msg,
                Time48::now(),
            ) {
                Ok(None) => {
                    // Message is not TSIG signed.
                }

                Ok(Some(tsig)) => {
                    // Message is TSIG signed by a known key.
                    trace!(
                        "Request is signed with TSIG key '{}'",
                        tsig.key().name()
                    );

                    // Convert to RequestOctets so that the non-TSIG signed
                    // message case can just pass through the RequestOctets.
                    let source = mut_msg.into_octets();
                    let octets = RequestOctets::octets_from(source);
                    let new_msg = Message::from_octets(octets).unwrap();

                    let mut new_req = Request::new(
                        req.client_addr(),
                        req.received_at(),
                        new_msg,
                        req.transport_ctx().clone(),
                        Some(tsig.key().name().clone()),
                    );

                    let num_bytes_to_reserve = tsig.key().compose_len();
                    new_req.reserve_bytes(num_bytes_to_reserve);

                    return ControlFlow::Continue(Some((
                        new_req,
                        TsigSigner::Transaction(tsig),
                    )));
                }

                Err(err) => {
                    // Message is incorrectly signed or signed with an unknown key.
                    warn!(
                        "{} for {} from {} refused: {err}",
                        q.qtype(),
                        q.qname(),
                        req.client_addr(),
                    );
                    let builder = mk_builder_for_target();
                    let additional = tsig::ServerError::<KS::Key>::unsigned(
                        TsigRcode::BADKEY,
                    )
                    .build_message(req.message(), builder)
                    .unwrap();
                    return ControlFlow::Break(additional);
                }
            }
        }

        ControlFlow::Continue(None)
    }

    /// Sign the given response, or if necessary construct and return an
    /// alternate response.
    fn postprocess(
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<NextSvc::Target>>,
        pp_config: PostprocessingConfig<KS>,
    ) -> Option<AdditionalBuilder<StreamTarget<NextSvc::Target>>> {
        // Sign the response.
        let mut tsig_signer = pp_config.tsig.lock().unwrap();

        // Remove the limit we should have imposed during pre-processing so
        // that we can use the space we reserved for the OPT RR.
        response.clear_push_limit();

        let signing_result = match tsig_signer.as_mut() {
            Some(TsigSigner::Transaction(_)) => {
                // Extract the single response signer and consume it in the
                // signing process.
                let Some(TsigSigner::Transaction(tsig)) = tsig_signer.take()
                else {
                    unreachable!()
                };
                trace!(
                    "Signing single response with TSIG key '{}'",
                    tsig.key().name()
                );
                tsig.answer(response, Time48::now())
            }

            Some(TsigSigner::Sequence(tsig)) => {
                // Use the multi-response signer to sign the response.
                trace!(
                    "Signing response stream with TSIG key '{}'",
                    tsig.key().name()
                );
                tsig.answer(response, Time48::now())
            }

            None => {
                // Nothing to do as unsigned requests don't require response
                // signing.
                return None;
            }
        };

        // Handle signing failure. This shouldn't happen because we reserve
        // space in preprocess() for the TSIG RR that we add when signing.
        if signing_result.is_err() {
            // 5.3. Generation of TSIG on Answers
            //   "If addition of the TSIG record will cause the message to be
            //   truncated, the server MUST alter the response so that a TSIG
            //   can be included. This response contains only the question and
            //   a TSIG record, has the TC bit set, and has an RCODE of 0
            //   (NOERROR). At this point, the client SHOULD retry the request
            //   using TCP (as per Section 4.2.2 of [RFC1035])."

            // We can't use the TSIG signer state we just had as that was consumed
            // in the failed attempt to sign the answer, so we have to create a new
            // TSIG state in order to sign the truncated response.
            if request.transport_ctx().is_udp() {
                return Self::mk_signed_truncated_response(
                    request, &pp_config,
                );
            } else {
                // In the TCP case there's not much we can do. The upstream
                // service pushes response messages into the stream and we try
                // and sign them. If there isn't enough space to add the TSIG
                // signature RR to the response we can't signal the upstream
                // to try again to produce a smaller response message as it
                // may already have finished pushing into the stream or be
                // several messages further on in its processsing. We also
                // can't edit the response message content ourselves as we
                // know nothing about the content. The only option left to us
                // is to try and truncate the TSIG MAC and see if that helps,
                // but we don't support that (yet? NSD doesn't support it
                // either).
                return Some(mk_error_response(
                    request.message(),
                    OptRcode::SERVFAIL,
                ));
            }
        }

        None
    }

    fn mk_signed_truncated_response(
        request: &Request<RequestOctets>,
        pp_config: &PostprocessingConfig<KS>,
    ) -> Option<AdditionalBuilder<StreamTarget<NextSvc::Target>>> {
        let octets = request.message().as_slice().to_vec();
        let mut mut_msg = Message::from_octets(octets).unwrap();
        let res = ServerTransaction::request(
            &pp_config.key_store,
            &mut mut_msg,
            Time48::now(),
        );

        match res {
            Ok(None) => {
                warn!("Ignoring attempt to create a signed truncated response for an unsigned request.");
                None
            }

            Ok(Some(tsig)) => {
                let builder = mk_builder_for_target();
                let mut new_response = builder
                    .start_answer(request.message(), Rcode::NOERROR)
                    .unwrap();
                new_response.header_mut().set_tc(true);
                let mut new_response = new_response.additional();

                if let Err(err) =
                    tsig.answer(&mut new_response, Time48::now())
                {
                    error!("Unable to sign truncated TSIG response: {err}");
                    Some(mk_error_response(
                        request.message(),
                        OptRcode::SERVFAIL,
                    ))
                } else {
                    Some(new_response)
                }
            }

            Err(err) => {
                error!("Unable to sign truncated TSIG response: {err}");
                Some(mk_error_response(request.message(), OptRcode::SERVFAIL))
            }
        }
    }

    fn get_relevant_question(
        msg: &Message<RequestOctets>,
    ) -> Option<Question<ParsedName<RequestOctets::Range<'_>>>> {
        if Opcode::QUERY == msg.header().opcode() && !msg.header().qr() {
            if let Some(q) = msg.first_question() {
                if matches!(q.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR)
                {
                    return Some(q);
                }
            }
        } else if Opcode::NOTIFY == msg.header().opcode()
            && !msg.header().qr()
        {
            if let Some(q) = msg.first_question() {
                if matches!(q.qtype(), Rtype::SOA) {
                    return Some(q);
                }
            }
        }

        None
    }

    fn map_stream_item(
        request: Request<RequestOctets, ()>,
        stream_item: ServiceResult<NextSvc::Target>,
        pp_config: PostprocessingConfig<KS>,
    ) -> ServiceResult<NextSvc::Target> {
        if let Ok(mut call_res) = stream_item {
            if matches!(
                call_res.feedback(),
                Some(ServiceFeedback::BeginTransaction)
            ) {
                // Does it need converting from the variant that supports
                // single messages only (ServerTransaction) to the variant
                // that supports signing multiple messages (ServerSequence)?
                // Note: confusingly BeginTransaction and ServerTransaction
                // use the term "transaction" to mean completely the opppsite
                // of each other. With BeginTransaction we mean that the
                // caller should instead a sequence of response messages
                // instead of the usual single response message. With
                // ServerTransaction the TSIG code means handling of single
                // messages only and NOT sequences for which there is a
                // separate ServerSequence type. Sigh.
                let mut locked_tsig = pp_config.tsig.lock().unwrap();
                let mutable_tsig = locked_tsig.deref_mut();
                if let Some(TsigSigner::Transaction(tsig_txn)) =
                    mutable_tsig.take()
                {
                    // Do the conversion and store the result for future
                    // invocations of this function for subsequent items
                    // in the response stream.
                    *mutable_tsig = Some(TsigSigner::Sequence(
                        ServerSequence::from(tsig_txn),
                    ));
                }
            }

            if let Some(response) = call_res.response_mut() {
                if let Some(new_response) =
                    Self::postprocess(&request, response, pp_config)
                {
                    *response = new_response;
                }
            }

            Ok(call_res)
        } else {
            stream_item
        }
    }
}

//--- Service

impl<RequestOctets, NextSvc, KS> Service<RequestOctets>
    for TsigMiddlewareSvc<RequestOctets, NextSvc, KS>
where
    RequestOctets:
        Octets + OctetsFrom<Vec<u8>> + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, Option<KeyName>>
        + Clone
        + 'static
        + Send
        + Sync
        + Unpin,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    KS: Clone + KeyStore + Unpin,
    KS::Key: Clone + Unpin,
    Infallible: From<<RequestOctets as octseq::OctetsFrom<Vec<u8>>>::Error>,
{
    type Target = NextSvc::Target;
    type Stream = MiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        PostprocessingStream<
            RequestOctets,
            NextSvc::Future,
            NextSvc::Stream,
            (),
            PostprocessingConfig<KS>,
        >,
        Once<Ready<<NextSvc::Stream as Stream>::Item>>,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = core::future::Ready<Self::Stream>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        match Self::preprocess(&request, &self.key_store) {
            ControlFlow::Continue(Some((modified_req, tsig_opt))) => {
                let tsig = Arc::new(std::sync::Mutex::new(Some(tsig_opt)));

                let svc_call_fut = self.next_svc.call(modified_req);

                let pp_config = PostprocessingConfig {
                    tsig,
                    key_store: self.key_store.clone(),
                };

                let map = PostprocessingStream::new(
                    svc_call_fut,
                    request,
                    pp_config,
                    Self::map_stream_item,
                );

                ready(MiddlewareStream::Map(map))
            }

            ControlFlow::Continue(None) => {
                let request = request.with_new_metadata(None);
                let svc_call_fut = self.next_svc.call(request);
                ready(MiddlewareStream::IdentityFuture(svc_call_fut))
            }

            ControlFlow::Break(additional) => {
                ready(MiddlewareStream::Result(once(ready(Ok(
                    CallResult::new(additional),
                )))))
            }
        }
    }
}

#[derive(Clone)]
pub struct PostprocessingConfig<KS>
where
    KS: KeyStore + Clone,
{
    tsig: Arc<std::sync::Mutex<Option<TsigSigner<<KS as KeyStore>::Key>>>>,
    key_store: KS,
}

#[derive(Clone, Debug)]
enum TsigSigner<K> {
    /// TODO
    Transaction(ServerTransaction<K>),

    /// TODO
    Sequence(ServerSequence<K>),
}
