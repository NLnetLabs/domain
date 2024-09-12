//! RFC 8495 TSIG message authentication middleware.
//!
//! This module provides a TSIG request validation and response signing
//! middleware service. The underlying TSIG RR processing is implemented using
//! the [`tsig`] module.
//!
//! # Communicating which key signed a request.
//!
//! For signed requests this middleware service passes the signing key to
//! upstream [`Service`] impls via request metadata. Upstream services can
//! choose to ignore the metadata by being generic over any kind of metadata,
//! or may offer a [`Service`] impl that specifically accepts the
//! [`Option<tsig::Key>`] metadata type. The upstream service is then able to
//! use the received metadata to learn which key the request was signed with.

use core::convert::Infallible;
use core::future::{ready, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;

use std::vec::Vec;

use futures::stream::{once, Once, Stream};
use octseq::{Octets, OctetsFrom};
use tracing::{error, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, ParsedName, Question, Rtype, StreamTarget};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::tsig::Time48;
use crate::tsig::{self, KeyStore, ServerSequence, ServerTransaction};

use super::stream::{MiddlewareStream, PostprocessingStream};

//------------ TsigMiddlewareSvc ----------------------------------------------

/// RFC 8495 TSIG message authentication middleware.
///
/// This middleware service validates TSIG signatures on incoming requests, if
/// any, and adds TSIG signatures to responses to signed requests.
///
/// Upstream services can detect whether a request is signed and with which
/// key by consuming the [`Option<KS::Key>`] metadata output by this service.
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
    /// Creates an instance of this middleware service.
    ///
    /// Keys in the provided [`KeyStore`] will be used to verify received signed
    /// requests and to sign the corresponding responses.
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
    RequestOctets: Octets + OctetsFrom<Vec<u8>> + Send + Sync + Unpin,
    NextSvc: Service<RequestOctets, Option<KS::Key>>,
    NextSvc::Target: Composer + Default,
    KS: Clone + KeyStore,
    KS::Key: Clone,
    Infallible: From<<RequestOctets as octseq::OctetsFrom<Vec<u8>>>::Error>,
{
    #[allow(clippy::type_complexity)]
    fn preprocess(
        req: &Request<RequestOctets>,
        key_store: &KS,
    ) -> ControlFlow<
        AdditionalBuilder<StreamTarget<NextSvc::Target>>,
        Option<(
            Request<RequestOctets, Option<KS::Key>>,
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
                        Some(tsig.key_wrapper().clone()),
                    );

                    let num_bytes_to_reserve = tsig.key().compose_len();
                    new_req.reserve_bytes(num_bytes_to_reserve);

                    return ControlFlow::Continue(Some((
                        new_req,
                        TsigSigner::Transaction(tsig),
                    )));
                }

                Err(err) => {
                    warn!(
                        "{} for {} from {} refused: {err}",
                        q.qtype(),
                        q.qname(),
                        req.client_addr(),
                    );
                    let builder = mk_builder_for_target();
                    let additional =
                        err.build_message(req.message(), builder).unwrap();
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
        pp_config: &mut PostprocessingConfig<KS::Key>,
    ) -> Option<AdditionalBuilder<StreamTarget<NextSvc::Target>>> {
        // Remove the limit we should have imposed during pre-processing so
        // that we can use the space we reserved for the OPT RR.
        response.clear_push_limit();

        // The variable itself isn't used by a reference to its interior value
        // *is* used if the if signing_result.is_err() block below.
        #[allow(unused_assignments)]
        let mut key_for_err_handling = None;

        let (signing_result, key) = match &mut pp_config.signer {
            Some(TsigSigner::Transaction(_)) => {
                // Extract the single response signer and consume it in the
                // signing process.
                let Some(TsigSigner::Transaction(signer)) =
                    pp_config.signer.take()
                else {
                    unreachable!()
                };

                trace!(
                    "Signing single response with TSIG key '{}'",
                    signer.key().name()
                );

                // We have to clone the key here in case the signer produces
                // an error, otherwise we lose access to the key as the signer
                // is consumed by calling answer(). The caller has control
                // over the key type via KS::Key so if cloning cost is a
                // problem the caller can choose to wrap the key in an Arc or
                // such to reduce the cloning cost.
                key_for_err_handling = Some(signer.key().clone());

                let res = signer.answer(response, Time48::now());

                (res, key_for_err_handling.as_ref().unwrap())
            }

            Some(TsigSigner::Sequence(ref mut signer)) => {
                // Use the multi-response signer to sign the response.
                trace!(
                    "Signing response stream with TSIG key '{}'",
                    signer.key().name()
                );
                let res = signer.answer(response, Time48::now());

                (res, signer.key())
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
                return Self::mk_signed_truncated_response(request, key);
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
        key: &tsig::Key,
    ) -> Option<AdditionalBuilder<StreamTarget<NextSvc::Target>>> {
        let octets = request.message().as_slice().to_vec();
        let mut mut_msg = Message::from_octets(octets).unwrap();
        let res =
            ServerTransaction::request(&key, &mut mut_msg, Time48::now());

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
        pp_config: &mut PostprocessingConfig<KS::Key>,
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
                if let Some(TsigSigner::Transaction(tsig_txn)) =
                    pp_config.signer.take()
                {
                    // Do the conversion and store the result for future
                    // invocations of this function for subsequent items
                    // in the response stream.
                    pp_config.signer = Some(TsigSigner::Sequence(
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

/// This [`Service`] implementation specifies that the upstream service will
/// be passed metadata of type [`Option<KS::Key>`]. The upstream service can
/// optionally use this to learn which TSIG key signed the request.
///
/// This service does not accept downstream metadata, explicitly restricting
/// what it accepts to `()`. This is because (a) the service should be the
/// first layer above the network server, or as near as possible, such that it
/// receives unmodified requests and that the responses it generates are sent
/// over the network without prior modification, and thus it is not very
/// likely that the is a downstream layer that has metadata to supply to us,
/// and (b) because this service does not propagate the metadata it receives
/// from downstream but instead outputs [`Option<KS::Key>`] metadata to
/// upstream services.
impl<RequestOctets, NextSvc, KS> Service<RequestOctets, ()>
    for TsigMiddlewareSvc<RequestOctets, NextSvc, KS>
where
    RequestOctets:
        Octets + OctetsFrom<Vec<u8>> + Send + Sync + 'static + Unpin,
    NextSvc: Service<RequestOctets, Option<KS::Key>>,
    NextSvc::Future: Unpin,
    NextSvc::Target: Composer + Default,
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
            PostprocessingConfig<KS::Key>,
        >,
        Once<Ready<<NextSvc::Stream as Stream>::Item>>,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Ready<Self::Stream>;

    fn call(&self, request: Request<RequestOctets, ()>) -> Self::Future {
        match Self::preprocess(&request, &self.key_store) {
            ControlFlow::Continue(Some((modified_req, signer))) => {
                let pp_config = PostprocessingConfig::new(signer);

                let svc_call_fut = self.next_svc.call(modified_req);

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

/// Data needed to do signing during response post-processing.

pub struct PostprocessingConfig<K> {
    /// The signer used to verify the request.
    ///
    /// Needed to sign responses.
    ///
    /// We store it as an Option because ServerTransaction::answer() consumes
    /// the signer so have to first take it out of this struct, as a reference
    /// is held to the struct so it iself cannot be consumed.
    signer: Option<TsigSigner<K>>,
}

impl<K> PostprocessingConfig<K> {
    fn new(signer: TsigSigner<K>) -> Self {
        Self {
            signer: Some(signer),
        }
    }
}

/// A wrapper around [`ServerTransaction`] and [`ServerSequence`].
///
/// This wrapper allows us to write calling code once that invokes methods on
/// the TSIG signer/validator which have the same name and purpose for single
/// response vs multiple response streams, yet have distinct Rust types and so
/// must be called on the correct type, without needing to know at the call
/// site which of the distinct types it actually is.
#[derive(Clone, Debug)]
enum TsigSigner<K> {
    /// A [`ServerTransaction`] for signing a single response.
    Transaction(ServerTransaction<K>),

    /// A [`ServerSequence`] for signing multiple responses.
    Sequence(ServerSequence<K>),
}
