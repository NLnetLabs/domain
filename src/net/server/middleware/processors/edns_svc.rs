//! RFC 6891 and related EDNS message processing.
use core::future::ready;
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::task::{Context, Poll};

use std::pin::Pin;

use futures::stream::once;
use futures::Stream;
use futures_util::StreamExt;
use octseq::Octets;
use tracing::{debug, enabled, error, trace, warn, Level};

use crate::base::iana::{OptRcode, OptionCode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::keepalive::IdleTimeout;
use crate::base::opt::{Opt, OptRecord, TcpKeepalive};
use crate::base::wire::Composer;
use crate::base::StreamTarget;
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::processors::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
use crate::net::server::middleware::util::MiddlewareStream;
use crate::net::server::service::{CallResult, Service, ServiceError};
use crate::net::server::util::start_reply;
use crate::net::server::util::{add_edns_options, remove_edns_opt_record};

/// EDNS version 0.
///
/// Version 0 is the highest EDNS version number recoded in the [IANA
/// registry] at the time of writing.
///
/// [IANA registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
const EDNS_VERSION_ZERO: u8 = 0;

/// A [`MiddlewareProcessor`] for adding EDNS(0) related functionality.
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [6891] | TBD     |
/// | [7828] | TBD     |
/// | [9210] | TBD     |
///
/// [6891]: https://datatracker.ietf.org/doc/html/rfc6891
/// [7828]: https://datatracker.ietf.org/doc/html/rfc7828
/// [9210]: https://datatracker.ietf.org/doc/html/rfc9210
/// [`MiddlewareProcessor`]: crate::net::server::middleware::processor::MiddlewareProcessor
#[derive(Debug, Default)]
pub struct EdnsMiddlewareSvc<S> {
    inner: S,
}

impl<S> EdnsMiddlewareSvc<S> {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> EdnsMiddlewareSvc<S> {
    /// Create a DNS error response to the given request with the given RCODE.
    fn error_response<RequestOctets, Target>(
        request: &Request<RequestOctets>,
        rcode: OptRcode,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        let mut additional = start_reply(request).additional();

        // Note: if rcode is non-extended this will also correctly handle
        // setting the rcode in the main message header.
        if let Err(err) = add_edns_options(&mut additional, |_, opt| {
            opt.set_rcode(rcode);
            Ok(())
        }) {
            warn!(
                "Failed to set (extended) error '{rcode}' in response: {err}"
            );
        }

        Self::postprocess(request, &mut additional);
        additional
    }
}

//--- MiddlewareProcessor

impl<S> EdnsMiddlewareSvc<S> {
    fn preprocess<RequestOctets, Target>(
        &self,
        request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        // https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.1
        // 6.1.1: Basic Elements
        // ...
        // "If a query message with more than one OPT RR is received, a
        //  FORMERR (RCODE=1) MUST be returned"
        let msg = request.message().clone();
        if let Ok(additional) = msg.additional() {
            let mut iter = additional.limit_to::<Opt<_>>();
            if let Some(opt) = iter.next() {
                if iter.next().is_some() {
                    // More than one OPT RR received.
                    debug!("RFC 6891 6.1.1 violation: request contains more than one OPT RR.");
                    return ControlFlow::Break(Self::error_response(
                        request,
                        OptRcode::FORMERR,
                    ));
                }

                if let Ok(opt) = opt {
                    let opt_rec = OptRecord::from(opt);

                    // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
                    // 6.1.3. OPT Record TTL Field Use
                    //   "If a responder does not implement the VERSION level
                    //    of the request, then it MUST respond with
                    //    RCODE=BADVERS."
                    if opt_rec.version() > EDNS_VERSION_ZERO {
                        debug!("RFC 6891 6.1.3 violation: request EDNS version {} > 0", opt_rec.version());
                        return ControlFlow::Break(Self::error_response(
                            request,
                            OptRcode::BADVERS,
                        ));
                    }

                    match request.transport_ctx() {
                        TransportSpecificContext::Udp(ctx) => {
                            // https://datatracker.ietf.org/doc/html/rfc7828#section-3.2.1
                            // 3.2.1. Sending Queries
                            //   "DNS clients MUST NOT include the
                            //    edns-tcp-keepalive option in queries sent
                            //    using UDP transport."
                            // TODO: We assume there is only one keep-alive
                            // option in the request. Should we check for
                            // multiple? Neither RFC 6891 nor RFC 7828 seem to
                            // disallow multiple keep alive options in the OPT
                            // RDATA but multiple at once seems strange.
                            if opt_rec.opt().tcp_keepalive().is_some() {
                                debug!("RFC 7828 3.2.1 violation: edns-tcp-keepalive option received via UDP");
                                return ControlFlow::Break(
                                    Self::error_response(
                                        request,
                                        OptRcode::FORMERR,
                                    ),
                                );
                            }

                            // https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.3
                            // 6.2.3. Requestor's Payload Size
                            //   "The requestor's UDP payload size (encoded in
                            //    the RR CLASS field) is the number of octets
                            //    of the largest UDP payload that can be
                            //    reassembled and delivered in the requestor's
                            //    network stack. Note that path MTU, with or
                            //    without fragmentation, could be smaller than
                            //    this.
                            //
                            //    Values lower than 512 MUST be treated as
                            //    equal to 512."
                            let requestors_udp_payload_size =
                                opt_rec.udp_payload_size();

                            if requestors_udp_payload_size
                                < MINIMUM_RESPONSE_BYTE_LEN
                            {
                                debug!("RFC 6891 6.2.3 violation: OPT RR class (requestor's UDP payload size) < {MINIMUM_RESPONSE_BYTE_LEN}");
                            }

                            // Clamp the lower bound of the size limit
                            // requested by the client:
                            let clamped_requestors_udp_payload_size =
                                u16::max(512, requestors_udp_payload_size);

                            // Clamp the upper bound of the size limit
                            // requested by the server:
                            let server_max_response_size_hint =
                                ctx.max_response_size_hint();
                            let clamped_server_hint =
                                server_max_response_size_hint.map(|v| {
                                    v.clamp(
                                        MINIMUM_RESPONSE_BYTE_LEN,
                                        clamped_requestors_udp_payload_size,
                                    )
                                });

                            // Use the clamped client size limit if no server hint exists,
                            // otherwise use the smallest of the client and server limits
                            // while not going lower than 512 bytes.
                            let negotiated_hint = match clamped_server_hint {
                                Some(clamped_server_hint) => u16::min(
                                    clamped_requestors_udp_payload_size,
                                    clamped_server_hint,
                                ),

                                None => clamped_requestors_udp_payload_size,
                            };

                            if enabled!(Level::TRACE) {
                                trace!("EDNS(0) response size negotation concluded: client requested={}, server requested={:?}, chosen value={}",
                                    opt_rec.udp_payload_size(), server_max_response_size_hint, negotiated_hint);
                            }

                            ctx.set_max_response_size_hint(Some(
                                negotiated_hint,
                            ));
                        }

                        TransportSpecificContext::NonUdp(_) => {
                            // https://datatracker.ietf.org/doc/html/rfc7828#section-3.2.1
                            // 3.2.1. Sending Queries
                            //   "Clients MUST specify an OPTION-LENGTH of 0
                            //    and omit the TIMEOUT value."
                            if let Some(keep_alive) =
                                opt_rec.opt().tcp_keepalive()
                            {
                                if keep_alive.timeout().is_some() {
                                    debug!("RFC 7828 3.2.1 violation: edns-tcp-keepalive option received via TCP contains timeout");
                                    return ControlFlow::Break(
                                        Self::error_response(
                                            request,
                                            OptRcode::FORMERR,
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn postprocess<RequestOctets, Target>(
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        // https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.1
        // 6.1.1: Basic Elements
        // ...
        // "If an OPT record is present in a received request, compliant
        //  responders MUST include an OPT record in their respective
        //  responses."
        //
        // We don't do anything about this scenario at present.

        // https://www.rfc-editor.org/rfc/rfc6891.html#section-7
        // 7: Transport considerations
        // ...
        // "Lack of presence of an OPT record in a request MUST be taken as an
        //  indication that the requestor does not implement any part of this
        //  specification and that the responder MUST NOT include an OPT
        //  record in its response."
        //
        // So strip off any OPT record present if the query lacked an OPT
        // record.
        if request.message().opt().is_none() {
            if let Err(err) = remove_edns_opt_record(response) {
                error!(
                    "Error while stripping OPT record from response: {err}"
                );
                *response = Self::error_response(request, OptRcode::SERVFAIL);
                return;
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc7828#section-3.3.2
        // 3.3.2.  Sending Responses
        //   "A DNS server that receives a query sent using TCP transport that
        //    includes an OPT RR (with or without the edns-tcp-keepalive
        //    option) MAY include the edns-tcp-keepalive option in the
        //    response to signal the expected idle timeout on a connection.
        //    Servers MUST specify the TIMEOUT value that is currently
        //    associated with the TCP session."
        //
        // https://datatracker.ietf.org/doc/html/rfc9210#section-4.2
        // 4.2. Connection Management
        //   "... DNS clients and servers SHOULD signal their timeout values
        //   using the edns-tcp-keepalive EDNS(0) option [RFC7828]."
        if let TransportSpecificContext::NonUdp(ctx) = request.transport_ctx()
        {
            if let Some(idle_timeout) = ctx.idle_timeout() {
                if let Ok(additional) = request.message().additional() {
                    let mut iter = additional.limit_to::<Opt<_>>();
                    if iter.next().is_some() {
                        match IdleTimeout::try_from(idle_timeout) {
                            Ok(timeout) => {
                                // Request has an OPT RR and server idle
                                // timeout is known: "Signal the timeout value
                                // using the edns-tcp-keepalive EDNS(0) option
                                // [RFC7828]".
                                if let Err(err) = add_edns_options(
                                    response,
                                    |existing_option_codes, builder| {
                                        if !existing_option_codes.contains(
                                            &OptionCode::TCP_KEEPALIVE,
                                        ) {
                                            builder.push(&TcpKeepalive::new(
                                                Some(timeout),
                                            ))
                                        } else {
                                            Ok(())
                                        }
                                    },
                                ) {
                                    warn!("Cannot add RFC 7828 edns-tcp-keepalive option to response: {err}");
                                }
                            }

                            Err(err) => {
                                warn!("Cannot add RFC 7828 edns-tcp-keepalive option to response: invalid timeout: {err}");
                            }
                        }
                    }
                }
            }
        }

        // TODO: For UDP EDNS capable clients (those that included an OPT
        // record in the request) should we set the Requestor's Payload Size
        // field to some value?
    }
}

//--- Service

impl<RequestOctets, S, Target> Service<RequestOctets> for EdnsMiddlewareSvc<S>
where
    RequestOctets: Octets + 'static,
    S: Service<RequestOctets>,
    S::Stream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin
        + 'static,
    Target: Composer + Default + 'static + Unpin,
{
    type Target = Target;
    type Stream = MiddlewareStream<
        S::Stream,
        PostprocessingStream<RequestOctets, Target, S::Stream>,
        Target,
    >;

    fn call(&self, request: Request<RequestOctets>) -> Self::Stream {
        match self.preprocess(&request) {
            ControlFlow::Continue(()) => {
                let st = self.inner.call(request.clone());
                let map = PostprocessingStream::new(st, request);
                MiddlewareStream::Postprocess(map)
            }
            ControlFlow::Break(mut response) => {
                Self::postprocess(&request, &mut response);
                MiddlewareStream::HandledOne(once(ready(Ok(
                    CallResult::new(response),
                ))))
            }
        }
    }
}

pub struct PostprocessingStream<
    RequestOctets,
    Target,
    InnerServiceResponseStream,
> where
    RequestOctets: Octets,
    InnerServiceResponseStream: futures::stream::Stream<
        Item = Result<CallResult<Target>, ServiceError>,
    >,
{
    request: Request<RequestOctets>,
    _phantom: PhantomData<Target>,
    stream: InnerServiceResponseStream,
}

impl<RequestOctets, Target, InnerServiceResponseStream>
    PostprocessingStream<RequestOctets, Target, InnerServiceResponseStream>
where
    RequestOctets: Octets,
    InnerServiceResponseStream: futures::stream::Stream<
        Item = Result<CallResult<Target>, ServiceError>,
    >,
{
    pub(crate) fn new(
        stream: InnerServiceResponseStream,
        request: Request<RequestOctets>,
    ) -> Self {
        Self {
            stream,
            request,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Target, InnerServiceResponseStream> Stream
    for PostprocessingStream<
        RequestOctets,
        Target,
        InnerServiceResponseStream,
    >
where
    RequestOctets: Octets,
    InnerServiceResponseStream: futures::stream::Stream<
            Item = Result<CallResult<Target>, ServiceError>,
        > + Unpin,
    Target: Composer + Default + Unpin,
{
    type Item = Result<CallResult<Target>, ServiceError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let res = futures::ready!(self.stream.poll_next_unpin(cx));
        let request = self.request.clone();
        Poll::Ready(res.map(|mut res| {
            if let Ok(cr) = &mut res {
                if let Some(response) = cr.get_response_mut() {
                    EdnsMiddlewareSvc::<InnerServiceResponseStream>::postprocess(&request, response);
                }
            }
            res
        }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use core::pin::Pin;

    use std::boxed::Box;
    use std::vec::Vec;

    use bytes::Bytes;
    use futures::stream::Once;
    use futures::stream::StreamExt;
    use tokio::time::Instant;

    use crate::base::{Dname, Message, MessageBuilder, Rtype};
    use crate::net::server::message::{
        Request, TransportSpecificContext, UdpTransportContext,
    };

    use crate::base::iana::Rcode;
    use crate::net::server::middleware::processors::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
    use crate::net::server::service::{CallResult, Service, ServiceError};
    use crate::net::server::util::{mk_builder_for_target, service_fn};

    use super::EdnsMiddlewareSvc;

    //------------ Constants -------------------------------------------------

    const MIN_ALLOWED: Option<u16> = Some(MINIMUM_RESPONSE_BYTE_LEN);
    const TOO_SMALL: Option<u16> = Some(511);
    const JUST_RIGHT: Option<u16> = MIN_ALLOWED;
    const HUGE: Option<u16> = Some(u16::MAX);

    //------------ Tests -----------------------------------------------------

    #[tokio::test]
    async fn clamp_max_response_size_correctly() {
        // Neither client or server specified a max UDP response size.
        assert_eq!(process(None, None).await, None);

        // --- Only server specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should leave these untouched as no EDNS
        // option was present in the request, only the server hint exists, and
        // EdnsMiddlewareProcessor only acts if the client EDNS option is
        // present.
        assert_eq!(process(None, TOO_SMALL).await, TOO_SMALL);
        assert_eq!(process(None, JUST_RIGHT).await, JUST_RIGHT);
        assert_eq!(process(None, HUGE).await, HUGE);

        // --- Only client specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should adopt these, after clamping
        // them.
        assert_eq!(process(TOO_SMALL, None).await, JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, None).await, JUST_RIGHT);
        assert_eq!(process(HUGE, None).await, HUGE);

        // --- Both client and server specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should negotiate the largest size
        // acceptable to both sides.
        assert_eq!(process(TOO_SMALL, TOO_SMALL).await, MIN_ALLOWED);
        assert_eq!(process(TOO_SMALL, JUST_RIGHT).await, JUST_RIGHT);
        assert_eq!(process(TOO_SMALL, HUGE).await, MIN_ALLOWED);
        assert_eq!(process(JUST_RIGHT, TOO_SMALL).await, JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, JUST_RIGHT).await, JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, HUGE).await, JUST_RIGHT);
        assert_eq!(process(HUGE, TOO_SMALL).await, MIN_ALLOWED);
        assert_eq!(process(HUGE, JUST_RIGHT).await, JUST_RIGHT);
        assert_eq!(process(HUGE, HUGE).await, HUGE);
    }

    //------------ Helper functions ------------------------------------------

    async fn process(
        client_value: Option<u16>,
        server_value: Option<u16>,
    ) -> Option<u16> {
        // Build a dummy DNS query.
        let query = MessageBuilder::new_vec();

        // With a dummy question.
        let mut query = query.question();
        query.push((Dname::<Bytes>::root(), Rtype::A)).unwrap();

        // And if requested, a requestor's UDP payload size:
        let message: Message<_> = if let Some(v) = client_value {
            let mut additional = query.additional();
            additional
                .opt(|builder| {
                    builder.set_udp_payload_size(v);
                    Ok(())
                })
                .unwrap();
            additional.into_message()
        } else {
            query.into_message()
        };

        // Package the query into a context aware request to make it look
        // as if it came from a UDP server.
        let ctx = UdpTransportContext::new(server_value);
        let request = Request::new(
            "127.0.0.1:12345".parse().unwrap(),
            Instant::now(),
            message,
            TransportSpecificContext::Udp(ctx),
        );

        fn my_service(
            req: Request<Vec<u8>>,
            _meta: (),
        ) -> Once<
            Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                CallResult<Vec<u8>>,
                                ServiceError,
                            >,
                        > + Send,
                >,
            >,
        > {
            // For each request create a single response:
            let msg = req.message().clone();
            futures::stream::once(Box::pin(async move {
                let builder = mk_builder_for_target();
                let answer = builder.start_answer(&msg, Rcode::NXDOMAIN)?;
                Ok(CallResult::new(answer.additional()))
            }))
        }

        // Either call the service directly.
        let my_svc = service_fn(my_service, ());
        let mut stream = my_svc.call(request.clone());
        let _call_result: CallResult<Vec<u8>> =
            stream.next().await.unwrap().unwrap();

        // Or pass the query through the middleware processor
        let processor_svc = EdnsMiddlewareSvc::new(my_svc);
        let mut stream = processor_svc.call(request.clone());
        let call_result: CallResult<Vec<u8>> =
            stream.next().await.unwrap().unwrap();
        let (_response, _feedback) = call_result.into_inner();

        // Get the modified response size hint.
        let TransportSpecificContext::Udp(modified_udp_context) =
            request.transport_ctx()
        else {
            unreachable!()
        };

        modified_udp_context.max_response_size_hint()
    }
}
