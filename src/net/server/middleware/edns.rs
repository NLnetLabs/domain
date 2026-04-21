//! RFC 6891 and related EDNS message processing.
use core::future::{ready, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;

use futures_util::stream::{once, Once, Stream};
use log::{log_enabled, Level};
use octseq::Octets;
use tracing::{debug, error, trace, warn};

use crate::base::iana::OptRcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::keepalive::IdleTimeout;
use crate::base::opt::{ComposeOptData, Opt, OptRecord, TcpKeepalive};
use crate::base::{Message, Name, StreamTarget};
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::{CallResult, Service, ServiceResult};
use crate::net::server::util::{
    add_edns_options, mk_error_response, remove_edns_opt_record,
};

use super::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
use super::stream::PostprocessingStream;
use crate::base::name::ToLabelIter;

/// EDNS version 0.
///
/// Version 0 is the highest EDNS version number recoded in the [IANA
/// registry] at the time of writing.
///
/// [IANA registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
const EDNS_VERSION_ZERO: u8 = 0;

/// A middleware service for adding EDNS(0) related functionality.
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
#[derive(Clone, Debug, Default)]
pub struct EdnsMiddlewareSvc<RequestOctets, NextSvc, RequestMeta>
where
    NextSvc: Service<RequestOctets, RequestMeta>,
    NextSvc::Future: Unpin,
    RequestOctets: Octets + Send + Sync + 'static + Unpin + Clone,
    RequestMeta: Clone + Default + Unpin + Send + Sync + 'static,
{
    /// The upstream [`Service`] to pass requests to and receive responses
    /// from.
    next_svc: NextSvc,

    /// Is the middleware service enabled?
    ///
    /// Defaults to true. If false, the service will pass requests and
    /// responses through unmodified.
    enabled: bool,

    _phantom: PhantomData<(RequestOctets, RequestMeta)>,
}

impl<RequestOctets, NextSvc, RequestMeta>
    EdnsMiddlewareSvc<RequestOctets, NextSvc, RequestMeta>
where
    NextSvc: Service<RequestOctets, RequestMeta>,
    NextSvc::Future: Unpin,
    RequestOctets: Octets + Send + Sync + 'static + Unpin + Clone,
    RequestMeta: Clone + Default + Unpin + Send + Sync + 'static,
{
    /// Creates an instance of this middleware service.
    #[must_use]
    pub fn new(next_svc: NextSvc) -> Self {
        Self {
            next_svc,
            enabled: true,
            _phantom: PhantomData,
        }
    }

    pub fn enable(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl<RequestOctets, NextSvc, RequestMeta>
    EdnsMiddlewareSvc<RequestOctets, NextSvc, RequestMeta>
where
    NextSvc: Service<RequestOctets, RequestMeta>,
    NextSvc::Future: Unpin,
    RequestOctets: Octets + Send + Sync + 'static + Unpin + Clone,
    RequestMeta: Clone + Default + Unpin + Send + Sync + 'static,
{
    fn preprocess(
        &self,
        request: &mut Request<RequestOctets, RequestMeta>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<NextSvc::Target>>> {
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
                    return ControlFlow::Break(mk_error_response(
                        request.message(),
                        OptRcode::FORMERR,
                    ));
                }

                let opt = match opt {
                    Ok(opt) => opt,
                    Err(err) => {
                        debug!("RFC 6891 violation: unable to parse OPT RR: {err}");
                        return ControlFlow::Break(mk_error_response(
                            request.message(),
                            OptRcode::FORMERR,
                        ));
                    }
                };

                let opt_rec = OptRecord::from(opt);

                // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
                // 6.1.3. OPT Record TTL Field Use
                //   "If a responder does not implement the VERSION level of
                //    the request, then it MUST respond with RCODE=BADVERS."
                if opt_rec.version() > EDNS_VERSION_ZERO {
                    debug!("RFC 6891 6.1.3 violation: request EDNS version {} > 0", opt_rec.version());
                    return ControlFlow::Break(mk_error_response(
                        request.message(),
                        OptRcode::BADVERS,
                    ));
                }

                match request.transport_ctx() {
                    TransportSpecificContext::Udp(ctx) => {
                        // https://datatracker.ietf.org/doc/html/rfc7828#section-3.3.1
                        // 3.3.1.  Receiving Queries
                        //   "A DNS server that receives a query using UDP
                        //    transport that includes the edns-tcp-keepalive
                        //    option MUST ignore the option."
                        if log_enabled!(Level::Debug)
                            && opt_rec.opt().tcp_keepalive().is_some()
                        {
                            debug!("RFC 7828 3.2.1 violation: ignoring edns-tcp-keepalive option received via UDP");
                        }

                        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.3
                        // 6.2.3. Requestor's Payload Size
                        //   "The requestor's UDP payload size (encoded in the
                        //    RR CLASS field) is the number of octets of the
                        //    largest UDP payload that can be reassembled and
                        //    delivered in the requestor's network stack. Note
                        //    that path MTU, with or without fragmentation,
                        //    could be smaller than this.
                        //
                        //    Values lower than 512 MUST be treated as equal
                        //    to 512."
                        let requestors_udp_payload_size =
                            opt_rec.udp_payload_size();

                        if log_enabled!(Level::Debug)
                            && requestors_udp_payload_size
                                < MINIMUM_RESPONSE_BYTE_LEN
                        {
                            debug!("RFC 6891 6.2.3 violation: OPT RR class (requestor's UDP payload size) < {MINIMUM_RESPONSE_BYTE_LEN}");
                        }

                        // Clamp the lower bound of the size limit requested
                        // by the client:
                        let clamped_requestors_udp_payload_size = u16::max(
                            MINIMUM_RESPONSE_BYTE_LEN,
                            requestors_udp_payload_size,
                        );

                        // Clamp the upper bound of the size limit requested
                        // by the server:
                        let server_max_response_size_hint =
                            ctx.max_response_size_hint();
                        let clamped_server_hint =
                            server_max_response_size_hint.map(|v| {
                                v.clamp(
                                    MINIMUM_RESPONSE_BYTE_LEN,
                                    clamped_requestors_udp_payload_size,
                                )
                            });

                        // Use the clamped client size limit if no server hint
                        // exists, otherwise use the smallest of the client
                        // and server limits while not going lower than 512
                        // bytes.
                        let negotiated_hint = match clamped_server_hint {
                            Some(clamped_server_hint) => u16::min(
                                clamped_requestors_udp_payload_size,
                                clamped_server_hint,
                            ),

                            None => clamped_requestors_udp_payload_size,
                        };

                        if log_enabled!(Level::Trace) {
                            trace!("EDNS(0) response size negotation concluded: client requested={}, server requested={:?}, chosen value={}",
                                opt_rec.udp_payload_size(), server_max_response_size_hint, negotiated_hint);
                        }

                        ctx.set_max_response_size_hint(Some(negotiated_hint));

                        Self::reserve_space_for_opt(request, false);
                    }

                    TransportSpecificContext::NonUdp(_ctx) => {
                        // https://datatracker.ietf.org/doc/html/rfc7828#section-3.2.1
                        // 3.2.1. Sending Queries
                        //   "Clients MUST specify an OPTION-LENGTH of 0 and
                        //    omit the TIMEOUT value."
                        if let Some(keep_alive) =
                            opt_rec.opt().tcp_keepalive()
                        {
                            if keep_alive.timeout().is_some() {
                                debug!("RFC 7828 3.2.1 violation: edns-tcp-keepalive option received via TCP contains timeout");
                                return ControlFlow::Break(
                                    mk_error_response(
                                        request.message(),
                                        OptRcode::FORMERR,
                                    ),
                                );
                            }
                        }

                        Self::reserve_space_for_opt(request, true);
                    }
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn postprocess(
        request: &Request<RequestOctets, RequestMeta>,
        response: &mut AdditionalBuilder<StreamTarget<NextSvc::Target>>,
    ) {
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
                *response =
                    mk_error_response(request.message(), OptRcode::SERVFAIL);
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

                                // Remove the limit we should have imposed during pre-processing so
                                // that we can use the space we reserved for the OPT RR.
                                response.clear_push_limit();

                                if let Err(err) =
                                    // TODO: Don't add the option if it
                                    // already exists?
                                    add_edns_options(
                                        response,
                                        |builder| {
                                            builder.push(&TcpKeepalive::new(
                                                Some(timeout),
                                            ))
                                        },
                                    )
                                {
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

        // https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.1
        // 6.1.1: Basic Elements
        // ...
        // "If an OPT record is present in a received request, compliant
        //  responders MUST include an OPT record in their respective
        //  responses."
        if request.message().opt().is_some()
            && Message::from_octets(response.as_slice())
                .unwrap()
                .opt()
                .is_none()
        {
            if let Err(err) = response.opt(|_| Ok(())) {
                warn!("Cannot add RFC 6891 OPT record to response: {err}");
            }
        }

        // TODO: For UDP EDNS capable clients (those that included an OPT
        // record in the request) should we set the Requestor's Payload Size
        // field to some value?
    }

    fn reserve_space_for_opt(
        request: &mut Request<RequestOctets, RequestMeta>,
        is_tcp: bool,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.1
        // 6.1.1. Basic Elements
        //   "If an OPT record is present in a received
        //    request, compliant responders MUST include an
        //    OPT record in their respective responses."
        if request.message().opt().is_none() {
            return;
        }

        // https://datatracker.ietf.org/doc/html/rfc7828#section-3.3.2
        // 3.3.2.  Sending Responses
        //   "A DNS server that receives a query sent using TCP transport that
        //    includes an OPT RR (with or without the edns-tcp-keepalive
        //    option) MAY include the edns-tcp-keepalive option in the
        //    response to signal the expected idle timeout on a connection.
        //    Servers MUST specify the TIMEOUT value that is currently
        //    associated with the TCP session."
        let keep_alive_option_len = if is_tcp {
            // TODO: As the byte length to reserve is fixed we would ideally
            // be able to use a constant here instead of calculating the
            // length.
            let option_data = TcpKeepalive::new(Some(0u16.into()));
            // OPTION-CODE + OPTION-LENGTH + OPTION-DATA
            2 + 2 + option_data.compose_len()
        } else {
            0
        };

        let root_name_len = Name::root_ref().compose_len();

        // See:
        //  - https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1
        //  - https://datatracker.ietf.org/doc/html/rfc6891#autoid-12
        //  - https://datatracker.ietf.org/doc/html/rfc7828#section-3.1

        // Calculate the size of the DNS OPTION RR that will be added to the
        // response during post-processing.
        let wire_opt_len = root_name_len // "0" root domain name per RFC 6891
            + 2 // TYPE
            + 2 // CLASS
            + 4 // TTL
            + 2 // RDLEN
            + keep_alive_option_len; // OPTION-DATA

        request.reserve_bytes(wire_opt_len);
    }

    fn map_stream_item(
        request: Request<RequestOctets, RequestMeta>,
        mut stream_item: ServiceResult<NextSvc::Target>,
        _pp_meta: &mut (),
    ) -> ServiceResult<NextSvc::Target> {
        if let Ok(cr) = &mut stream_item {
            if let Some(response) = cr.response_mut() {
                Self::postprocess(&request, response);
            }
        }
        stream_item
    }
}

//--- Service

impl<RequestOctets, NextSvc, RequestMeta> Service<RequestOctets, RequestMeta>
    for EdnsMiddlewareSvc<RequestOctets, NextSvc, RequestMeta>
where
    NextSvc: Service<RequestOctets, RequestMeta>,
    NextSvc::Future: Unpin,
    RequestOctets: Octets + Send + Sync + 'static + Unpin + Clone,
    RequestMeta: Clone + Default + Unpin + Send + Sync + 'static,
{
    type Target = NextSvc::Target;
    type Stream = MiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        PostprocessingStream<
            RequestOctets,
            NextSvc::Future,
            NextSvc::Stream,
            RequestMeta,
            (),
        >,
        Once<Ready<<NextSvc::Stream as Stream>::Item>>,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Ready<Self::Stream>;
    fn call(
        &self,
        mut request: Request<RequestOctets, RequestMeta>,
    ) -> Self::Future {
        if !self.enabled {
            let svc_call_fut = self.next_svc.call(request.clone());
            return ready(MiddlewareStream::IdentityFuture(svc_call_fut));
        }

        match self.preprocess(&mut request) {
            ControlFlow::Continue(()) => {
                let svc_call_fut = self.next_svc.call(request.clone());
                let map = PostprocessingStream::new(
                    svc_call_fut,
                    request,
                    (),
                    Self::map_stream_item,
                );
                ready(MiddlewareStream::Map(map))
            }
            ControlFlow::Break(mut response) => {
                Self::postprocess(&request, &mut response);
                ready(MiddlewareStream::Result(once(ready(Ok(
                    CallResult::new(response),
                )))))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use bytes::Bytes;
    use futures_util::stream::StreamExt;
    use tokio::time::Instant;

    use crate::base::{Message, MessageBuilder, Name, Rtype};
    use crate::net::server::message::{
        Request, TransportSpecificContext, UdpTransportContext,
    };

    use crate::base::iana::Rcode;
    use crate::net::server::middleware::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
    use crate::net::server::service::{CallResult, Service, ServiceResult};
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
        // The EdnsMiddlewareSvc should leave these untouched as no EDNS
        // option was present in the request, only the server hint exists, and
        // EdnsMiddlewareSvc only acts if the client EDNS option is present.
        assert_eq!(process(None, TOO_SMALL).await, TOO_SMALL);
        assert_eq!(process(None, JUST_RIGHT).await, JUST_RIGHT);
        assert_eq!(process(None, HUGE).await, HUGE);

        // --- Only client specified max UDP response sizes
        //
        // The EdnsMiddlewareSvc should adopt these, after clamping
        // them.
        assert_eq!(process(TOO_SMALL, None).await, JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, None).await, JUST_RIGHT);
        assert_eq!(process(HUGE, None).await, HUGE);

        // --- Both client and server specified max UDP response sizes
        //
        // The EdnsMiddlewareSvc should negotiate the largest size
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
        query.push((Name::<Bytes>::root(), Rtype::A)).unwrap();

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
            ctx.into(),
            (),
        );

        fn my_service(
            req: Request<Vec<u8>, ()>,
            _meta: (),
        ) -> ServiceResult<Vec<u8>> {
            // For each request create a single response:
            let builder = mk_builder_for_target();
            let answer =
                builder.start_answer(req.message(), Rcode::NXDOMAIN)?;
            Ok(CallResult::new(answer.additional()))
        }

        // Either call the service directly.
        let my_svc = service_fn(my_service, ());
        let mut stream = my_svc.call(request.clone()).await;
        let _call_result: CallResult<_> =
            stream.next().await.unwrap().unwrap();

        // Or pass the query through the middleware service
        let middleware_svc = EdnsMiddlewareSvc::new(my_svc);
        let mut stream = middleware_svc.call(request.clone()).await;
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
