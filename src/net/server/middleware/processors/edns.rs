//! RFC 6891 and related EDNS message processing.
use core::ops::ControlFlow;

use octseq::Octets;
use tracing::{debug, trace, warn};

use crate::base::iana::OptRcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt::keepalive::IdleTimeout;
use crate::base::opt::{Opt, OptRecord, TcpKeepalive};
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::processor::MiddlewareProcessor;
use crate::net::server::middleware::processors::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
use crate::net::server::util::add_edns_options;
use crate::net::server::util::start_reply;

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
pub struct EdnsMiddlewareProcessor;

impl EdnsMiddlewareProcessor {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl EdnsMiddlewareProcessor {
    /// Create a DNS error response to the given request with the given RCODE.
    fn error_response<RequestOctets, Target>(
        request: &Request<Message<RequestOctets>>,
        rcode: OptRcode,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        let mut additional = start_reply(request).additional();

        // Note: if rcode is non-extended this will also correctly handle
        // setting the rcode in the main message header.
        if let Err(err) = additional.opt(|opt| {
            opt.set_rcode(rcode);
            Ok(())
        }) {
            warn!(
                "Failed to set (extended) error '{rcode}' in response: {err}"
            );
        }

        additional
    }
}

//--- MiddlewareProcessor

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for EdnsMiddlewareProcessor
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn preprocess(
        &self,
        request: &mut Request<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
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
                        OptRcode::FormErr,
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
                            OptRcode::BadVers,
                        ));
                    }

                    match request.transport_mut() {
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
                                        OptRcode::FormErr,
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
                            let clamped_server_hint =
                                ctx.max_response_size_hint.map(|v| {
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

                            trace!("EDNS(0) response size negotation concluded: client requested={}, server requested={:?}, chosen value={}",
                            opt_rec.udp_payload_size(), ctx.max_response_size_hint, negotiated_hint);
                            ctx.max_response_size_hint =
                                Some(negotiated_hint);
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
                                            OptRcode::FormErr,
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

    fn postprocess(
        &self,
        request: &Request<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
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
        if let TransportSpecificContext::NonUdp(ctx) = request.transport() {
            if let Ok(additional) = request.message().additional() {
                let mut iter = additional.limit_to::<Opt<_>>();
                if iter.next().is_some() {
                    if let Some(idle_timeout) = ctx.idle_timeout {
                        match IdleTimeout::try_from(idle_timeout) {
                            Ok(timeout) => {
                                // Request has an OPT RR and server idle
                                // timeout is known: "Signal the timeout value
                                // using the edns-tcp-keepalive EDNS(0) option
                                // [RFC7828]".
                                if let Err(err) =
                                    add_edns_options(response, |builder| {
                                        builder.push(&TcpKeepalive::new(
                                            Some(timeout),
                                        ))
                                    })
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
        //
        // TODO: What if anything should we do if we detect a request with an
        // OPT record but a response that lacks an OPT record?

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

        // TODO: How can we strip off the OPT record in the response if no OPT
        // record is present in the request?
    }
}

#[cfg(test)]
mod tests {
    use core::ops::ControlFlow;

    use std::vec::Vec;

    use bytes::Bytes;
    use tokio::time::Instant;

    use crate::base::{Dname, Message, MessageBuilder, Rtype};
    use crate::net::server::message::{
        Request, TransportSpecificContext, UdpTransportContext,
    };

    use super::EdnsMiddlewareProcessor;
    use crate::net::server::middleware::processor::MiddlewareProcessor;
    use crate::net::server::middleware::processors::mandatory::MINIMUM_RESPONSE_BYTE_LEN;

    //------------ Constants -------------------------------------------------

    const MIN_ALLOWED: Option<u16> = Some(MINIMUM_RESPONSE_BYTE_LEN);
    const TOO_SMALL: Option<u16> = Some(511);
    const JUST_RIGHT: Option<u16> = MIN_ALLOWED;
    const HUGE: Option<u16> = Some(u16::MAX);

    //------------ Tests -----------------------------------------------------

    #[test]
    fn clamp_max_response_size_correctly() {
        // Neither client or server specified a max UDP response size.
        assert_eq!(process(None, None), None);

        // --- Only server specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should leave these untouched as no EDNS
        // option was present in the request, only the server hint exists, and
        // EdnsMiddlewareProcessor only acts if the client EDNS option is
        // present.
        assert_eq!(process(None, TOO_SMALL), TOO_SMALL);
        assert_eq!(process(None, JUST_RIGHT), JUST_RIGHT);
        assert_eq!(process(None, HUGE), HUGE);

        // --- Only client specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should adopt these, after clamping
        // them.
        assert_eq!(process(TOO_SMALL, None), JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, None), JUST_RIGHT);
        assert_eq!(process(HUGE, None), HUGE);

        // --- Both client and server specified max UDP response sizes
        //
        // The EdnsMiddlewareProcessor should negotiate the largest size
        // acceptable to both sides.
        assert_eq!(process(TOO_SMALL, TOO_SMALL), MIN_ALLOWED);
        assert_eq!(process(TOO_SMALL, JUST_RIGHT), JUST_RIGHT);
        assert_eq!(process(TOO_SMALL, HUGE), MIN_ALLOWED);
        assert_eq!(process(JUST_RIGHT, TOO_SMALL), JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, JUST_RIGHT), JUST_RIGHT);
        assert_eq!(process(JUST_RIGHT, HUGE), JUST_RIGHT);
        assert_eq!(process(HUGE, TOO_SMALL), MIN_ALLOWED);
        assert_eq!(process(HUGE, JUST_RIGHT), JUST_RIGHT);
        assert_eq!(process(HUGE, HUGE), HUGE);
    }

    //------------ Helper functions ------------------------------------------

    fn process(
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
        let udp_context = UdpTransportContext {
            max_response_size_hint: server_value,
        };
        let mut request = Request::new(
            "127.0.0.1:12345".parse().unwrap(),
            Instant::now(),
            message,
            TransportSpecificContext::Udp(udp_context),
        );

        // And pass the query through the middleware processor
        let processor = EdnsMiddlewareProcessor::new();
        let processor: &dyn MiddlewareProcessor<Vec<u8>, Vec<u8>> =
            &processor;
        let mut response = MessageBuilder::new_stream_vec().additional();
        if let ControlFlow::Continue(()) = processor.preprocess(&mut request)
        {
            processor.postprocess(&request, &mut response);
        }

        // Get the modified response size hint.
        let TransportSpecificContext::Udp(modified_udp_context) =
            request.transport()
        else {
            unreachable!()
        };

        modified_udp_context.max_response_size_hint
    }
}
