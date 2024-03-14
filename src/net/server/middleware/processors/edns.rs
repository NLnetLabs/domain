//! RFC 6891 and related EDNS message processing.
use octseq::Octets;
use tracing::{debug, trace, warn};

use crate::net::server::util::add_edns_options;
use crate::{
    base::{
        iana::OptRcode,
        message_builder::AdditionalBuilder,
        opt::{keepalive::IdleTimeout, Opt, OptRecord, TcpKeepalive},
        wire::Composer,
        Message, StreamTarget,
    },
    net::server::{
        message::{ContextAwareMessage, TransportSpecificContext},
        middleware::processor::MiddlewareProcessor,
        util::start_reply,
    },
};
use core::ops::ControlFlow;

/// EDNS version 0.
///
/// Version 0 is the highest EDNS version number recoded in the [IANA
/// registry] at the time of writing.
///
/// [IANA registry]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
pub const EDNS_VERSION_ZERO: u8 = 0;

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
#[derive(Debug)]
pub struct EdnsMiddlewareProcessor {
    max_version: u8,
}

impl EdnsMiddlewareProcessor {
    /// Constructs an instance of this processor.
    #[must_use]
    pub fn new(max_version: u8) -> Self {
        Self { max_version }
    }
}

impl EdnsMiddlewareProcessor {
    fn err_response<RequestOctets, Target>(
        request: &ContextAwareMessage<Message<RequestOctets>>,
        rcode: OptRcode,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        let builder = start_reply(request);

        // Note: if rcode is non-extended this will also correctly handle
        // setting the rcode in the main message header.
        let mut additional = builder.additional();
        additional
            .opt(|opt| {
                opt.set_rcode(rcode);
                Ok(())
            })
            .unwrap();

        additional
    }
}

//--- Default

impl Default for EdnsMiddlewareProcessor {
    /// Constructs an instance of this processor with default configuration.
    ///
    /// The processor will only accept EDNS version 0 OPT records from
    /// clients. EDNS version 0 is the highest EDNS version number recoded in
    /// the [IANA registry] at the time of writing.
    ///
    /// [IANA registry]:
    ///     https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-14
    fn default() -> Self {
        Self {
            max_version: EDNS_VERSION_ZERO,
        }
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
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        // https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.1
        // 6.1.1: Basic Elements
        // ...
        // "If a query message with more than one OPT RR is received, a
        //  FORMERR (RCODE=1) MUST be returned"
        if let Ok(additional) = request.message().additional() {
            let mut iter = additional.limit_to::<Opt<_>>();
            if let Some(opt) = iter.next() {
                if iter.next().is_some() {
                    // More than one OPT RR received.
                    debug!("RFC 6891 6.1.1 violation: request contains more than one OPT RR.");
                    return ControlFlow::Break(Self::err_response(
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
                    if opt_rec.version() > self.max_version {
                        debug!("RFC 6891 6.1.3 violation: request EDNS version {} > {}", opt_rec.version(), self.max_version);
                        return ControlFlow::Break(Self::err_response(
                            request,
                            OptRcode::BadVers,
                        ));
                    }

                    match request.transport() {
                        TransportSpecificContext::Udp(mut ctx) => {
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
                                    Self::err_response(
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

                            if requestors_udp_payload_size < 512 {
                                debug!("RFC 6891 6.2.3 violation: OPT RR class (requestor's UDP payload size) < 512");
                            }

                            if ctx.max_response_size_hint.is_none() {
                                let size = u16::max(
                                    512,
                                    requestors_udp_payload_size,
                                );
                                trace!("Setting max response size hint from EDNS(0) requestor's UDP payload size ({})", requestors_udp_payload_size);
                                ctx.max_response_size_hint = Some(size);
                            }
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
                                        Self::err_response(
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
        request: &ContextAwareMessage<Message<RequestOctets>>,
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
