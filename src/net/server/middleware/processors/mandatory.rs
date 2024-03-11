//! Core DNS RFC standards based message processing.
use octseq::Octets;
use tracing::{debug, enabled, trace, Level};

use crate::{
    base::{
        iana::Rcode, message_builder::AdditionalBuilder, opt::Opt,
        wire::Composer, Message, StreamTarget,
    },
    net::server::{
        message::ContextAwareMessage,
        middleware::processor::MiddlewareProcessor,
        util::mk_builder_for_target,
    },
};
use core::ops::ControlFlow;

/// A [`MiddlewareProcessor`] for enforcing RFC standards on processed messages.
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [1035] | TBD     |
/// | [6891] | TBD     |
///
/// [1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [6891]: https://datatracker.ietf.org/doc/html/rfc6891
/// [`MiddlewareProcessor`]: crate::net::server::middleware::processor::MiddlewareProcessor
#[derive(Default)]
pub struct MandatoryMiddlewareProcessor;

impl MandatoryMiddlewareProcessor {
    /// Constructs an instance of this processor.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for MandatoryMiddlewareProcessor
where
    RequestOctets: AsRef<[u8]> + Octets,
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
        let mut new_max_response_size_hint = None;
        if let Ok(additional) = request.message().additional() {
            let mut iter = additional.limit_to::<Opt<_>>();
            if let Some(opt) = iter.next() {
                if iter.next().is_some() {
                    // More than one OPT RR received.
                    if enabled!(Level::DEBUG) {
                        debug!("RFC 6891 6.1.1 violation: request contains more than one OPT RR.");
                    }
                    let mut builder = mk_builder_for_target();
                    builder.header_mut().set_rcode(Rcode::FormErr);
                    return ControlFlow::Break(builder.additional());
                } else if request.received_over_udp() {
                    if let Ok(opt) = opt {
                        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.3
                        // 6.2.3. Requestor's Payload Size
                        //
                        //   "The requestor's UDP payload size (encoded in the RR CLASS field) is
                        //    the number of octets of the largest UDP payload that can be
                        //    reassembled and delivered in the requestor's network stack.  Note
                        //    that path MTU, with or without fragmentation, could be smaller than
                        //    this.
                        //
                        //    Values lower than 512 MUST be treated as equal to 512."
                        let requestors_udp_payload_size: u16 =
                            opt.class().into();
                        if requestors_udp_payload_size < 512
                            && enabled!(Level::DEBUG)
                        {
                            debug!("RFC 6891 6.2.3 violation: OPT RR class (requestor's UDP payload size) < 512");
                        } else if request.max_response_size_hint().is_none() {
                            trace!("Setting max response size hint from EDNS(0) requestor's UDP payload size ({})", requestors_udp_payload_size);
                            new_max_response_size_hint =
                                Some(requestors_udp_payload_size);
                        }
                    }
                }
            }

            if let Some(max_response_size_hint) = new_max_response_size_hint {
                request.set_max_response_size_hint(max_response_size_hint);
            }
        }

        ControlFlow::Continue(())
    }

    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
        // 4.1.1: Header section format
        //
        // ID      A 16 bit identifier assigned by the program that
        //         generates any kind of query.  This identifier is copied
        //         the corresponding reply and can be used by the requester
        //         to match up replies to outstanding queries.
        response
            .header_mut()
            .set_id(request.message().header().id());

        // QR      A one bit field that specifies whether this message is a
        //         query (0), or a response (1).
        response.header_mut().set_qr(true);

        // RD      Recursion Desired - this bit may be set in a query and
        //         is copied into the response.  If RD is set, it directs
        //         the name server to pursue the query recursively.
        //         Recursive query support is optional.
        response
            .header_mut()
            .set_rd(request.message().header().rd());

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
        //
        // if request.opt().is_none() && response.opt().is_some() {
        // }

        // TODO: For non-error responses is it mandatory that the question
        // from the request be copied to the response? Unbound and domain
        // think so. If this has not been done, how should we react here?
    }
}
