//! Core DNS RFC standards based message processing for MUST requirements.
use core::ops::ControlFlow;

use octseq::Octets;
use tracing::{debug, error, trace, warn};

use crate::base::iana::{Opcode, Rcode};
use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::{Composer, ParseError};
use crate::base::StreamTarget;
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::processor::MiddlewareProcessor;
use crate::net::server::util::{mk_builder_for_target, start_reply};
use std::fmt::Display;

/// The minimum legal UDP response size in bytes.
///
/// As defined by [RFC 1035 section 4.2.1].
///
/// [RFC 1035 section 4.2.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
pub const MINIMUM_RESPONSE_BYTE_LEN: u16 = 512;

/// A [`MiddlewareProcessor`] for enforcing core RFC MUST requirements on
/// processed messages.
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [1035] | TBD     |
/// | [2181] | TBD     |
///
/// [`MiddlewareProcessor`]:
///     crate::net::server::middleware::processor::MiddlewareProcessor
/// [1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [2181]: https://datatracker.ietf.org/doc/html/rfc2181
#[derive(Debug)]
pub struct MandatoryMiddlewareProcessor {
    /// In strict mode the processor does more checks on requests and
    /// responses.
    strict: bool,
}

impl MandatoryMiddlewareProcessor {
    /// Creates a new processor instance.
    ///
    /// The processor will operate in strict mode.
    #[must_use]
    pub fn new() -> Self {
        Self { strict: true }
    }

    /// Creates a new processor instance.
    ///
    /// The processor will operate in relaxed mode.
    #[must_use]
    pub fn relaxed() -> Self {
        Self { strict: false }
    }

    /// Create a DNS error response to the given request with the given RCODE.
    fn error_response<RequestOctets, Target>(
        &self,
        request: &Request<RequestOctets>,
        rcode: Rcode,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        let mut response = start_reply(request);
        response.header_mut().set_rcode(rcode);
        let mut additional = response.additional();
        self.postprocess(request, &mut additional);
        additional
    }
}

impl MandatoryMiddlewareProcessor {
    /// Truncate the given response message if it is too large.
    ///
    /// Honours either a transport supplied hint, if present in the given
    /// [`UdpSpecificTransportContext`], as to how large the response is
    /// allowed to be, or if missing will instead honour the clients indicated
    /// UDP response payload size (if an EDNS OPT is present in the request).
    ///
    /// Truncation discards the authority and additional sections, except for
    /// any OPT record present which will be preserved, then truncates to the
    /// specified byte length.
    fn truncate<RequestOctets, Target>(
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) -> Result<(), TruncateError>
    where
        Target: Composer + Default,
        RequestOctets: AsRef<[u8]>,
    {
        if let TransportSpecificContext::Udp(ctx) = request.transport_ctx() {
            // https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.1
            //   "Messages carried by UDP are restricted to 512 bytes (not
            //    counting the IP or UDP headers).  Longer messages are
            //    truncated and the TC bit is set in the header."
            let max_response_size = ctx
                .max_response_size_hint()
                .unwrap_or(MINIMUM_RESPONSE_BYTE_LEN);
            let max_response_size = max_response_size as usize;
            let response_len = response.as_slice().len();

            if response_len > max_response_size {
                // Truncate per RFC 1035 section 6.2 and RFC 2181 sections 5.1
                // and 9:
                //
                // https://datatracker.ietf.org/doc/html/rfc1035#section-6.2
                //   "When a response is so long that truncation is required,
                //    the truncation should start at the end of the response
                //    and work forward in the datagram.  Thus if there is any
                //    data for the authority section, the answer section is
                //    guaranteed to be unique."
                //
                // https://datatracker.ietf.org/doc/html/rfc2181#section-5.1
                //   "A query for a specific (or non-specific) label, class,
                //    and type, will always return all records in the
                //    associated RRSet - whether that be one or more RRs.  The
                //    response must be marked as "truncated" if the entire
                //    RRSet will not fit in the response."
                //
                // https://datatracker.ietf.org/doc/html/rfc2181#section-9
                //   "Where TC is set, the partial RRSet that would not
                //    completely fit may be left in the response.  When a DNS
                //    client receives a reply with TC set, it should ignore
                //    that response, and query again, using a mechanism, such
                //    as a TCP connection, that will permit larger replies."
                //
                // https://datatracker.ietf.org/doc/html/rfc6891#section-7
                //   "The minimal response MUST be the DNS header, question
                //    section, and an OPT record.  This MUST also occur when
                //    a truncated response (using the DNS header's TC bit) is
                //    returned."

                // Tell the client that we are truncating the response.
                response.header_mut().set_tc(true);

                // Remember the original length.
                let old_len = response.as_slice().len();

                // Copy the header, question and opt record from the
                // additional section, but leave the answer and authority
                // sections empty.
                let source = response.as_message();
                let mut target = mk_builder_for_target();

                *target.header_mut() = source.header();

                let mut target = target.question();
                for rr in source.question() {
                    target.push(rr?)?;
                }

                let mut target = target.additional();
                if let Some(opt) = source.opt() {
                    if let Err(err) = target.push(opt.as_record()) {
                        warn!("Error while truncating response: unable to push OPT record: {err}");
                        // As the client had an OPT record and RFC 6891 says
                        // when truncating that there MUST be an OPT record,
                        // attempt to push just the empty OPT record (as the
                        // OPT record header still has value, e.g. the
                        // requestors payload size field and extended rcode).
                        if let Err(err) = target.opt(|builder| {
                            builder.set_version(opt.version());
                            builder.set_rcode(opt.rcode(response.header()));
                            builder
                                .set_udp_payload_size(opt.udp_payload_size());
                            Ok(())
                        }) {
                            error!("Error while truncating response: unable to add minimal OPT record: {err}");
                        }
                    }
                }

                let new_len = target.as_slice().len();
                trace!("Truncating response from {old_len} bytes to {new_len} bytes");

                *response = target;
            }
        }

        Ok(())
    }
}

//--- MiddlewareProcessor

// TODO: If we extend this later to do a lot more than setting a couple of
// header flags, and if we think that there may be a need for alternate
// truncation strategies, then it might make sense to factor out truncation to
// make it "pluggable" by the user.
impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for MandatoryMiddlewareProcessor
where
    RequestOctets: AsRef<[u8]> + Octets,
    Target: Composer + Default,
{
    fn preprocess(
        &self,
        request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        // https://www.rfc-editor.org/rfc/rfc3425.html
        // 3 - Effect on RFC 1035
        //   ..
        //   "Therefore IQUERY is now obsolete, and name servers SHOULD return
        //    a "Not Implemented" error when an IQUERY request is received."
        if self.strict
            && request.message().header().opcode() == Opcode::IQUERY
        {
            debug!(
                "RFC 3425 3 violation: request opcode IQUERY is obsolete."
            );
            return ControlFlow::Break(
                self.error_response(request, Rcode::NOTIMP),
            );
        }

        ControlFlow::Continue(())
    }

    fn postprocess(
        &self,
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        if let Err(err) = Self::truncate(request, response) {
            error!("Error while truncating response: {err}");
            *response = self.error_response(request, Rcode::SERVFAIL);
            return;
        }

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

        // https://www.rfc-editor.org/rfc/rfc1035.html
        // https://www.rfc-editor.org/rfc/rfc3425.html
        //
        // All responses shown in RFC 1035 (except those for inverse queries,
        // opcode 1, which was obsoleted by RFC 4325) contain the question
        // from the request. So we would expect the number of questions in the
        // response to match the number of questions in the request.
        if self.strict
            && !request.message().header_counts().qdcount()
                == response.counts().qdcount()
        {
            warn!("RFC 1035 violation: response question count != request question count");
        }
    }
}

//--- Default

impl Default for MandatoryMiddlewareProcessor {
    fn default() -> Self {
        Self::new()
    }
}

//------------ TruncateError -------------------------------------------------

/// An error occured during oversize response truncation.
enum TruncateError {
    /// There was a problem parsing the request, specifically the question
    /// section.
    InvalidQuestion(ParseError),

    /// There was a problem pushing to the response.
    PushFailure(PushError),
}

impl Display for TruncateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TruncateError::InvalidQuestion(err) => {
                write!(f, "Unable to parse question: {err}")
            }
            TruncateError::PushFailure(err) => {
                write!(f, "Unable to push into response: {err}")
            }
        }
    }
}

impl From<ParseError> for TruncateError {
    fn from(err: ParseError) -> Self {
        Self::InvalidQuestion(err)
    }
}

impl From<PushError> for TruncateError {
    fn from(err: PushError) -> Self {
        Self::PushFailure(err)
    }
}

#[cfg(test)]
mod tests {
    use core::ops::ControlFlow;

    use std::vec::Vec;

    use bytes::Bytes;
    use tokio::time::Instant;

    use crate::base::{Dname, MessageBuilder, Rtype};
    use crate::net::server::message::{
        Request, TransportSpecificContext, UdpTransportContext,
    };

    use super::MandatoryMiddlewareProcessor;
    use crate::base::iana::OptionCode;
    use crate::net::server::middleware::processor::MiddlewareProcessor;
    use crate::net::server::middleware::processors::mandatory::MINIMUM_RESPONSE_BYTE_LEN;
    use octseq::OctetsBuilder;

    //------------ Constants -------------------------------------------------

    const MIN_ALLOWED: u16 = MINIMUM_RESPONSE_BYTE_LEN;
    const TOO_SMALL: u16 = 511;
    const JUST_RIGHT: u16 = MIN_ALLOWED;
    const HUGE: u16 = u16::MAX;

    //------------ Tests -----------------------------------------------------

    #[test]
    fn clamp_max_response_size_correctly() {
        assert!(process(None) <= Some(MIN_ALLOWED as usize));
        assert!(process(Some(TOO_SMALL)) <= Some(MIN_ALLOWED as usize));
        assert!(process(Some(TOO_SMALL)) <= Some(MIN_ALLOWED as usize));
        assert!(process(Some(TOO_SMALL)) <= Some(MIN_ALLOWED as usize));
        assert!(process(Some(JUST_RIGHT)) <= Some(JUST_RIGHT as usize));
        assert!(process(Some(JUST_RIGHT)) <= Some(JUST_RIGHT as usize));
        assert!(process(Some(JUST_RIGHT)) <= Some(JUST_RIGHT as usize));
        assert!(process(Some(HUGE)) <= Some(HUGE as usize));
        assert!(process(Some(HUGE)) <= Some(HUGE as usize));
        assert!(process(Some(HUGE)) <= Some(HUGE as usize));
    }

    //------------ Helper functions ------------------------------------------

    // Returns Some(n) if truncation occurred where n is the size after
    // truncation.
    fn process(max_response_size_hint: Option<u16>) -> Option<usize> {
        // Build a dummy DNS query.
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((Dname::<Bytes>::root(), Rtype::A)).unwrap();
        let extra_bytes = vec![0; (MIN_ALLOWED as usize) * 2];
        let mut additional = query.additional();
        additional
            .opt(|builder| {
                builder.push_raw_option(
                    OptionCode::PADDING,
                    extra_bytes.len() as u16,
                    |target| {
                        target.append_slice(&extra_bytes).unwrap();
                        Ok(())
                    },
                )
            })
            .unwrap();
        let old_size = additional.as_slice().len();
        let message = additional.into_message();

        // TODO: Artificially expand the message to be as big as possible
        // so that it will get truncated.

        // Package the query into a context aware request to make it look
        // as if it came from a UDP server.
        let ctx = UdpTransportContext::new(max_response_size_hint);
        let request = Request::new(
            "127.0.0.1:12345".parse().unwrap(),
            Instant::now(),
            message,
            TransportSpecificContext::Udp(ctx),
        );

        // And pass the query through the middleware processor
        let processor = MandatoryMiddlewareProcessor::default();
        let processor: &dyn MiddlewareProcessor<Vec<u8>, Vec<u8>> =
            &processor;
        let mut response = MessageBuilder::new_stream_vec().additional();
        if let ControlFlow::Continue(()) = processor.preprocess(&request) {
            processor.postprocess(&request, &mut response);
        }

        // Get the response length
        let new_size = response.as_slice().len();

        if new_size < old_size {
            Some(new_size)
        } else {
            None
        }
    }
}
