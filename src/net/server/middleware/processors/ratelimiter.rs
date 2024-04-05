//! Rate limiting middleware
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use std::net::IpAddr;

use governor::{DefaultKeyedRateLimiter, Quota};
use octseq::Octets;
use tracing::{info, warn};

use crate::base::iana::OptRcode;
use crate::base::message_builder::AdditionalBuilder;

use crate::base::wire::Composer;
use crate::base::StreamTarget;
use crate::net::server::message::Request;
use crate::net::server::middleware::processor::MiddlewareProcessor;

use crate::net::server::util::{add_edns_options, start_reply};

//------------ Constants -----------------------------------------------------

/// The default maximum number of requests/second/client IP address.
const DEFAULT_QPS_LIMIT: u32 = 200;

//------------ RateLimitingMiddlewareProcessor -------------------------------

/// A [`MiddlewareProcessor`] for limiting the rate of requests.
#[derive(Debug)]
pub struct RateLimitingMiddlewareProcessor {
    /// A per client IP address rate limiter.
    limiter: DefaultKeyedRateLimiter<IpAddr>,
}

impl Default for RateLimitingMiddlewareProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitingMiddlewareProcessor {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(DEFAULT_QPS_LIMIT)
    }

    /// Creates an instance of this processor with the given configuration.
    #[must_use]
    pub fn with_config(qps_limit: u32) -> Self {
        let limiter = DefaultKeyedRateLimiter::keyed(Quota::per_second(
            NonZeroU32::new(qps_limit).unwrap(),
        ));
        Self { limiter }
    }
}

impl RateLimitingMiddlewareProcessor {
    /// Create a DNS error response to the given request with the given RCODE.
    fn error_response<RequestOctets, Target>(
        &self,
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
        if let Err(err) = add_edns_options(&mut additional, |opt| {
            opt.set_rcode(rcode);
            Ok(())
        }) {
            warn!(
                "Failed to set (extended) error '{rcode}' in response: {err}"
            );
        }

        self.postprocess(request, &mut additional);
        additional
    }
}

//--- MiddlewareProcessor

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for RateLimitingMiddlewareProcessor
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn preprocess(
        &self,
        request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        let client_ip = &request.client_addr().ip();
        match self.limiter.check_key(client_ip) {
            Ok(_) => ControlFlow::Continue(()),
            Err(_) => {
                info!("Refusing to serve {client_ip}: rate limit exceeded");
                let res = self.error_response(request, OptRcode::REFUSED);
                ControlFlow::Break(res)
            }
        }
    }

    fn postprocess(
        &self,
        _request: &Request<RequestOctets>,
        _response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use core::ops::ControlFlow;

    use std::vec::Vec;

    use bytes::Bytes;
    use tokio::time::Instant;

    use crate::base::iana::Rcode;
    use crate::base::{Dname, MessageBuilder, Rtype};
    use crate::net::server::message::{
        Request, TransportSpecificContext, UdpTransportContext,
    };

    use super::RateLimitingMiddlewareProcessor;
    use crate::net::server::middleware::processor::MiddlewareProcessor;

    //------------ Tests -----------------------------------------------------

    #[test]
    fn _rate_limit_requests() {}

    //------------ Helper functions ------------------------------------------

    fn _process() -> Rcode {
        // Build a dummy DNS query.
        let query = MessageBuilder::new_vec();

        // With a dummy question.
        let mut query = query.question();
        query.push((Dname::<Bytes>::root(), Rtype::A)).unwrap();
        let message = query.into_message();

        // Package the query into a context aware request to make it look
        // as if it came from a UDP server.
        let ctx = UdpTransportContext::new(None);
        let request = Request::new(
            "127.0.0.1:12345".parse().unwrap(),
            Instant::now(),
            message,
            TransportSpecificContext::Udp(ctx),
        );

        // And pass the query through the middleware processor
        let processor = RateLimitingMiddlewareProcessor::new();
        let processor: &dyn MiddlewareProcessor<Vec<u8>, Vec<u8>> =
            &processor;
        let mut response = MessageBuilder::new_stream_vec().additional();
        if let ControlFlow::Continue(()) = processor.preprocess(&request) {
            processor.postprocess(&request, &mut response);
        }

        // Get the result code
        response.header().rcode()
    }
}
