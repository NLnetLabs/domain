//! Rate limiting middleware
use core::num::NonZeroU32;
use core::ops::ControlFlow;

use std::net::IpAddr;

use governor::{DefaultDirectRateLimiter, DefaultKeyedRateLimiter, Quota};
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

/// The default maximum number of requests/second.
const DEFAULT_QPS_LIMIT: u32 = 2000;

//------------ RateLimiter ---------------------------------------------------

#[derive(Debug)]
enum RateLimiter {
    PerRequest(DefaultDirectRateLimiter),
    PerRequestPerIp(DefaultKeyedRateLimiter<IpAddr>),
}

impl RateLimiter {
    pub fn per_request(qps_limit: u32) -> Self {
        let limiter = DefaultDirectRateLimiter::direct(Quota::per_second(
            NonZeroU32::new(qps_limit).unwrap(),
        ));
        Self::PerRequest(limiter)
    }

    pub fn per_request_per_ip(qps_limit: u32) -> Self {
        let limiter = DefaultKeyedRateLimiter::keyed(Quota::per_second(
            NonZeroU32::new(qps_limit).unwrap(),
        ));
        Self::PerRequestPerIp(limiter)
    }
}

//------------ Config --------------------------------------------------------

/// Configuration for rate limiting middleware.
#[derive(Debug)]
pub struct Config {
    /// Whether to limit per client IP address or across all requests
    /// irrespective of client IP address.
    per_ip: bool,

    /// The maximum number requests per second to limit to.
    qps_limit: u32,
}

impl Config {
    /// Sets whether to limit per per client IP address or across all requests
    /// irrespective of client IP address.
    pub fn set_per_ip(&mut self, per_ip: bool) {
        self.per_ip = per_ip;
    }

    /// Is this a per IP rate limiter?
    pub fn per_ip(&self) -> bool {
        self.per_ip
    }

    /// Sets the maximum number of requests per second to limit to.
    /// 
    /// In the context of the rate limiter configuration, i.e. maximum
    /// requests per second per client IP address, or maximum requests per
    /// second irrespective of client IP address.
    pub fn set_qps_limit(&mut self, qps_limit: u32) {
        self.qps_limit = qps_limit;
    }

    /// Gets the maximum number of requests per second to limit to.
    pub fn qps_limit(&self) -> u32 {
        self.qps_limit
    }
}

//--- Default

impl Default for Config {
    fn default() -> Self {
        Self {
            per_ip: false,
            qps_limit: DEFAULT_QPS_LIMIT,
        }
    }
}

//------------ RateLimitingMiddlewareProcessor -------------------------------

/// A [`MiddlewareProcessor`] for limiting the rate of requests.
#[derive(Debug)]
pub struct RateLimitingMiddlewareProcessor {
    /// A per client IP address rate limiter.
    limiter: RateLimiter,
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
        Self::with_config(Config::default())
    }

    /// Creates an instance of this processor with the given configuration.
    #[must_use]
    pub fn with_config(config: Config) -> Self {
        let limiter = match config.per_ip {
            true => RateLimiter::per_request_per_ip(config.qps_limit),
            false => RateLimiter::per_request(config.qps_limit),
        };
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
        let res = match &self.limiter {
            RateLimiter::PerRequest(limiter) => {
                limiter.check().inspect_err(|_| {
                    info!("Refusing to serve: rate limit exceeded")
                })
            }
            RateLimiter::PerRequestPerIp(limiter) => {
                let client_ip = &request.client_addr().ip();
                limiter.check_key(client_ip).inspect_err(|_| {
                    info!(
                        "Refusing to serve {client_ip}: rate limit exceeded"
                    )
                })
            }
        };

        match res {
            Ok(_) => ControlFlow::Continue(()),
            Err(_) => {
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
