//! DNS Cookies related message processing.
use core::ops::ControlFlow;
use core::str::FromStr;

use std::net::IpAddr;
use std::string::{String, ToString};
use std::vec::Vec;

use inetnum::addr::Prefix;
use octseq::Octets;
use rand::RngCore;
use tracing::{debug, trace, warn};

use crate::base::iana::{OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt;
use crate::base::wire::{Composer, ParseError};
use crate::base::{Serial, StreamTarget};
use crate::net::server::message::Request;
use crate::net::server::middleware::processor::MiddlewareProcessor;
use crate::net::server::util::add_edns_options;
use crate::net::server::util::{mk_builder_for_target, start_reply};

//----------- Constants -------------------------------------------------------

/// The five minute period referred to by
/// https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3.
const FIVE_MINUTES_AS_SECS: u32 = 5 * 60;

/// The one hour period referred to by
/// https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3.
const ONE_HOUR_AS_SECS: u32 = 60 * 60;

//----------- NetBlock --------------------------------------------------------

/// An IPv4 or IPv6 network range.
///
// Note: Using a wrapper type avoids exposing the 3rd party IpNetwork type in
// our public API so that we can swap it out later for an alternative if
// needed without impacting the public API.
#[derive(Clone, Debug)]
pub struct NetBlock(Prefix);

impl NetBlock {
    /// Is the given IP address part of this network range?
    fn contains(&self, ip: IpAddr) -> bool {
        self.0.contains(ip)
    }
}

//--- FromStr

impl FromStr for NetBlock {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(NetBlock(
            Prefix::from_str(s).map_err(|err| ToString::to_string(&err))?,
        ))
    }
}

//----------- CookiesMiddlewareProcessor --------------------------------------

/// A DNS Cookies [`MiddlewareProcessor`].
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [7873] | TBD     |
/// | [9018] | TBD     |
///
/// [7873]: https://datatracker.ietf.org/doc/html/rfc7873
/// [9018]: https://datatracker.ietf.org/doc/html/rfc7873
/// [`MiddlewareProcessor`]: crate::net::server::middleware::processor::MiddlewareProcessor
#[derive(Debug)]
pub struct CookiesMiddlewareProcessor {
    /// A user supplied secret used in making the cookie value.
    server_secret: [u8; 16],

    /// Clients connecting from these IP addresses will be required to provide
    /// a cookie otherwise they will receive REFUSED with TC=1 prompting them
    /// to reconnect with TCP in order to "authenticate" themselves.
    deny_list: Vec<NetBlock>,
}

impl CookiesMiddlewareProcessor {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new(server_secret: [u8; 16]) -> Self {
        Self {
            server_secret,
            deny_list: vec![],
        }
    }

    /// Define IP addresses required to supply DNS cookies if using UDP.
    #[must_use]
    pub fn with_denied_addresses<T: Into<Vec<NetBlock>>>(
        mut self,
        deny_list: T,
    ) -> Self {
        self.deny_list = deny_list.into();
        self
    }
}

impl CookiesMiddlewareProcessor {
    /// Get the DNS cookie, if any, for the given message.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc7873#section-5.2
    /// 5.2 Responding to a Request
    ///   "In all cases of multiple COOKIE options in a request, only the
    ///    first (the one closest to the DNS header) is considered. All others
    ///    are ignored."
    ///
    /// Returns:
    ///   - None if the request has no cookie,
    ///   - Some(Ok(cookie)) if the first cookie in the request could be
    ///     parsed.
    ///   - Some(Err(err)) if the first cookie in the request could not be
    ///     parsed.
    #[must_use]
    fn cookie<RequestOctets: Octets>(
        request: &Request<RequestOctets>,
    ) -> Option<Result<opt::Cookie, ParseError>> {
        // Note: We don't use `opt::Opt::first()` because that will silently
        // ignore an unparseable COOKIE option but we need to detect and
        // handle that case. TODO: Should we warn in some way if the request
        // has more than one COOKIE option?
        request
            .message()
            .opt()
            .and_then(|opt| opt.opt().iter::<opt::Cookie>().next())
    }

    /// Check whether or not the given timestamp is okay.
    ///
    /// Returns true if the given timestamp is within the permitted difference
    /// to now as specified by [RFC 9018 section 4.3].
    ///
    /// [RFC 9018 section 4.3]: https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3
    #[must_use]
    fn timestamp_ok(serial: Serial) -> bool {
        // https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3
        // 4.3. The Timestamp Sub-Field:
        //   "The Timestamp value prevents Replay Attacks and MUST be checked
        //    by the server to be within a defined period of time. The DNS
        //    server SHOULD allow cookies within a 1-hour period in the past
        //    and a 5-minute period into the future to allow operation of
        //    low-volume clients and some limited time skew between the DNS
        //    servers in the anycast set."
        let now = Serial::now();
        let too_new_at = now.add(FIVE_MINUTES_AS_SECS);
        let expires_at = serial.add(ONE_HOUR_AS_SECS);
        if now > expires_at {
            trace!("Invalid server cookie: cookie has expired ({now} > {expires_at})");
            false
        } else if serial > too_new_at {
            trace!("Invalid server cookie: cookie is too new ({serial} > {too_new_at})");
            false
        } else {
            true
        }
    }

    /// Create a DNS response message for the given request, including cookie.
    fn response_with_cookie<RequestOctets, Target>(
        &self,
        request: &Request<RequestOctets>,
        rcode: OptRcode,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        let mut additional = start_reply(request).additional();

        if let Some(Ok(client_cookie)) = Self::cookie(request) {
            let response_cookie = client_cookie.create_response(
                Serial::now(),
                request.client_addr().ip(),
                &self.server_secret,
            );

            // Note: if rcode is non-extended this will also correctly handle
            // setting the rcode in the main message header.
            if let Err(err) = add_edns_options(&mut additional, |opt| {
                opt.cookie(response_cookie)?;
                opt.set_rcode(rcode);
                Ok(())
            }) {
                warn!("Failed to add cookie to response: {err}");
            }
        }

        additional
    }

    /// Create a DNS error response message indicating that the client
    /// supplied cookie is not okay.
    ///
    /// Panics
    ///
    /// This function will panic if the given request does not include a DNS
    /// client cookie or is unable to write to an internal buffer while
    /// constructing the response.
    #[must_use]
    fn bad_cookie_response<RequestOctets, Target>(
        &self,
        request: &Request<RequestOctets>,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.3
        //   "If the server responds [ed: by sending a BADCOOKIE error
        //    response], it SHALL generate its own COOKIE option containing
        //    both the Client Cookie copied from the request and a Server
        //    Cookie it has generated, and it will add this COOKIE option to
        //    the response's OPT record.

        self.response_with_cookie(request, OptRcode::BADCOOKIE)
    }

    /// Create a DNS response to a client cookie prefetch request.
    #[must_use]
    fn prefetch_cookie_response<RequestOctets, Target>(
        &self,
        request: &Request<RequestOctets>,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + Default,
    {
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.4
        // Querying for a Server Cookie:
        //   "For servers with DNS Cookies enabled, the
        //   QUERY opcode behavior is extended to support queries with an
        //   empty Question Section (a QDCOUNT of zero (0)), provided that an
        //   OPT record is present with a COOKIE option.  Such servers will
        //   send a reply that has an empty Answer Section and has a COOKIE
        //   option containing the Client Cookie and a valid Server Cookie.
        //
        //   If such a query provided just a Client Cookie and no Server
        //   Cookie, the response SHALL have the RCODE NOERROR."
        self.response_with_cookie(request, Rcode::NOERROR.into())
    }

    /// Is the given IP address required to authenticate itself?
    ///
    /// If the given IP address is on our deny list it is required to
    /// authenticate itself.
    fn must_authenticate(&self, ip: IpAddr) -> bool {
        self.deny_list.iter().any(|netblock| netblock.contains(ip))
    }
}

//--- Default

impl Default for CookiesMiddlewareProcessor {
    /// Creates an instance of this processor with default configuration.
    ///
    /// The processor will use a randomly generated server secret.
    fn default() -> Self {
        let mut server_secret = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut server_secret);

        Self {
            server_secret,
            deny_list: Default::default(),
        }
    }
}

//--- MiddlewareProcessor

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for CookiesMiddlewareProcessor
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    #[tracing::instrument(skip_all, fields(request_ip = %request.client_addr().ip()))]
    fn preprocess(
        &self,
        request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        match Self::cookie(request) {
            None => {
                trace!("Request does not contain a DNS cookie");

                // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.1
                // No OPT RR or No COOKIE Option:
                //   "If there is no OPT record or no COOKIE option
                //   present in the request, then the server responds to
                //   the request as if the server doesn't implement the
                //   COOKIE option."

                // https://datatracker.ietf.org/doc/html/rfc7873#section-1
                // 1. Introduction
                //   "The protection provided by DNS Cookies is similar to
                //    that provided by using TCP for DNS transactions.
                //    ...
                //    Where DNS Cookies are not available but TCP is, falling
                //    back to using TCP is reasonable."

                // While not required by RFC 7873, like Unbound the caller can
                // configure this middleware processor to require clients
                // contacting it from certain IP addresses or ranges to
                // authenticate themselves or be refused with TC=1 to signal
                // that they should resubmit their request via TCP.
                if request.transport_ctx().is_udp()
                    && self.must_authenticate(request.client_addr().ip())
                {
                    debug!("Rejecting cookie-less non-TCP request due to matching deny list entry");
                    let builder = mk_builder_for_target();
                    let mut additional = builder.additional();
                    additional.header_mut().set_rcode(Rcode::REFUSED);
                    additional.header_mut().set_tc(true);
                    return ControlFlow::Break(additional);
                }

                // Continue as if we we don't implement the COOKIE option.
            }

            Some(Err(err)) => {
                // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.2
                // Malformed COOKIE Option:
                //   "If the COOKIE option is too short to contain a
                //    Client Cookie, then FORMERR is generated.  If the
                //    COOKIE option is longer than that required to hold a
                //    COOKIE option with just a Client Cookie (8 bytes)
                //    but is shorter than the minimum COOKIE option with
                //    both a Client Cookie and a Server Cookie (16 bytes),
                //    then FORMERR is generated.  If the COOKIE option is
                //    longer than the maximum valid COOKIE option (40
                //    bytes), then FORMERR is generated."

                // TODO: Should we warn in some way about the exact reason
                // for rejecting the request?

                // NOTE: The RFC doesn't say that we should send our server
                // cookie back with the response, so we don't do that here
                // unlike in the other cases where we respond early.
                debug!("Received malformed DNS cookie: {err}");
                let mut builder = mk_builder_for_target();
                builder.header_mut().set_rcode(Rcode::FORMERR);
                return ControlFlow::Break(builder.additional());
            }

            Some(Ok(cookie)) => {
                // TODO: Does the "at least occasionally" condition below
                // referencing RFC 7873 section 5.2.3 mean that (a) we don't
                // have to do this for every response, and (b) we might want
                // to add configuration settings for controlling how often we
                // do this?

                let server_cookie_exists = cookie.server().is_some();
                let server_cookie_is_valid = cookie.check_server_hash(
                    request.client_addr().ip(),
                    &self.server_secret,
                    Self::timestamp_ok,
                );

                if !server_cookie_is_valid {
                    trace!("Request has an invalid DNS server cookie");

                    // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.3
                    // Only a Client Cookie:
                    //   "Based on server policy, including rate limiting, the
                    //   server chooses one of the following:
                    //
                    //    (1) Silently discard the request.
                    //
                    //    (2) Send a BADCOOKIE error response.
                    //
                    //    (3) Process the request and provide a normal
                    //        response.  The RCODE is NOERROR, unless some
                    //        non-cookie error occurs in processing the
                    //        request.
                    //
                    //    ... <snip> ...
                    //
                    //    Servers MUST, at least occasionally, respond to such
                    //    requests to inform the client of the correct Server
                    //    Cookie.
                    //
                    //    ... <snip> ...
                    //
                    //    If the request was received over TCP, the
                    //    server SHOULD take the authentication
                    //    provided by the use of TCP into account and
                    //    SHOULD choose (3).  In this case, if the
                    //    server is not willing to accept the security
                    //    provided by TCP as a substitute for the
                    //    security provided by DNS Cookies but instead
                    //    chooses (2), there is some danger of an
                    //    indefinite loop of retries (see Section
                    //    5.3)."

                    // TODO: Does "(1)" above in combination with the text in
                    // section 5.2.5 "SHALL process the request" mean that we
                    // are not allowed to reject the request prior to this
                    // point based on rate limiting or other server policy?

                    // TODO: Should we add a configuration option that allows
                    // for choosing between approaches (1), (2) and (3)? For
                    // now err on the side of security and go with approach
                    // (2): send a BADCOOKIE response.

                    // https://datatracker.ietf.org/doc/html/rfc7873#section-5.4
                    // Querying for a Server Cookie:
                    //   "For servers with DNS Cookies enabled, the QUERY
                    //   opcode behavior is extended to support queries with
                    //   an empty Question Section (a QDCOUNT of zero (0)),
                    //   provided that an OPT record is present with a COOKIE
                    //   option.  Such servers will send a reply that has an
                    //   empty Answer Section and has a COOKIE option
                    //   containing the Client Cookie and a valid Server
                    //   Cookie.

                    // TODO: Does the TCP check also apply to RFC 7873 section
                    // 5.4 "Querying for a Server Cookie" too?

                    if request.message().header_counts().qdcount() == 0 {
                        let additional = if !server_cookie_exists {
                            // "If such a query provided just a Client Cookie
                            // and no Server Cookie, the response SHALL have
                            // the RCODE NOERROR."
                            trace!(
                                "Replying to DNS cookie pre-fetch request with missing server cookie");
                            self.prefetch_cookie_response(request)
                        } else {
                            // "In this case, the response SHALL have the
                            // RCODE BADCOOKIE if the Server Cookie sent with
                            // the query was invalid"
                            debug!(
                                    "Rejecting pre-fetch request due to invalid server cookie");
                            self.bad_cookie_response(request)
                        };
                        return ControlFlow::Break(additional);
                    } else if request.transport_ctx().is_udp()
                        && self.must_authenticate(request.client_addr().ip())
                    {
                        let additional = self.bad_cookie_response(request);
                        debug!("Rejecting non-TCP request with invalid server cookie due to matching deny list entry");
                        return ControlFlow::Break(additional);
                    }
                } else if request.message().header_counts().qdcount() == 0 {
                    // https://datatracker.ietf.org/doc/html/rfc7873#section-5.4
                    // Querying for a Server Cookie:
                    //   "This mechanism can also be used to
                    //   confirm/re-establish an existing Server Cookie by
                    //   sending a cached Server Cookie with the Client
                    //   Cookie.  In this case, the response SHALL have the
                    //   RCODE BADCOOKIE if the Server Cookie sent with the
                    //   query was invalid and the RCODE NOERROR if it was
                    //   valid."

                    // TODO: Does the TCP check also apply to RFC 7873 section
                    // 5.4 "Querying for a Server Cookie" too?
                    trace!(
                            "Replying to DNS cookie pre-fetch request with valid server cookie");
                    let additional = self.prefetch_cookie_response(request);
                    return ControlFlow::Break(additional);
                } else {
                    trace!("Request has a valid DNS cookie");
                }
            }
        }

        trace!("Permitting request to flow");

        ControlFlow::Continue(())
    }

    fn postprocess(
        &self,
        _request: &Request<RequestOctets>,
        _response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.1
        // No OPT RR or No COOKIE Option:
        //   If the request lacked a client cookie we don't need to do
        //   anything.
        //
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.2
        // Malformed COOKIE Option:
        //   If the request COOKIE option was malformed we would have already
        //   rejected it during pre-processing so again nothing to do here.
        //
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.3
        // Only a Client Cookie:
        //   If the request had a client cookie but no server cookie and
        //   we didn't already reject the request during pre-processing.
        //
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.4
        // A Client Cookie and an Invalid Server Cookie:
        //   Per RFC 7873 this is handled the same way as the "Only a Client
        //   Cookie" case.
        //
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.5
        // A Client Cookie and a Valid Server Cookie
        //   Any server cookie will already have been validated during
        //   pre-processing, we don't need to check it again here.
    }
}

#[cfg(test)]
mod tests {
    use core::ops::ControlFlow;

    use bytes::Bytes;
    use std::vec::Vec;
    use tokio::time::Instant;

    use crate::base::opt::cookie::ClientCookie;
    use crate::base::opt::Cookie;
    use crate::base::{Message, MessageBuilder, Name, Rtype};
    use crate::net::server::message::{Request, UdpTransportContext};
    use crate::net::server::middleware::processor::MiddlewareProcessor;

    use super::CookiesMiddlewareProcessor;

    #[test]
    fn dont_add_cookie_twice() {
        // Build a dummy DNS query containing a client cookie.
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((Name::<Bytes>::root(), Rtype::A)).unwrap();
        let mut additional = query.additional();
        let client_cookie = ClientCookie::new_random();
        let cookie = Cookie::new(client_cookie, None);
        additional.opt(|builder| builder.cookie(cookie)).unwrap();
        let message = additional.into_message();

        // Package the query into a context aware request to make it look
        // as if it came from a UDP server.
        let ctx = UdpTransportContext::default();
        let client_addr = "127.0.0.18:12345".parse().unwrap();
        let request =
            Request::new(client_addr, Instant::now(), message, ctx.into());

        // Setup the cookie middleware processor such that it requires
        // the mock client to provide a valid cookie.
        let server_secret: [u8; 16] = [1u8; 16];
        let processor = CookiesMiddlewareProcessor::new(server_secret)
            .with_denied_addresses(["127.0.0.0/24".parse().unwrap()]);
        let processor: &dyn MiddlewareProcessor<Vec<u8>, Vec<u8>> =
            &processor;

        // And pass the query through the middleware processor
        let ControlFlow::Break(mut response) = processor.preprocess(&request)
        else {
            unreachable!()
        };
        processor.postprocess(&request, &mut response);

        // Expect the response to contain a single cookie option containing
        // both a client cookie and a server cookie.
        let response = response.finish();
        let response_bytes = response.as_dgram_slice().to_vec();
        let response = Message::from_octets(response_bytes).unwrap();

        let Some(opt_record) = response.opt() else {
            panic!("Missing OPT record")
        };

        let mut cookie_iter = opt_record.opt().iter::<Cookie>();
        let Some(Ok(cookie)) = cookie_iter.next() else {
            panic!("Invalid or missing cookie")
        };

        assert!(
            cookie.check_server_hash(
                client_addr.ip(),
                &server_secret,
                |_| true
            ),
            "The cookie is incomplete or invalid"
        );

        assert!(
            cookie_iter.next().is_none(),
            "There should only be one COOKIE option"
        );
    }
}
