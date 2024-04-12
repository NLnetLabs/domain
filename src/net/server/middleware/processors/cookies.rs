//! DNS Cookies related message processing.
use core::ops::ControlFlow;

use std::net::IpAddr;
use std::vec::Vec;

use octseq::Octets;
use rand::RngCore;
use tracing::{debug, trace, warn};

use crate::base::iana::{OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::opt;
use crate::base::opt::Cookie;
use crate::base::wire::{Composer, ParseError};
use crate::base::{Serial, StreamTarget};
use crate::net::server::message::Request;
use crate::net::server::middleware::processor::MiddlewareProcessor;
use crate::net::server::util::add_edns_options;
use crate::net::server::util::{mk_builder_for_target, start_reply};

/// The five minute period referred to by
/// https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3.
const FIVE_MINUTES_AS_SECS: u32 = 5 * 60;

/// The one hour period referred to by
/// https://www.rfc-editor.org/rfc/rfc9018.html#section-4.3.
const ONE_HOUR_AS_SECS: u32 = 60 * 60;

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
    ip_deny_list: Vec<IpAddr>,
}

impl CookiesMiddlewareProcessor {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new(server_secret: [u8; 16]) -> Self {
        Self {
            server_secret,
            ip_deny_list: vec![],
        }
    }

    /// Define IP addresses required to supply DNS cookies if using UDP.
    #[must_use]
    pub fn with_denied_ips<T: Into<Vec<IpAddr>>>(
        mut self,
        ip_deny_list: T,
    ) -> Self {
        self.ip_deny_list = ip_deny_list.into();
        self
    }
}

impl CookiesMiddlewareProcessor {
    /// Get the DNS COOKIE, if any, for the given message.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc7873#section-5.2: Responding
    /// to a Request: "In all cases of multiple COOKIE options in a request,
    ///   only the first (the one closest to the DNS header) is considered.
    ///   All others are ignored."
    ///
    /// Returns:
    ///   - `None` if the request has no cookie,
    ///   - Some(Ok(cookie)) if the request has a cookie in the correct
    ///     format,
    ///   - Some(Err(err)) if the request has a cookie that we could not
    ///     parse.
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
        now <= expires_at && serial <= too_new_at
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

    /// Check the cookie contained in the request to make sure that it is
    /// complete, and if so return the cookie to the caller.
    #[must_use]
    fn ensure_cookie_is_complete<Target: Octets>(
        &self,
        request: &Request<Target>,
    ) -> Option<Cookie> {
        if let Some(Ok(cookie)) = Self::cookie(request) {
            let cookie = if cookie.server().is_some() {
                cookie
            } else {
                cookie.create_response(
                    Serial::now(),
                    request.client_addr().ip(),
                    &self.server_secret,
                )
            };

            Some(cookie)
        } else {
            None
        }
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
            ip_deny_list: Default::default(),
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
    fn preprocess(
        &self,
        request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        match Self::cookie(request) {
            None => {
                trace!("Request does not include DNS cookies");

                // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.1
                // No OPT RR or No COOKIE Option:
                //   "If there is no OPT record or no COOKIE option
                //   present in the request, then the server responds to
                //   the request as if the server doesn't implement the
                //   COOKIE option."

                // For clients on the IP deny list they MUST authenticate
                // themselves to the server, either with a cookie or by
                // re-connecting over TCP, so we REFUSE them and reply with
                // TC=1 to prompt them to reconnect via TCP.
                if request.transport_ctx().is_udp()
                    && self.ip_deny_list.contains(&request.client_addr().ip())
                {
                    debug!(
                        "Rejecting cookie-less non-TCP request due to matching IP deny list entry"
                    );
                    let builder = mk_builder_for_target();
                    let mut additional = builder.additional();
                    additional.header_mut().set_rcode(Rcode::REFUSED);
                    additional.header_mut().set_tc(true);
                    return ControlFlow::Break(additional);
                } else {
                    trace!("Permitting cookie-less request to flow due to use of TCP transport");
                }
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
                    } else if request.transport_ctx().is_udp() {
                        let additional = self.bad_cookie_response(request);
                        debug!(
                                "Rejecting non-TCP request due to invalid server cookie");
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
        request: &Request<RequestOctets>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
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

        if let Some(filled_cookie) = self.ensure_cookie_is_complete(request) {
            // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.5
            //   "The server SHALL process the request and include a COOKIE
            //   option in the response by (a) copying the complete COOKIE
            //   option from the request or (b) generating a new COOKIE option
            //   containing both the Client Cookie copied from the request and
            //   a valid Server Cookie it has generated."
            if let Err(err) = add_edns_options(response, |builder| {
                builder.push(&filled_cookie)
            }) {
                warn!("Cannot add RFC 7873 DNS Cookie option to response: {err}");
            }
        }
    }
}
