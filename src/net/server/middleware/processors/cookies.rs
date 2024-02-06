use octseq::{Octets, OctetsBuilder};

use crate::{
    base::{
        iana::{OptRcode, Rcode},
        message_builder::AdditionalBuilder,
        opt::{self, Cookie},
        wire::{Composer, ParseError},
        Message, MessageBuilder, Serial, StreamTarget,
    },
    net::server::{
        middleware::processor::MiddlewareProcessor,
        traits::message::ContextAwareMessage,
    },
};
use core::ops::ControlFlow;

pub struct CookiesMiddlewareProcesor {
    server_secret: [u8; 16],
}

impl CookiesMiddlewareProcesor {
    #[must_use]
    pub fn new(server_secret: [u8; 16]) -> Self {
        Self { server_secret }
    }
}

impl CookiesMiddlewareProcesor {
    /// Get the DNS COOKIE, if any, for the given message.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc7873#section-5.2:
    /// Responding to a Request:
    ///   "In all cases of multiple COOKIE options in a request, only the
    ///   first (the one closest to the DNS header) is considered. All others
    ///   are ignored."
    #[must_use]
    fn cookie<RequestOctets: AsRef<[u8]> + Octets>(
        request: &ContextAwareMessage<Message<RequestOctets>>,
    ) -> Option<Result<opt::Cookie, ParseError>> {
        // Note: We don't use `opt::Opt::first()` because that will silently
        // ignore an unparseable COOKIE option but we need to detect and
        // handle that case. TODO: Should we warn in some way if the request
        // has more than one COOKIE option?
        request
            .opt()
            .and_then(|opt| opt.opt().iter::<opt::Cookie>().nth(0))
    }

    #[must_use]
    fn timestamp_ok(_serial: Serial) -> bool {
        // TODO
        true
    }

    /// Panics
    ///
    /// This function will panic if the given request does not include a DNS
    /// client cookie or is unable to write to an internal buffer while
    /// constructing the response.
    #[must_use]
    fn bad_cookie_response<RequestOctets, Target>(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        builder: MessageBuilder<StreamTarget<Target>>,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: Octets,
        Target: Composer + OctetsBuilder,
    {
        // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.3
        //   "If the server responds [ed: by sending a BADCOOKIE error
        //    response], it SHALL generate its own COOKIE option containing
        //    both the Client Cookie copied from the request and a Server
        //    Cookie it has generated, and it will add this COOKIE option to
        //    the response's OPT record.

        // TODO: Do we need a configuration option to choose to generate RFC
        // 7873 cookies instead of RFC 9018 interoperable cookies? For now err
        // on the side of robustness and go with RFC 9018 interoperable
        // cookies.
        let cookie = Self::cookie(request).unwrap().unwrap().create_response(
            Serial::now(),
            request.client_addr().ip(),
            &self.server_secret,
        );

        let mut additional = builder.additional();
        additional
            .opt(|opt| {
                opt.cookie(cookie)?;
                opt.set_rcode(OptRcode::BadCookie);
                Ok(())
            })
            .unwrap();

        additional
    }

    #[must_use]
    fn prefetch_cookie_response<RequestOctets, Target>(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        mut builder: MessageBuilder<StreamTarget<Target>>,
    ) -> AdditionalBuilder<StreamTarget<Target>>
    where
        RequestOctets: AsRef<[u8]> + Octets,
        Target: Composer + OctetsBuilder,
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
        let cookie = Self::cookie(request).unwrap().unwrap().create_response(
            Serial::now(),
            request.client_addr().ip(),
            &self.server_secret,
        );

        builder.header_mut().set_rcode(Rcode::NoError);

        let mut additional = builder.additional();
        additional.opt(|opt| opt.cookie(cookie)).unwrap();

        additional
    }

    #[must_use]
    fn ensure_cookie_is_complete<Target: Octets>(
        &self,
        request: &ContextAwareMessage<Message<Target>>,
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

    fn mk_builder_for_target<Target>() -> MessageBuilder<StreamTarget<Target>>
    where
        Target: Composer + OctetsBuilder + Default,
    {
        let target = StreamTarget::new(Target::default())
            .map_err(|_| ())
            .unwrap(); // SAFETY
        MessageBuilder::from_target(target).unwrap() // SAFETY
    }
}

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for CookiesMiddlewareProcesor
where
    RequestOctets: AsRef<[u8]> + Octets,
    Target: Composer + OctetsBuilder + Default,
{
    fn preprocess(
        &self,
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        match Self::cookie(request) {
            None => {
                // https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.1
                // No OPT RR or No COOKIE Option:
                //   "If there is no OPT record or no COOKIE option
                //   present in the request, then the server responds to
                //   the request as if the server doesn't implement the
                //   COOKIE option."
                // So, nothing to do here.
            }

            Some(Err(_err)) => {
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

                let mut builder = Self::mk_builder_for_target();
                builder.header_mut().set_rcode(Rcode::FormErr);
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

                    if request.header_counts().qdcount() == 0 {
                        let builder = Self::mk_builder_for_target::<Target>();
                        let additional = if !server_cookie_exists {
                            // "If such a query provided just a Client Cookie
                            // and no Server Cookie, the response SHALL have
                            // the RCODE NOERROR."
                            self.prefetch_cookie_response(request, builder)
                        } else {
                            // "In this case, the response SHALL have the
                            // RCODE BADCOOKIE if the Server Cookie sent with
                            // the query was invalid"
                            self.bad_cookie_response(request, builder)
                        };
                        return ControlFlow::Break(additional);
                    } else if !request.received_over_tcp() {
                        let builder = Self::mk_builder_for_target();
                        let additional =
                            self.bad_cookie_response(request, builder);
                        return ControlFlow::Break(additional);
                    }
                } else if request.header_counts().qdcount() == 0 {
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

                    let builder = Self::mk_builder_for_target();
                    let additional =
                        self.prefetch_cookie_response(request, builder);
                    return ControlFlow::Break(additional);
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

            // TODO: Do we need to replace all COOKIE options rather than
            // append another one (which, if not the first, should be ignored
            // by the client) ?
            response.opt(|opt| opt.cookie(filled_cookie)).unwrap();
        }
    }
}
