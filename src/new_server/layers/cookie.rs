//! DNS cookie management.

use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::{ControlFlow, Range},
};

use std::{sync::Arc, vec::Vec};

use arc_swap::ArcSwap;
use rand::{CryptoRng, Rng, RngCore};

use crate::{
    new_base::{
        wire::{AsBytes, ParseBytesByRef},
        Serial,
    },
    new_edns::{
        ClientCookie, Cookie, CookieBuf, CookieError, EdnsOption, OptionCode,
    },
    new_server::{
        exchange::{Metadata, OutgoingResponse, ResponseCode},
        transport::{SourceIpAddr, UdpMetadata},
        Exchange, LocalServiceLayer, ServiceLayer,
    },
};

//----------- CookieLayer ----------------------------------------------------

/// Server-side DNS cookie management.
#[derive(Debug)]
pub struct CookieLayer {
    /// The cookie policy to use.
    policy: ArcSwap<CookiePolicy>,

    /// The secrets to use for signing and verifying.
    secrets: ArcSwap<CookieSecrets>,
}

//--- Interaction

impl CookieLayer {
    /// Construct a new [`CookieLayer`].
    pub fn new(policy: CookiePolicy, secrets: CookieSecrets) -> Self {
        Self {
            policy: ArcSwap::new(Arc::new(policy)),
            secrets: ArcSwap::new(Arc::new(secrets)),
        }
    }

    /// Load the cookie policy.
    ///
    /// The current state of the policy is loaded.  The policy may be changed
    /// by a different thread, so future calls to the method may result in
    /// different policies.
    pub fn get_policy(&self) -> Arc<CookiePolicy> {
        self.policy.load_full()
    }

    /// Replace the cookie policy.
    ///
    /// This will atomically update the policy, so that future callers of
    /// [`get_policy()`](Self::get_policy()) will (soon but not necessarily
    /// immediately) see the updated policy.
    pub fn set_policy(&self, policy: CookiePolicy) {
        self.policy.store(Arc::new(policy));
    }

    /// Load the cookie secrets.
    ///
    /// The current state of the secrets is loaded.  The secrets may be
    /// changed by a different thread, so future calls to the method may
    /// result in different secrets.
    pub fn get_secrets(&self) -> Arc<CookieSecrets> {
        self.secrets.load_full()
    }

    /// Replace the cookie secrets.
    ///
    /// This will atomically update the secrets, so that future callers of
    /// [`get_secrets()`](Self::get_secrets()) will (soon but not necessarily
    /// immediately) see the updated secrets.
    pub fn set_secrets(&self, secrets: CookieSecrets) {
        self.secrets.store(Arc::new(secrets));
    }
}

//--- Processing incoming requests

impl CookieLayer {
    /// Respond to an incoming request with an alleged server cookie.
    fn process_incoming_server_cookie<'a>(
        &self,
        exchange: &mut Exchange<'a>,
        addr: IpAddr,
        cookie: &'a Cookie,
    ) -> ControlFlow<()> {
        // Determine the validity period of the cookie.
        let now = Serial::unix_time();
        let validity = now + -300..now + 3600;

        // Check if the cookie is actually valid.
        if self.secrets.load().verify(&addr, validity, cookie).is_err() {
            // Simply ignore the server part.
            return self.process_incoming_wo_server_cookie(
                exchange,
                addr,
                Some(cookie.request()),
            );
        }

        // Determine whether the cookie needs to be renewed.
        let expiry = now + 1800;
        let regenerate = cookie.timestamp() >= expiry;

        // Remember the cookie status.
        let cookie = CookieBuf::copy_from(cookie);
        let metadata = CookieMetadata::ServerCookie { cookie, regenerate };
        exchange.metadata.push(Metadata::new(metadata));

        // Continue into the next layer.
        ControlFlow::Continue(())
    }

    /// Respond to an incoming request without a (valid) server cookie.
    fn process_incoming_wo_server_cookie<'a>(
        &self,
        exchange: &mut Exchange<'a>,
        addr: IpAddr,
        cookie: Option<&'a ClientCookie>,
    ) -> ControlFlow<()> {
        // RFC 7873, section 5.2.3:
        //
        // > Servers MUST, at least occasionally, respond to such requests to
        // > inform the client of the correct Server Cookie.  This is
        // > necessary so that such a client can bootstrap to the more secure
        // > state where requests and responses have recognized Server Cookies
        // > and Client Cookies.  A server is not expected to maintain
        // > per-client state to achieve this.  For example, it could respond
        // > to every Nth request across all clients.

        // We rate-limit requests based on the cookie policy.  If the request
        // originates from a restricted IP address, the request is allowed to
        // continue with a small probability.  All requests from unrestricted
        // IP addresses are allowed to go through.  All non-UDP requests are
        // allowed to go through anyway.
        if !exchange.metadata.iter().any(|m| m.is::<UdpMetadata>())
            || !self.policy.load().is_required_for(addr)
            || rand::thread_rng().gen_bool(0.05)
        {
            // The request is allowed to go through.
            let metadata = match cookie {
                Some(&cookie) => CookieMetadata::ClientCookie(cookie),
                None => CookieMetadata::None,
            };
            exchange.metadata.push(Metadata::new(metadata));
            return ControlFlow::Continue(());
        }

        // Block the request.
        if exchange.request.has_edns() {
            exchange.respond(ResponseCode::BadCookie);
        } else {
            exchange.respond(ResponseCode::Refused);
            exchange.response.flags =
                exchange.response.flags.set_truncated(true);
        }
        exchange
            .response
            .questions
            .append(&mut exchange.request.questions);

        ControlFlow::Break(())
    }
}

//--- Processing outgoing responses

impl CookieLayer {
    /// Generate an EDNS COOKIE option for a response.
    fn generate_cookie(
        &self,
        addr: IpAddr,
        cookie: ClientCookie,
    ) -> CookieBuf {
        cookie.respond(addr, &self.secrets.load().primary)
    }
}

//--- ServiceLayer

impl ServiceLayer for CookieLayer {
    async fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        // Check for an EDNS COOKIE option.
        let cookie = exchange
            .request
            .options
            .iter()
            .find(|option| option.code() == OptionCode::COOKIE)
            .cloned();

        // Determine the IP address the request originated from.
        let Some(&SourceIpAddr(addr)) =
            exchange.metadata.iter().find_map(|m| m.try_as())
        else {
            // We couldn't determine the source address.
            // TODO: This is unexpected, log it.
            return ControlFlow::Continue(());
        };

        match cookie {
            Some(EdnsOption::Cookie(cookie)) => {
                self.process_incoming_server_cookie(exchange, addr, cookie)
            }

            Some(EdnsOption::ClientCookie(cookie)) => self
                .process_incoming_wo_server_cookie(
                    exchange,
                    addr,
                    Some(cookie),
                ),

            None => {
                self.process_incoming_wo_server_cookie(exchange, addr, None)
            }

            _ => unreachable!(),
        }
    }

    async fn process_outgoing(&self, response: OutgoingResponse<'_, '_>) {
        // Determine the IP address the request originated from.
        let Some(&SourceIpAddr(addr)) =
            response.metadata.iter().find_map(|m| m.try_as())
        else {
            // We couldn't determine the source address.
            // TODO: This is unexpected, log it.
            return;
        };

        // Check for cookie metadata.
        let cookie = match response.metadata.iter().find_map(|m| m.try_as()) {
            // The request had a client cookie (and possibly an invalid server
            // cookie).  Generate a new server cookie and include it.
            Some(CookieMetadata::ClientCookie(cookie)) => {
                self.generate_cookie(addr, *cookie)
            }

            // The request had a server cookie that may need to be renewed.
            Some(CookieMetadata::ServerCookie { cookie, regenerate }) => {
                if *regenerate {
                    self.generate_cookie(addr, *cookie.request())
                } else {
                    cookie.clone()
                }
            }

            // The request did not contain a cookie, or the cookie layer was
            // disabled when answering this request.
            Some(CookieMetadata::None) | None => return,
        };

        // Copy the cookie into the response.
        // TODO: Check that the response includes an EDNS record.
        let cookie = response.alloc.alloc_slice_copy((*cookie).as_bytes());
        let cookie = Cookie::parse_bytes_by_ref(cookie).unwrap();
        let option = EdnsOption::Cookie(cookie);
        response.response.options.push(option);
    }
}

impl LocalServiceLayer for CookieLayer {
    async fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> ControlFlow<()> {
        self.process_incoming(exchange).await
    }

    async fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) {
        self.process_outgoing(response).await
    }
}

//----------- CookiePolicy ---------------------------------------------------

/// Configuration for DNS cookie enforcement.
#[derive(Clone, Debug, Default)]
pub struct CookiePolicy {
    /// IP addresses that must provide DNS cookies with their queries.
    pub required: PrefixTree,

    /// IP addresses that need not provide DNS cookies with their queries.
    pub allowed: PrefixTree,
}

impl CookiePolicy {
    /// Whether an IP address is required to use DNS cookies.
    pub fn is_required_for(&self, addr: IpAddr) -> bool {
        match (self.required.test(addr), self.allowed.test(addr)) {
            // The address is restricted, but is more specifically allowed.
            (Some(r), Some(a)) if a >= r => false,

            // The address is definitely restricted.
            (Some(_), _) => true,

            // There are no restrictions on the address.
            (None, _) => true,
        }
    }
}

//----------- CookieSecrets --------------------------------------------------

/// The secrets used for DNS cookies.
#[derive(Clone, Debug)]
pub struct CookieSecrets {
    /// The primary secret (used for generation and verification).
    pub primary: [u8; 16],

    /// A secondary secret for verification.
    pub secondary: [u8; 16],
}

impl CookieSecrets {
    /// Initialize [`CookieSecrets`] with a random primary.
    pub fn generate() -> Self {
        Self::generate_with(rand::thread_rng())
    }

    /// Initialize [`CookieSecrets`] with the given RNG.
    pub fn generate_with(mut rng: impl CryptoRng + RngCore) -> Self {
        let primary = rng.gen();
        Self {
            primary,
            secondary: primary,
        }
    }

    /// Verify the given cookie against these secrets.
    fn verify(
        &self,
        addr: &IpAddr,
        validity: Range<Serial>,
        cookie: &Cookie,
    ) -> Result<(), CookieError> {
        let Err(err) = cookie.verify(*addr, &self.primary, validity.clone())
        else {
            return Ok(());
        };

        // TODO: Compare secrets more carefully.
        if self.primary == self.secondary {
            return Err(err);
        }

        cookie.verify(*addr, &self.secondary, validity)
    }
}

//----------- CookieMetadata -------------------------------------------------

/// Information about a DNS request's use of cookies.
pub enum CookieMetadata {
    /// The request did not use DNS cookies.
    None,

    /// The request included a DNS client cookie.
    ClientCookie(ClientCookie),

    /// The request included a DNS server cookie.
    ServerCookie {
        /// The cookie used in the request.
        cookie: CookieBuf,

        /// Whether a new cookie should be generated.
        regenerate: bool,
    },
}

//----------- PrefixTree -----------------------------------------------------

/// A set of IP addresses represented as prefixes.
#[derive(Clone, Debug, Default)]
pub struct PrefixTree {
    /// A list of v4 prefixes, from longest to shortest.
    v4_prefixes: Vec<(u8, Ipv4Addr)>,

    /// A list of v6 prefixes, from longest to shortest.
    v6_prefixes: Vec<(u8, Ipv6Addr)>,
}

impl PrefixTree {
    /// Build a [`PrefixTree`] from an unsorted list of prefixes.
    ///
    /// The prefixes will be sorted before being used.  Outside the valid
    /// length of each prefix, only zero bits must be used.
    pub fn from_prefixes(
        mut v4_prefixes: Vec<(u8, Ipv4Addr)>,
        mut v6_prefixes: Vec<(u8, Ipv6Addr)>,
    ) -> Self {
        v4_prefixes.sort_unstable_by(|a, b| a.0.cmp(&b.0).reverse());
        v6_prefixes.sort_unstable_by(|a, b| a.0.cmp(&b.0).reverse());
        Self::from_sorted_prefixes(v4_prefixes, v6_prefixes)
    }

    /// Build a [`PrefixTree`] from a sorted list of prefixes.
    ///
    /// The prefixes must be sorted from longest to shortest.  Within a
    /// particular prefix length, the addresses are unordered.  Outside the
    /// valid length of each prefix, only zero bits must be used.
    pub fn from_sorted_prefixes(
        v4_prefixes: Vec<(u8, Ipv4Addr)>,
        v6_prefixes: Vec<(u8, Ipv6Addr)>,
    ) -> Self {
        Self {
            v4_prefixes,
            v6_prefixes,
        }
    }

    /// Test whether an IP address is in this prefix tree.
    ///
    /// If a matching prefix is found, its length is returned.
    pub fn test(&self, addr: IpAddr) -> Option<u8> {
        match addr {
            IpAddr::V4(addr) => self.test_v4(addr),
            IpAddr::V6(addr) => self.test_v6(addr),
        }
    }

    /// Test whether an IPv4 address is in this prefix tree.
    ///
    /// If a matching prefix is found, its length is returned.
    pub fn test_v4(&self, addr: Ipv4Addr) -> Option<u8> {
        self.v4_prefixes
            .iter()
            .copied()
            .find(|(_, prefix)| (prefix & addr) == *prefix)
            .map(|(length, _)| length)
    }

    /// Test whether an IPv6 address is in this prefix tree.
    ///
    /// If a matching prefix is found, its length is returned.
    pub fn test_v6(&self, addr: Ipv6Addr) -> Option<u8> {
        self.v6_prefixes
            .iter()
            .copied()
            .find(|(_, prefix)| (prefix & addr) == *prefix)
            .map(|(length, _)| length)
    }
}
