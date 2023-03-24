//! EDNS Option for DNS cookies.
//!
//! The option in this module – [`Cookie`] –  is part of a simple mechanism
//! that helps DNS servers to mitigate denial-of-service and amplification
//! attacks called DNS cookies.
//!
//! In this mechanism, the client creates a client cookie and includes it in
//! its request to a server. When answering, the server generates a server
//! cookie from the client cookie and a secret and includes it in the
//! response. When the client sends subsequent queries to the same server,
//! it includes both the same client cookie as before and the server cookie
//! it received, thus identifying itself as having sent a query before.
//! Because server cookies are deterministic for a given client cookie, the
//! server doesn’t need to keep any state other than the secret.
//!
//! The DNS Cookie mechanism is defined in [RFC 7873]. Guidance for creating
//! client and server cookies is provided by [RFC 9018].
//!
//! [RFC 7873]: https://tools.ietf.org/html/rfc7873
//! [RFC 9018]: https://tools.ietf.org/html/rfc9018

use core::{fmt, hash};
use octseq::array::Array;
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;
use crate::base::Serial;
use crate::utils::base16;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{Opt, OptData, ComposeOptData, ParseOptData};


//------------ Cookie --------------------------------------------------------

/// Option data for a DNS cookie.
///
/// A value of this type carries two parts: A mandatory [`ClientCookie`] and
/// an optional [`ServerCookie`]. The client cookie is chosen by, yes, the
/// client and added to a request when contacting a specific server for the
/// first time. When responding, a server calculates a server cookie from the
/// client cookie and adds both of them to the response. The client remembers
/// both and includes them in subsequent requests. The server can now check
/// that the the server cookie was indeed calculated by it and treat the
/// repeat customer differently.
///
/// While you can create a new cookie using the [`new`][Self::new] method,
/// shortcuts are available for the standard workflow. A new initial cookie
/// can be created via [`create_initial`][Self::create_initial]. As this will
/// be a random client cookie, it needs the `rand` feature. The server can
/// check whether a received cookie includes a server cookie created by it
/// via the [`check_server_hash`][Self::check_server_hash] method. It needs
/// the SipHash-2-4 algorithm and is thus available if the `siphasher` feature
/// is enabled. The same feature also enables the
/// [`create_response`][Self::create_response] method which creates the server
/// cookie to be included in a response.
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie {
    /// The client cookie.
    client: ClientCookie, 

    /// The optional server cookie.
    server: Option<ServerCookie>,
}

impl Cookie {
    /// Creates a new cookie from client and optional server cookie.
    pub fn new(
        client: ClientCookie,
        server: Option<ServerCookie>
    ) -> Self {
        Cookie { client, server }
    }

    /// Returns the client cookie.
    pub fn client(&self) -> ClientCookie {
        self.client
    }

    /// Returns a reference to the server cookie if present.
    pub fn server(&self) -> Option<&ServerCookie> {
        self.server.as_ref()
    }

    /// Parses the cookie from its wire format.
    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        Ok(Cookie::new(
            ClientCookie::parse(parser)?,
            ServerCookie::parse_opt(parser)?,
        ))
    }

    /// Returns whether the standard server cookie’s hash is correct.
    ///
    /// The `client_ip` is the source IP address of a request. The `secret`
    /// is the server cookie secret. The timestamp is checked via the
    /// `timestamp_ok` closure which is given the timestamp and should return
    /// whether it is acceptable.
    ///
    /// Returns `false` if the cookie is not a server cookie, if it is but
    /// not a standard server cookie, or if it is but either the timestamp
    /// is not acceptable or the hash differs from what it should be.
    ///
    /// Thus, if this method returns `false`, there is no valid server cookie
    /// and the server can proceed as if there was no server cookie as
    /// described in section 5.2.3 of [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    #[cfg(feature = "siphasher")]
    pub fn check_server_hash(
        &self,
        client_ip: crate::base::net::IpAddr,
        secret: &[u8; 16],
        timestamp_ok: impl FnOnce(Serial) -> bool,
    ) -> bool {
        self.server.as_ref().and_then(|server| {
            server.try_to_standard()
        }).and_then(|server| {
            timestamp_ok(server.timestamp()).then_some(server)
        }).map(|server| {
            server.check_hash(self.client(), client_ip, secret)
        }).unwrap_or(false)
    }

    /// Creates a random client cookie for including in an initial request.
    #[cfg(feature = "rand")]
    pub fn create_initial() -> Self {
        Self::new(ClientCookie::new_random(), None)
    }

    /// Creates a standard format cookie option for sending a response.
    ///
    /// This method uses the client cookie and the additional values provided
    /// to produce a cookie option that should be included in a response.
    #[cfg(feature = "siphasher")]
    pub fn create_response(
        &self, 
        timestamp: Serial,
        client_ip: crate::base::net::IpAddr,
        secret: &[u8; 16]
    ) -> Self {
        Self::new(
            self.client,
            Some(
                StandardServerCookie::calculate(
                    self.client, timestamp, client_ip, secret
                ).into()
            )
        )
    }
}


//--- OptData

impl OptData for Cookie {
    fn code(&self) -> OptionCode {
        OptionCode::Cookie
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParseOptData<'a, Octs> for Cookie {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Cookie {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for Cookie {
    fn compose_len(&self) -> u16 {
        match self.server.as_ref() {
            Some(server) => {
                ClientCookie::COMPOSE_LEN.checked_add(
                    server.compose_len()
                ).expect("long server cookie")
            }
            None => ClientCookie::COMPOSE_LEN
        }
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.client.compose(target)?;
        if let Some(server) = self.server.as_ref() {
            server.compose(target)?;
        }
        Ok(())
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.client, f)?;
        if let Some(server) = self.server.as_ref() {
            fmt::Display::fmt(server, f)?;
        }
        Ok(())
    }
}


//--- Extending Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first cookie option if present.
    pub fn cookie(&self) -> Option<Cookie> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends a new cookie option.
    pub fn cookie(
        &mut self, cookie: Cookie,
    ) -> Result<(), Target::AppendError> {
        self.push(&cookie)
    }

    /// Appends a new initial client cookie.
    ///
    /// The appened cookie will have a random client cookie portion and no
    /// server cookie. See [`Cookie`] for more information about cookies.
    #[cfg(feature = "rand")]
    pub fn initial_cookie(&mut self) -> Result<(), Target::AppendError> {
        self.push(&Cookie::create_initial())
    }
}


//------------ ClientCookie --------------------------------------------------

/// A client cookie for DNS cookies.
///
/// The client cookies consists of exactly 8 octets. It is generated by a
/// client for each server it sends queries to. It is important to use a
/// different cookie for every server so a server cannot spoof answers for
/// other servers.
///
/// Originally, it was suggested to include the client’s IP address when
/// generating the cookie, but since the address may not be known when
/// originating a request, this has been relaxed and it is now suggested that
/// the cookies is just random data. If the `rand` feature is enabled, the
/// `new`
#[cfg_attr(feature = "rand", doc = "[`new_random`][ClientCookie::new_random]")]
#[cfg_attr(not(feature = "rand"), doc = "`new_random`")]
/// constructor can be used to generate such a random cookie. Otherwise,
/// it needs to be created from the octets via
/// [`from_octets`][ClientCookie::from_octets]. Similarly, the `Default`
/// implementation will create a random cookie and is thus only available if
/// the `rand` feature is enabled.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientCookie([u8; 8]);

impl ClientCookie {
    /// Creates a new client cookie from the given octets.
    pub const fn from_octets(octets: [u8; 8]) -> Self {
        Self(octets)
    }

    /// Creates a new random client cookie.
    #[cfg(feature = "rand")]
    pub fn new_random() -> Self {
        Self(rand::random())
    }

    /// Converts the cookie into its octets.
    pub fn into_octets(self) -> [u8; 8] {
        self.0
    }

    /// Parses a client cookie from its wire format.
    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        let mut res = Self::from_octets([0; 8]);
        parser.parse_buf(res.as_mut())?;
        Ok(res)
    }

    /// The length of the wire format of a client cookie.
    pub const COMPOSE_LEN: u16 = 8;

    /// Appends the wire format of the client cookie to the target.
    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.0)
    }
}

//--- Default

#[cfg(feature = "rand")]
impl Default for ClientCookie {
    fn default() -> Self {
        Self::new_random()
    }
}

//--- From

impl From<[u8; 8]> for ClientCookie {
    fn from(src: [u8; 8]) -> Self {
        Self::from_octets(src)
    }
}

impl From<ClientCookie> for [u8; 8] {
    fn from(src: ClientCookie) -> Self {
        src.0
    }
}

//--- AsRef and AsMut

impl AsRef<[u8]> for ClientCookie {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for ClientCookie {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

//--- Hash

impl hash::Hash for ClientCookie {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0)
    }
}

//--- Display

impl fmt::Display for ClientCookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.0.as_ref(), f)
    }
}


//------------ ServerCookie --------------------------------------------------

/// A server cookie for DNS cookies.
///
/// In the original specification, the server cookie was of variable length
/// between 8 and 32 octets. It was supposed to be generated via some sort
/// of message authentication code from the client cookie and a server secret.
/// Leaving the concrete mechanism to the implementer resulted in
/// interoperability problems if servers from multiple vendors were placed
/// behind the same public address. Thus, [RFC 9018] defined a standard
/// mechanism of the content and generation of the cookie.
///
/// This standard server cookie consists of a 1 octet version number
/// (currently 1), 3 reserved octets that must be zero, a 4 octet timestamp
/// as seconds since the Unix epoch, and 8 octets of hash value.
///
/// In version 1, the hash is calculated feeding the SipHash-2-4 that has been
/// initialized with a server secret the concatenation of client cookie,
/// version, reserved, timestamp, client IP address.
///
/// [RFC 9018]: https://tools.ietf.org/html/rfc9018
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ServerCookie(Array<32>);

impl ServerCookie {
    /// Creates a new server cookie from the given octets.
    ///
    /// # Panics
    ///
    /// The function panics if `octets` is shorter than 8 octets or longer
    /// than 32.
    pub fn from_octets(slice: &[u8]) -> Self {
        assert!(slice.len() >= 8, "server cookie shorter than 8 octets");
        let mut res = Array::new();
        res.append_slice(slice).expect("server cookie longer tha 32 octets");
        Self(res)
    }

    /// Parses a server cookie from its wire format.
    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        if parser.remaining() < 8 {
            return Err(ParseError::form_error("short server cookie"))
        }
        let mut res = Array::new();
        res.resize_raw(parser.remaining()).map_err(|_| {
            ParseError::form_error("long server cookie")
        })?;
        parser.parse_buf(res.as_slice_mut())?;
        Ok(Self(res))
    }

    /// Parses an optional server cookie from its wire format.
    pub fn parse_opt<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Option<Self>, ParseError> {
        if parser.remaining() > 0 {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }

    /// Converts the cookie into a standard cookie if possible.
    ///
    /// This is possible if the length of the cookie is 16 octets. Returns
    /// `None` otherwise.
    pub fn try_to_standard(&self) -> Option<StandardServerCookie> {
        TryFrom::try_from(self.0.as_slice()).map(StandardServerCookie).ok()
    }

    /// Returns the length of the wire format of the cookie.
    pub fn compose_len(&self) -> u16 {
        u16::try_from(self.0.len()).expect("long server cookie")
    }

    /// Appends the wire format of the cookie to the target.
    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0.as_ref())
    }
}

//--- From

impl From<StandardServerCookie> for ServerCookie {
    fn from(src: StandardServerCookie) -> Self {
        Self::from_octets(&src.0)
    }
}

//--- AsRef

impl AsRef<[u8]> for ServerCookie {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//--- Display

impl fmt::Display for ServerCookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.0.as_ref(), f)
    }
}


//------------ StandardServerCookie ------------------------------------------

/// An interoperable server cookie for DNS cookies.
///
/// In the original specification, the server cookie was of variable length
/// and rules for its generation were left to the server implementers. This
/// resulted in interoperability problems if servers from multiple vendors
/// were placed behind the same public address. Thus, [RFC 9018] defined a
/// standard mechanism of the content and generation of the cookie. This
/// type is such a standard server cookie.
///
/// This standard server cookie consists of a 1 octet version number
/// (currently 1), 3 reserved octets that must be zero, a 4 octet timestamp
/// as seconds since the Unix epoch, and 8 octets of hash value.
///
/// In version 1, the hash is calculated feeding the SipHash-2-4 that has been
/// initialized with a server secret the concatenation of client cookie,
/// version, reserved, timestamp, client IP address. Generatin and checking
/// the hash is available if the `siphasher` feature is enabled.
///
/// [RFC 9018]: https://tools.ietf.org/html/rfc9018
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StandardServerCookie(
    // We let this type wrap a u8 array so we can provide AsRef<[u8]> it.
    // This makes reading the timestamp a tiny bit expensive on certain
    // systems, but so be it.
    [u8; 16]
);

impl StandardServerCookie {
    /// Creates a new server cookie from the provided components.
    pub fn new(
        version: u8,
        reserved: [u8; 3],
        timestamp: Serial,
        hash: [u8; 8]
    ) -> Self {
        let ts = timestamp.into_int().to_be_bytes();
        Self(
            [ version, reserved[0], reserved[1], reserved[2],
              ts[0], ts[1], ts[2], ts[3],
              hash[0], hash[1], hash[2], hash[3],
              hash[4], hash[5], hash[6], hash[7],
            ]
        )
    }

    /// Calculates the server cookie for the given components.
    #[cfg(feature = "siphasher")]
    pub fn calculate(
        client_cookie: ClientCookie,
        timestamp: Serial,
        client_ip: crate::base::net::IpAddr,
        secret: &[u8; 16]
    ) -> Self {
        let mut res = Self::new(1, [0; 3], timestamp, [0; 8]);
        res.set_hash(
            res.calculate_hash(client_cookie, client_ip, secret)
        );
        res
    }

    /// Returns the version field of the cookie.
    pub fn version(self) -> u8 {
        self.0[0]
    }

    /// Returns the reserved field of the cookie.
    pub fn reserved(self) -> [u8; 3] {
        TryFrom::try_from(&self.0[1..4]).expect("bad slicing")
    }

    /// Returns the timestamp field of the cookie.
    pub fn timestamp(self) -> Serial {
        Serial::from_be_bytes(
            TryFrom::try_from(&self.0[4..8]).expect("bad slicing")
        )
    }

    /// Returns the hash field of the cookie.
    pub fn hash(self) -> [u8; 8] {
        TryFrom::try_from(&self.0[8..]).expect("bad slicing")
    }

    /// Sets the hash field to the given value.
    pub fn set_hash(&mut self, hash: [u8; 8]) {
        self.0[8..].copy_from_slice(&hash);
    }

    /// Returns whether the hash matches the given client cookie and secret.
    #[cfg(feature = "siphasher")]
    pub fn check_hash(
        self,
        client_cookie: ClientCookie,
        client_ip: crate::base::net::IpAddr,
        secret: &[u8; 16]
    ) -> bool {
        self.calculate_hash(client_cookie, client_ip, secret) == self.hash()
    }

    /// Calculates the hash value.
    ///
    /// The method takes the version, reserved, and timestamp fields from
    /// `self` and the rest from the arguments. It returns the hash as an
    /// octets array.
    //
    // XXX The hash implementation for SipHash-2-4 returns the result as
    // a `u64` whereas RFC 9018 assumes it is returned as an octets array in
    // a standard ordering. Somewhat surprisingly, this ordering turns out to
    // be little endian.
    #[cfg(feature = "siphasher")]
    fn calculate_hash(
        self,
        client_cookie: ClientCookie,
        client_ip: crate::base::net::IpAddr,
        secret: &[u8; 16]
    ) -> [u8; 8] {
        use core::hash::{Hash, Hasher};
        use crate::base::net::IpAddr;

        let mut hasher = siphasher::sip::SipHasher24::new_with_key(secret);
        client_cookie.hash(&mut hasher);
        hasher.write(&self.0[..8]);
        match client_ip {
            IpAddr::V4(addr) => hasher.write(&addr.octets()),
            IpAddr::V6(addr) => hasher.write(&addr.octets()),
        }
        hasher.finish().to_le_bytes()
    }
}

//--- Display

impl fmt::Display for StandardServerCookie {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.0.as_ref(), f)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    /// Tests from Appendix A of RFC 9018.
    #[cfg(all(feature = "siphasher", feature = "std"))]
    mod standard_server {
        use crate::base::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use crate::base::wire::{compose_vec, parse_slice};
        use super::*;

        const CLIENT_1: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100));
        const CLIENT_2: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 203));
        const CLIENT_6: IpAddr = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x220, 0x1, 0x59de, 0xd0f4, 0x8769, 0x82b8
        ));

        const SECRET: [u8; 16] = [
            0xe5, 0xe9, 0x73, 0xe5, 0xa6, 0xb2, 0xa4, 0x3f,
            0x48, 0xe7, 0xdc, 0x84, 0x9e, 0x37, 0xbf, 0xcf,
        ];

        /// A.1. Learning a New Server Cookie
        #[test]
        fn new_cookie() {
            let request = Cookie::new(
                ClientCookie::from_octets(
                    [ 0x24, 0x64, 0xc4, 0xab, 0xcf, 0x10, 0xc9, 0x57 ]
                ),
                None
            );
            assert_eq!(
                compose_vec(|vec| request.compose_option(vec)),
                base16::decode_vec("2464c4abcf10c957").unwrap()
            );

            assert_eq!(
                compose_vec(|vec| {
                    request.create_response(
                        Serial(1559731985), CLIENT_1, &SECRET
                    ).compose_option(vec)
                }),
                base16::decode_vec(
                    "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
                ).unwrap()
            );
        }

        /// A.2.  The Same Client Learning a Renewed (Fresh) Server Cookie
        #[test]
        fn renew_cookie() {
            let request = parse_slice(
                &base16::decode_vec(
                "2464c4abcf10c957010000005cf79f111f8130c3eee29480"
                ).unwrap(),
                Cookie::parse
            ).unwrap();
            assert!(
                request.check_server_hash(
                    CLIENT_1, &SECRET,
                    |serial| serial == Serial(1559731985)
                )
            );

            assert_eq!(
                compose_vec(|vec| {
                    request.create_response(
                        Serial(1559734385), CLIENT_1, &SECRET
                    ).compose_option(vec)
                }),
                base16::decode_vec(
                    "2464c4abcf10c957010000005cf7a871d4a564a1442aca77"
                ).unwrap()
            );
        }

        /// A.3.  Another Client Learning a Renewed Server Cookie
        #[test]
        fn non_zero_reserved() {
            let request = parse_slice(
                &base16::decode_vec(
                    "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5"
                ).unwrap(),
                Cookie::parse
            ).unwrap();
            assert!(
                request.check_server_hash(
                    CLIENT_2, &SECRET,
                    |serial| serial == Serial(1559727985)
                )
            );

            assert_eq!(
                compose_vec(|vec| {
                    request.create_response(
                        Serial(1559734700), CLIENT_2, &SECRET
                    ).compose_option(vec)
                }),
                base16::decode_vec(
                    "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e"
                ).unwrap()
            );
        }

        /// A.4.  IPv6 Query with Rolled Over Secret
        #[test]
        fn new_secret() {

            const OLD_SECRET: [u8; 16] = [
                0xdd, 0x3b, 0xdf, 0x93, 0x44, 0xb6, 0x78, 0xb1,
                0x85, 0xa6, 0xf5, 0xcb, 0x60, 0xfc, 0xa7, 0x15,
            ];
            const NEW_SECRET: [u8; 16] = [
                0x44, 0x55, 0x36, 0xbc, 0xd2, 0x51, 0x32, 0x98,
                0x07, 0x5a, 0x5d, 0x37, 0x96, 0x63, 0xc9, 0x62,
            ];

            let request = parse_slice(
                &base16::decode_vec(
                    "22681ab97d52c298010000005cf7c57926556bd0934c72f8"
                ).unwrap(),
                Cookie::parse
            ).unwrap();
            assert!(
                !request.check_server_hash(
                    CLIENT_6, &NEW_SECRET,
                    |serial| serial == Serial(1559741817)
                )
            );
            assert!(
                request.check_server_hash(
                    CLIENT_6, &OLD_SECRET,
                    |serial| serial == Serial(1559741817)
                )
            );

            assert_eq!(
                compose_vec(|vec| {
                    request.create_response(
                        Serial(1559741961), CLIENT_6, &NEW_SECRET
                    ).compose_option(vec)
                }),
                base16::decode_vec(
                    "22681ab97d52c298010000005cf7c609a6bb79d16625507a"
                ).unwrap()
            );
        }
    }
}

