//! DNS response codes and extended response codes.
//!
//! The original DNS specification in [RFC 1035] specified four bits of the
//! message header as response code. The type [`Rcode`] defined herein
//! represents these codes. Later, [RFC 2671][] (now [RFC 6891]) added eight
//! bits to the response code to be transmitted as part of the OPT
//! pseudo-resource record. To make matters even worse, the TSIG and TKEY
//! records defined by [RFC 2845] and [RFC 2930] use a 16 bit error code.
//! All of these codes share the same definition space. Even so, we have
//! separate types for each of these.
//!
//! [`Rcode`]: enum.Rcode.html
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035
//! [RFC 2671]: https://tools.ietf.org/html/rfc2671
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845
//! [RFC 2930]: https://tools.ietf.org/html/rfc2930
//! [RFC 6891]: https://tools.ietf.org/html/rfc6891
//!
#![allow(clippy::upper_case_acronyms)]

use core::{cmp, fmt, hash};

//------------ Rcode --------------------------------------------------------

/// DNS Response Codes.
///
/// The response code of a response indicates what happend on the server
/// when trying to answer the query. The code is a 4 bit value and part of
/// the header of a DNS message.
///
/// This response was defined as part of [RFC 1035]. Later, [RFC 2671]
/// defined an extended response code of 12 bits using the lower four bits
/// from the header and eight additional bits stored in the OPT
/// pseudo-record. The type [OptRcode] represents this extended response
/// code. A third response code, now 16 bit wide, was defined for the
/// transaction authentication mechansim (TSIG) in [RFC 2845] and is
/// represented by [TsigRcode].
///
/// All three codes share the same name space. Their values are defined in
/// one registry, [IANA DNS RCODEs]. This type is complete as of 2019-01-28.
///
/// [OptRcode]: enum.OptRcode.html
/// [TsigRcode]: enum.TsigRcode.html
/// [IANA DNS RCODEs]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
#[derive(Clone, Copy, Debug)]
pub enum Rcode {
    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NoError,

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    FormErr,

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    ServFail,

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NXDomain,

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NotImp,

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    Refused,

    /// Name exists when it should not.
    ///
    /// Returned for an UPDATE query when a domain requested to not exist
    /// does in fact exist.
    ///
    /// Returned when resolving a DNAME redirection when the resulting name
    /// exceeds the length of 255 octets.
    ///
    /// Defined in [RFC 2136] for the UPDATE query and [RFC 6672] for DNAME
    /// redirection.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 6672]: https://tools.ietf.org/html/rfc6672
    YXDomain,

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    YXRRSet,

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    NXRRSet,

    /// Server not authoritative for zone or client not authorized.
    ///
    /// Returned for an UPDATE query when the server is not an authoritative
    /// name server for the requested domain.
    ///
    /// Returned for queries using TSIG when authorisation failed.
    ///
    /// Defined in [RFC 2136] for UPDATE and [RFC 2845] for TSIG.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    NotAuth,

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    NotZone,

    /// A raw, integer rcode value.
    ///
    /// When converting to an `u8`, only the lower four bits are used.
    Int(u8),
}

impl Rcode {
    /// Creates an rcode from an integer.
    ///
    /// Only the lower four bits of `value` are considered.
    #[must_use]
    pub fn from_int(value: u8) -> Rcode {
        use self::Rcode::*;

        match value & 0x0F {
            0 => NoError,
            1 => FormErr,
            2 => ServFail,
            3 => NXDomain,
            4 => NotImp,
            5 => Refused,
            6 => YXDomain,
            7 => YXRRSet,
            8 => NXRRSet,
            9 => NotAuth,
            10 => NotZone,
            value => Int(value),
        }
    }

    /// Returns the integer value for this rcode.
    ///
    /// Only the lower 4 bits of the returned octet are used by the rcode. The
    /// upper four bits are always zero.
    #[must_use]
    pub fn to_int(self) -> u8 {
        use self::Rcode::*;

        match self {
            NoError => 0,
            FormErr => 1,
            ServFail => 2,
            NXDomain => 3,
            NotImp => 4,
            Refused => 5,
            YXDomain => 6,
            YXRRSet => 7,
            NXRRSet => 8,
            NotAuth => 9,
            NotZone => 10,
            Int(value) => value & 0x0F,
        }
    }
}

//--- From

impl From<u8> for Rcode {
    fn from(value: u8) -> Rcode {
        Rcode::from_int(value)
    }
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> u8 {
        value.to_int()
    }
}

//--- Display

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Rcode::*;

        match *self {
            NoError => "NOERROR".fmt(f),
            FormErr => "FORMERR".fmt(f),
            ServFail => "SERVFAIL".fmt(f),
            NXDomain => "NXDOMAIN".fmt(f),
            NotImp => "NOTIMP".fmt(f),
            Refused => "REFUSED".fmt(f),
            YXDomain => "YXDOMAIN".fmt(f),
            YXRRSet => "YXRRSET".fmt(f),
            NXRRSet => "NXRRSET".fmt(f),
            NotAuth => "NOAUTH".fmt(f),
            NotZone => "NOTZONE".fmt(f),
            Int(i) => match Rcode::from_int(i) {
                Rcode::Int(i) => i.fmt(f),
                value => value.fmt(f),
            },
        }
    }
}

//--- PartialEq and Eq

impl cmp::PartialEq for Rcode {
    fn eq(&self, other: &Rcode) -> bool {
        self.to_int() == other.to_int()
    }
}

impl cmp::PartialEq<u8> for Rcode {
    fn eq(&self, other: &u8) -> bool {
        self.to_int() == *other
    }
}

impl cmp::PartialEq<Rcode> for u8 {
    fn eq(&self, other: &Rcode) -> bool {
        *self == other.to_int()
    }
}

impl cmp::Eq for Rcode {}

//--- PartialOrd and Ord

impl cmp::PartialOrd for Rcode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl cmp::PartialOrd<u8> for Rcode {
    fn partial_cmp(&self, other: &u8) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl cmp::PartialOrd<Rcode> for u8 {
    fn partial_cmp(&self, other: &Rcode) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl cmp::Ord for Rcode {
    fn cmp(&self, other: &Rcode) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}

//--- Hash

impl hash::Hash for Rcode {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl serde::Serialize for Rcode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        self.to_int().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Rcode {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        u8::deserialize(deserializer).map(Rcode::from_int)
    }
}

//------------ OptRcode -----------------------------------------------------

/// Extended DNS Response Codes for OPT records.
///
/// Originally, the response code embedded in the header of each DNS
/// message was four bits long. This code, defined in [RFC 1035], is
/// represented by the [Rcode] type. The extension mechanism for DNS
/// initially defined in [RFC 2671] and updated by [RFC 6891] added eight
/// more bits to be stored in the OPT pseudo-resource record. This type
/// represents the complete 12 bit extended response code.
///
/// There is a third, 16 bit wide response code for transaction
/// authentication (TSIG) defined in [RFC 2845] and represented by the
/// [`TsigRcode`] type. The code mostly shares the same name space except
/// for an unfortunate collision in between the BADVERS and BADSIG values.
/// Because of this, we decided to have separate types.
///
/// The values for all three response code types are defined in
/// the [IANA DNS RCODEs] registry. This type is complete as of 2019-01-28.
///
/// The 12-bit extended RCODE defined by [RFC 6891] stores the lowest 4-bits
/// of the extended RCODE in the main DNS header RCODE field and stores the
/// remaining 8-bits (right shifted by 4-bits) in the OPT record header RCODE
/// field, like so:
///
/// ```text
/// NoError:    0 = 0b0000_0000_0000
///                             ^^^^ Stored in DNS header RCODE field
///                   ^^^^_^^^^      Stored in OPT header RCODE field
///
/// FormErr:    1 = 0b0000_0000_0001
///                             ^^^^ Stored in DNS header RCODE field
///                   ^^^^_^^^^      Stored in OPT header RCODE field
///
/// BadVers:   16 = 0b0000_0001_0000
///                             ^^^^ Stored in DNS header RCODE field
///                   ^^^^_^^^^      Stored in OPT header RCODE field
///
/// BadCookie: 23 = 0b0000_0001_0111
///                             ^^^^ Stored in DNS header RCODE field
///                   ^^^^_^^^^      Stored in OPT header RCODE field
/// ```
///
/// This type offers several functions to ease working with the separate parts
/// and the combined value of an extended RCODE:
///
/// - [`OptRcode::rcode()`]: the RFC 1035 header RCODE part.
/// - [`OptRcode::ext()`]`: the RFC 6891 ENDS OPT extended RCODE part.
/// - [`OptRcode::to_parts()`]`: to access both parts at once.
/// - [`OptRcode::to_int()`]`: the IANA number for the RCODE combining both
///   parts.
///
/// [Rcode]: enum.Rcode.html
/// [`TsigRcode`]: enum.TsigRcode.html
/// [IANA DNS RCODEs]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
/// [RFC 2845]: https://tools.ietf.org/html/rfc2845
/// [RFC 2930]: https://tools.ietf.org/html/rfc2930
/// [RFC 6891]: https://tools.ietf.org/html/rfc6891
#[derive(Clone, Copy, Debug)]
pub enum OptRcode {
    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NoError,

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    FormErr,

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    ServFail,

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NXDomain,

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    NotImp,

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    Refused,

    /// Name exists when it should not.
    ///
    /// Returned for an UPDATE query when a domain requested to not exist
    /// does in fact exist.
    ///
    /// Returned when resolving a DNAME redirection when the resulting name
    /// exceeds the length of 255 octets.
    ///
    /// Defined in [RFC 2136] for the UPDATE query and [RFC 6672] for DNAME
    /// redirection.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 6672]: https://tools.ietf.org/html/rfc6672
    YXDomain,

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    YXRRSet,

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    NXRRSet,

    /// Server not authoritative for zone or client not authorized.
    ///
    /// Returned for an UPDATE query when the server is not an authoritative
    /// name server for the requested domain.
    ///
    /// Returned for queries using TSIG when authorisation failed.
    ///
    /// Defined in [RFC 2136] for UPDATE and [RFC 2845] for TSIG.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    NotAuth,

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    NotZone,

    /// Bad OPT version.
    ///
    /// A name server does not implement the EDNS version requested in the
    /// OPT record.
    ///
    /// Defined in [RFC 6891].
    ///
    /// [RFC 6891]: https://tools.ietf.org/html/rfc6891
    BadVers,

    // XXX We will not define the values from the TSIG and TKEY RFCs,
    //     unless are used in OPT records, too?
    /// Bad or missing server cookie.
    ///
    /// The request contained a COOKIE option either without a server cookie
    /// or with a server cookie that did not validate.
    ///
    /// Defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    BadCookie,

    /// A raw, integer rcode value.
    ///
    /// When converting to a 12 bit code, the upper four bits are simply
    /// ignored.
    Int(u16),
}

impl OptRcode {
    /// Creates an rcode from an integer.
    ///
    /// Only the lower twelve bits of `value` are considered.
    #[must_use]
    pub fn from_int(value: u16) -> OptRcode {
        use self::OptRcode::*;

        match value & 0x0FFF {
            0 => NoError,
            1 => FormErr,
            2 => ServFail,
            3 => NXDomain,
            4 => NotImp,
            5 => Refused,
            6 => YXDomain,
            7 => YXRRSet,
            8 => NXRRSet,
            9 => NotAuth,
            10 => NotZone,
            16 => BadVers,
            23 => BadCookie,
            value => Int(value),
        }
    }

    /// Returns the integer value for this rcode.
    ///
    /// Only the lower 12 bits of the returned octet are used by the rcode.
    /// The upper four bits are always zero.
    #[must_use]
    pub fn to_int(self) -> u16 {
        use self::OptRcode::*;

        match self {
            NoError => 0,
            FormErr => 1,
            ServFail => 2,
            NXDomain => 3,
            NotImp => 4,
            Refused => 5,
            YXDomain => 6,
            YXRRSet => 7,
            NXRRSet => 8,
            NotAuth => 9,
            NotZone => 10,
            BadVers => 16,
            BadCookie => 23,
            Int(value) => value & 0x0FFF,
        }
    }

    /// Creates an extended rcode value from its parts.
    #[must_use]
    pub fn from_parts(rcode: Rcode, ext: u8) -> OptRcode {
        OptRcode::from_int(u16::from(ext) << 4 | u16::from(rcode.to_int()))
    }

    /// Returns the two parts of an extended rcode value.
    #[must_use]
    pub fn to_parts(self) -> (Rcode, u8) {
        let res = self.to_int();
        (Rcode::from_int(res as u8), (res >> 4) as u8)
    }

    /// Returns the rcode part of the extended rcode.
    #[must_use]
    pub fn rcode(self) -> Rcode {
        self.to_parts().0
    }

    /// Returns the extended octet of the extended rcode.
    #[must_use]
    pub fn ext(self) -> u8 {
        self.to_parts().1
    }
}

//--- From

impl From<u16> for OptRcode {
    fn from(value: u16) -> OptRcode {
        OptRcode::from_int(value)
    }
}

impl From<OptRcode> for u16 {
    fn from(value: OptRcode) -> u16 {
        value.to_int()
    }
}

impl From<Rcode> for OptRcode {
    fn from(value: Rcode) -> OptRcode {
        OptRcode::from_parts(value, 0)
    }
}

//--- Display

impl fmt::Display for OptRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::OptRcode::*;

        match *self {
            NoError => "NOERROR".fmt(f),
            FormErr => "FORMERR".fmt(f),
            ServFail => "SERVFAIL".fmt(f),
            NXDomain => "NXDOMAIN".fmt(f),
            NotImp => "NOTIMP".fmt(f),
            Refused => "REFUSED".fmt(f),
            YXDomain => "YXDOMAIN".fmt(f),
            YXRRSet => "YXRRSET".fmt(f),
            NXRRSet => "NXRRSET".fmt(f),
            NotAuth => "NOAUTH".fmt(f),
            NotZone => "NOTZONE".fmt(f),
            BadVers => "BADVER".fmt(f),
            BadCookie => "BADCOOKIE".fmt(f),
            Int(i) => match OptRcode::from_int(i) {
                Int(i) => i.fmt(f),
                value => value.fmt(f),
            },
        }
    }
}

//------------ TsigRcode ----------------------------------------------------

int_enum! {
    /// Response codes for transaction authentication (TSIG).
    ///
    /// TSIG and TKEY resource records contain a 16 bit wide error field whose
    /// values are an extension of the standard DNS [`Rcode`]. While it was
    /// intended to also share the same space with the extended response codes
    /// used by EDNS (see [`OptRcode`]), both used the value 16. To allow
    /// distinguish between the two uses of this value, we have two separate
    /// types.
    ///
    /// The values for all three response code types are defined in
    /// the [IANA DNS RCODEs] registry. This type is complete as of 2019-01-28.
    ///
    /// [`Rcode`]: enum.Rcode.html
    /// [`OptRcode`]: enum.OptRcode.html
    /// [IANA DNS RCODEs]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
    =>
    TsigRcode, u16;

    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (NoError => 0, b"NOERROR")

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (FormErr => 1, b"FORMERR")

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (ServFail => 2, b"SERVFAIL")

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (NXDomain => 3, b"NXDOMAIN")

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (NotImp => 4, b"NOTIMPL")

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (Refused => 5, b"REFUSED")

    /// Name exists when it should not.
    ///
    /// Returned for an UPDATE query when a domain requested to not exist
    /// does in fact exist.
    ///
    /// Returned when resolving a DNAME redirection when the resulting name
    /// exceeds the length of 255 octets.
    ///
    /// Defined in [RFC 2136] for the UPDATE query and [RFC 6672] for DNAME
    /// redirection.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 6672]: https://tools.ietf.org/html/rfc6672
    (YXDomain => 6, b"YXDOMAIN")

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (YXRRSet => 7, b"YXRRSET")

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (NXRRSet => 8, b"NXRRSET")

    /// Server not authoritative for zone or client not authorized.
    ///
    /// Returned for an UPDATE query when the server is not an authoritative
    /// name server for the requested domain.
    ///
    /// Returned for queries using TSIG when authorisation failed.
    ///
    /// Defined in [RFC 2136] for UPDATE and [RFC 2845] for TSIG.
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (NotAuth => 9, b"NOTAUTH")

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (NotZone => 10, b"NOTZONE")

    /// TSIG signature failure.
    ///
    /// The TSIG signature fails to verify.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BadSig => 16, b"BADSIG")

    /// Key not recognized.
    ///
    /// The server did not recognize the key used for generating the
    /// signature.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BadKey => 17, b"BADKEY")

    /// Signature out of time window.
    ///
    /// The server time was outside the time interval specified by the
    /// request.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BadTime => 18, b"BADTIME")

    /// Bad TKEY mode.
    ///
    /// The mode field in a TKEY resource record contained a mode not
    /// supported by the server.
    ///
    /// Defined in [RFC 2930].
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BadMode => 19, b"BADMODE")

    /// Duplicate key name.
    ///
    /// In TKEY records, when establishing a new key, the name used already
    /// exists at the server or when deleting a key, a key of this name does
    /// not exist.
    ///
    /// Defined in [RFC 2930].
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BadName => 20, b"BADNAME")

    /// Algorithm not supported.
    ///
    /// The value is defined in [RFC 2930] but never actually explained.
    /// Presumably, it will be returned when the algorithm field of a TKEY
    /// record contains a value not supported by the server.
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BadAlg => 21, b"BADALG")

    /// Bad truncation.
    ///
    /// A TSIG record was received with a MAC too short for the local
    /// policy in force.
    ///
    /// Defined in [RFC 4635].
    ///
    /// [RFC 4635]: https://tools.ietf.org/html/rfc4635
    (BadTrunc => 22, b"BADTRUNC")

    /// Bad or missing server cookie.
    ///
    /// The request contained a COOKIE option either without a server cookie
    /// or with a server cookie that did not validate.
    ///
    /// Defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    (BadCookie => 23, b"BADCOOKIE")
}

//--- From

impl From<Rcode> for TsigRcode {
    fn from(value: Rcode) -> TsigRcode {
        TsigRcode::from_int(u16::from(value.to_int()))
    }
}

impl From<OptRcode> for TsigRcode {
    fn from(value: OptRcode) -> TsigRcode {
        TsigRcode::from_int(value.to_int())
    }
}

int_enum_str_with_decimal!(TsigRcode, u16, "unknown TSIG error");

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn optrcode_parts() {
        // Define a macro to test the various functions involved in working
        // with RFC 6891 extended RCODEs. Given an OPT RCODE enum variant,
        // check if the functions produce the expected high bit, low bit and
        // combined values.
        macro_rules! assert_opt_rcode_parts_eq {
            ($name:expr, $high_bits:expr, $low_bits:expr) => {
                let u12 = (($high_bits as u16) << 4) | ($low_bits as u16);
                assert_eq!($name.rcode().to_int(), $low_bits);
                assert_eq!($name.ext(), $high_bits);
                assert_eq!($name.to_parts().0.to_int(), $low_bits);
                assert_eq!($name.to_parts().1, $high_bits);
                assert_eq!($name.to_int(), u12);
            };
        }

        // Test RFC 1035 Rcode enum variants that domain defines, plus any
        // boundary cases not included in that set.
        assert_eq!(Rcode::NoError, 0b0000);
        assert_eq!(Rcode::FormErr, 0b0001);
        assert_eq!(Rcode::ServFail, 0b0010);
        assert_eq!(Rcode::NXDomain, 0b0011);
        assert_eq!(Rcode::NotImp, 0b0100);
        assert_eq!(Rcode::Refused, 0b0101);
        assert_eq!(Rcode::YXDomain, 0b0110);
        assert_eq!(Rcode::YXRRSet, 0b0111);
        assert_eq!(Rcode::NXRRSet, 0b1000);
        assert_eq!(Rcode::NotAuth, 0b1001);
        assert_eq!(Rcode::NotZone, 0b1010);
        assert_eq!(Rcode::Int(14), 0b1110);
        assert_eq!(Rcode::Int(15), 0b1111);

        // Test RFC 6891 OptRcode enum variants that domain defines, plus any
        // boundary cases not included in that set:
        assert_opt_rcode_parts_eq!(OptRcode::NoError, 0b000_0000, 0b0000);
        assert_opt_rcode_parts_eq!(OptRcode::FormErr, 0b000_0000, 0b0001);
        assert_opt_rcode_parts_eq!(OptRcode::ServFail, 0b000_0000, 0b0010);
        assert_opt_rcode_parts_eq!(OptRcode::NXDomain, 0b000_0000, 0b0011);
        assert_opt_rcode_parts_eq!(OptRcode::NotImp, 0b000_0000, 0b0100);
        assert_opt_rcode_parts_eq!(OptRcode::Refused, 0b000_0000, 0b0101);
        assert_opt_rcode_parts_eq!(OptRcode::YXDomain, 0b000_0000, 0b0110);
        assert_opt_rcode_parts_eq!(OptRcode::YXRRSet, 0b000_0000, 0b0111);
        assert_opt_rcode_parts_eq!(OptRcode::NXRRSet, 0b000_0000, 0b1000);
        assert_opt_rcode_parts_eq!(OptRcode::NotAuth, 0b000_0000, 0b1001);
        assert_opt_rcode_parts_eq!(OptRcode::NotZone, 0b000_0000, 0b1010);
        assert_opt_rcode_parts_eq!(OptRcode::Int(15), 0b0000_0000, 0b1111);
        assert_opt_rcode_parts_eq!(OptRcode::BadVers, 0b0000_0001, 0b0000);
        assert_opt_rcode_parts_eq!(OptRcode::Int(17), 0b0000_0001, 0b0001);
        assert_opt_rcode_parts_eq!(OptRcode::BadCookie, 0b000_0001, 0b0111);
        assert_opt_rcode_parts_eq!(OptRcode::Int(4094), 0b1111_1111, 0b1110);
        assert_opt_rcode_parts_eq!(OptRcode::Int(4095), 0b1111_1111, 0b1111);
    }
}
