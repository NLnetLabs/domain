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
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035
//! [RFC 2671]: https://tools.ietf.org/html/rfc2671
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845
//! [RFC 2930]: https://tools.ietf.org/html/rfc2930
//! [RFC 6891]: https://tools.ietf.org/html/rfc6891

//  Note: Rcode and OptRcode don’t use the macros since they don’t use all the
//  bits of the wrapped integer.

use core::fmt;
use core::str::FromStr;

//------------ Rcode ---------------------------------------------------------

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
/// [IANA DNS RCODEs]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Rcode(u8);

impl Rcode {
    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NOERROR: Self = Self(0);

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const FORMERR: Self = Self(1);

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const SERVFAIL: Self = Self(2);

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NXDOMAIN: Self = Self(3);

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NOTIMP: Self = Self(4);

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const REFUSED: Self = Self(5);

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
    pub const YXDOMAIN: Self = Self(6);

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const YXRRSET: Self = Self(7);

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const NXRRSET: Self = Self(8);

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
    pub const NOTAUTH: Self = Self(9);

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const NOTZONE: Self = Self(10);
}

impl Rcode {
    /// Creates an rcode from an integer, returning `None` if invalid.
    ///
    /// The rcode is valid if the upper four bits of `value` are all zero.
    #[must_use]
    pub const fn checked_from_int(value: u8) -> Option<Self> {
        if value & 0xF0 != 0 {
            None
        } else {
            Some(Rcode(value))
        }
    }

    /// Creates an rcode from an integer, only considering the lower four bits.
    ///
    /// This function will ignore the upper four bit of `value`.
    #[must_use]
    pub const fn masked_from_int(value: u8) -> Self {
        Rcode(value & 0x0F)
    }

    /// Returns the integer value for this rcode.
    ///
    /// Only the lower 4 bits of the returned octet are used by the rcode. The
    /// upper four bits are always zero.
    #[must_use]
    pub const fn to_int(self) -> u8 {
        self.0
    }

    /// Returns the mnemonic for this value if there is one.
    #[must_use]
    pub const fn to_mnemonic(self) -> Option<&'static [u8]> {
        match self {
            Rcode::NOERROR => Some(b"NOERROR"),
            Rcode::FORMERR => Some(b"FORMERR"),
            Rcode::SERVFAIL => Some(b"SERVFAIL"),
            Rcode::NXDOMAIN => Some(b"NXDOMAIN"),
            Rcode::NOTIMP => Some(b"NOTIMP"),
            Rcode::REFUSED => Some(b"REFUSED"),
            Rcode::YXDOMAIN => Some(b"YXDOMAIN"),
            Rcode::YXRRSET => Some(b"YXRRSET"),
            Rcode::NXRRSET => Some(b"NXRRSET"),
            Rcode::NOTAUTH => Some(b"NOTAUTH"),
            Rcode::NOTZONE => Some(b"NOTZONE"),
            _ => None,
        }
    }
}

//--- FromStr

impl FromStr for Rcode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NOERROR" => Ok(Rcode::NOERROR),
            "FORMERR" => Ok(Rcode::FORMERR),
            "SERVFAIL" => Ok(Rcode::SERVFAIL),
            "NXDOMAIN" => Ok(Rcode::NXDOMAIN),
            "NOTIMP" => Ok(Rcode::NOTIMP),
            "REFUSED" => Ok(Rcode::REFUSED),
            "YXDOMAIN" => Ok(Rcode::YXDOMAIN),
            "YXRRSET" => Ok(Rcode::YXRRSET),
            "NXRRSET" => Ok(Rcode::NXRRSET),
            "NOTAUTH" => Ok(Rcode::NOTAUTH),
            "NOTZONE" => Ok(Rcode::NOTZONE),
            _ => Err(()),
        }
    }
}

//--- TryFrom and From

impl TryFrom<u8> for Rcode {
    type Error = InvalidRcode;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Rcode::checked_from_int(value).ok_or(InvalidRcode(()))
    }
}

impl From<Rcode> for u8 {
    fn from(value: Rcode) -> u8 {
        value.to_int()
    }
}

//--- Display and Debug

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self
            .to_mnemonic()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
        {
            Some(mnemonic) => f.write_str(mnemonic),
            None => self.0.fmt(f),
        }
    }
}

impl fmt::Debug for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self
            .to_mnemonic()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
        {
            Some(mnemonic) => write!(f, "Rcode::{}", mnemonic),
            None => f.debug_tuple("Rcode").field(&self.0).finish(),
        }
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
        u8::deserialize(deserializer).and_then(|code| {
            Rcode::try_from(code).map_err(serde::de::Error::custom)
        })
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
/// - [`OptRcode::rcode`]: the RFC 1035 header RCODE part.
/// - [`OptRcode::ext`]`: the RFC 6891 ENDS OPT extended RCODE part.
/// - [`OptRcode::to_parts`]`: to access both parts at once.
/// - [`OptRcode::to_int`]`: the IANA number for the RCODE combining both
///   parts.
///
/// [IANA DNS RCODEs]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
/// [RFC 2845]: https://tools.ietf.org/html/rfc2845
/// [RFC 2930]: https://tools.ietf.org/html/rfc2930
/// [RFC 6891]: https://tools.ietf.org/html/rfc6891
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OptRcode(u16);

impl OptRcode {
    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NOERROR: Self = Self::from_rcode(Rcode::NOERROR);

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const FORMERR: Self = Self::from_rcode(Rcode::FORMERR);

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const SERVFAIL: Self = Self::from_rcode(Rcode::SERVFAIL);

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NXDOMAIN: Self = Self::from_rcode(Rcode::NXDOMAIN);

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const NOTIMP: Self = Self::from_rcode(Rcode::NOTIMP);

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    pub const REFUSED: Self = Self::from_rcode(Rcode::REFUSED);

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
    pub const YXDOMAIN: Self = Self::from_rcode(Rcode::YXDOMAIN);

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const YXRRSET: Self = Self::from_rcode(Rcode::YXRRSET);

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const NXRRSET: Self = Self::from_rcode(Rcode::NXRRSET);

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
    pub const NOTAUTH: Self = Self::from_rcode(Rcode::NOTAUTH);

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    pub const NOTZONE: Self = Self::from_rcode(Rcode::NOTZONE);

    /// Bad OPT version.
    ///
    /// A name server does not implement the EDNS version requested in the
    /// OPT record.
    ///
    /// Defined in [RFC 6891].
    ///
    /// [RFC 6891]: https://tools.ietf.org/html/rfc6891
    pub const BADVERS: Self = Self(16);

    // XXX We will not define the values from the TSIG and TKEY RFCs,
    //     unless they are used in OPT records, too?
    /// Bad or missing server cookie.
    ///
    /// The request contained a COOKIE option either without a server cookie
    /// or with a server cookie that did not validate.
    ///
    /// Defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    pub const BADCOOKIE: Self = Self(23);
}

impl OptRcode {
    /// Creates an rcode from an integer, returning `None` if invalid.
    ///
    /// The rcode is valid if the upper four bits of `value` are all zero.
    #[must_use]
    pub const fn checked_from_int(value: u16) -> Option<OptRcode> {
        if value & 0x0FFF != 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Creates an rcode from an integer, only considering the lower four bits.
    ///
    /// This function will ignore the upper four bit of `value`.
    #[must_use]
    pub const fn masked_from_int(value: u16) -> OptRcode {
        Self(value & 0x0FFF)
    }

    /// Creates an OPT rcode from a plain rcode.
    #[must_use]
    pub const fn from_rcode(rcode: Rcode) -> Self {
        Self(rcode.0 as u16)
    }

    /// Returns the integer value for this rcode.
    ///
    /// Only the lower 12 bits of the returned octet are used by the rcode.
    /// The upper four bits are always zero.
    #[must_use]
    pub const fn to_int(self) -> u16 {
        self.0
    }

    /// Creates an extended rcode value from its parts.
    #[must_use]
    pub fn from_parts(rcode: Rcode, ext: u8) -> OptRcode {
        OptRcode(u16::from(ext) << 4 | u16::from(rcode.to_int()))
    }

    /// Returns the two parts of an extended rcode value.
    #[must_use]
    pub fn to_parts(self) -> (Rcode, u8) {
        (Rcode::masked_from_int(self.0 as u8), (self.0 >> 4) as u8)
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

    /// Returns true if the RCODE is extended, false otherwise.
    #[must_use]
    pub fn is_ext(&self) -> bool {
        // https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
        // 6.1.3. OPT Record TTL Field Use
        //   ...
        //   "EXTENDED-RCODE
        //       Forms the upper 8 bits of extended 12-bit RCODE (together
        //       with the 4 bits defined in [RFC1035].  Note that
        //       EXTENDED-RCODE value 0 indicates that an unextended RCODE is
        //       in use (values 0 through 15)."
        self.0 >> 4 != 0
    }

    /// Returns the mnemonic for this value if there is one.
    #[must_use]
    pub const fn to_mnemonic(self) -> Option<&'static [u8]> {
        match self {
            OptRcode::NOERROR => Some(b"NOERROR"),
            OptRcode::FORMERR => Some(b"FORMERR"),
            OptRcode::SERVFAIL => Some(b"SERVFAIL"),
            OptRcode::NXDOMAIN => Some(b"NXDOMAIN"),
            OptRcode::NOTIMP => Some(b"NOTIMP"),
            OptRcode::REFUSED => Some(b"REFUSED"),
            OptRcode::YXDOMAIN => Some(b"YXDOMAIN"),
            OptRcode::YXRRSET => Some(b"YXRRSET"),
            OptRcode::NXRRSET => Some(b"NXRRSET"),
            OptRcode::NOTAUTH => Some(b"NOTAUTH"),
            OptRcode::NOTZONE => Some(b"NOTZONE"),
            OptRcode::BADVERS => Some(b"BADVERS"),
            OptRcode::BADCOOKIE => Some(b"BADCOOKIE"),
            _ => None,
        }
    }
}

//--- FromStr

impl FromStr for OptRcode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NOERROR" => Ok(OptRcode::NOERROR),
            "FORMERR" => Ok(OptRcode::FORMERR),
            "SERVFAIL" => Ok(OptRcode::SERVFAIL),
            "NXDOMAIN" => Ok(OptRcode::NXDOMAIN),
            "NOTIMP" => Ok(OptRcode::NOTIMP),
            "REFUSED" => Ok(OptRcode::REFUSED),
            "YXDOMAIN" => Ok(OptRcode::YXDOMAIN),
            "YXRRSET" => Ok(OptRcode::YXRRSET),
            "NXRRSET" => Ok(OptRcode::NXRRSET),
            "NOTAUTH" => Ok(OptRcode::NOTAUTH),
            "NOTZONE" => Ok(OptRcode::NOTZONE),
            "BADVERS" => Ok(OptRcode::BADVERS),
            "BADCOOKIE" => Ok(OptRcode::BADCOOKIE),
            _ => Err(()),
        }
    }
}

//--- TryFrom and From

impl TryFrom<u16> for OptRcode {
    type Error = InvalidRcode;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        OptRcode::checked_from_int(value).ok_or(InvalidRcode(()))
    }
}

impl From<OptRcode> for u16 {
    fn from(value: OptRcode) -> u16 {
        value.to_int()
    }
}

impl From<Rcode> for OptRcode {
    fn from(value: Rcode) -> OptRcode {
        OptRcode::from_rcode(value)
    }
}

//--- Display and Debug

impl fmt::Display for OptRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self
            .to_mnemonic()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
        {
            Some(mnemonic) => f.write_str(mnemonic),
            None => self.0.fmt(f),
        }
    }
}

impl fmt::Debug for OptRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self
            .to_mnemonic()
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
        {
            Some(mnemonic) => write!(f, "Rcode::{}", mnemonic),
            None => f.debug_tuple("Rcode").field(&self.0).finish(),
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
    (NOERROR => 0, b"NOERROR")

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (FORMERR => 1, b"FORMERR")

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (SERVFAIL => 2, b"SERVFAIL")

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (NXDOMAIN => 3, b"NXDOMAIN")

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (NOTIMP => 4, b"NOTIMPL")

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in [RFC 1035].
    ///
    /// [RFC 1035]: https://tools.ietf.org/html/rfc1035
    (REFUSED => 5, b"REFUSED")

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
    (YXDOMAIN => 6, b"YXDOMAIN")

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (YXRRSET => 7, b"YXRRSET")

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (NXRRSET => 8, b"NXRRSET")

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
    (NOTAUTH => 9, b"NOTAUTH")

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in [RFC 2136].
    ///
    /// [RFC 2136]: https://tools.ietf.org/html/rfc2136
    (NOTZONE => 10, b"NOTZONE")

    /// TSIG signature failure.
    ///
    /// The TSIG signature fails to verify.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BADSIG => 16, b"BADSIG")

    /// Key not recognized.
    ///
    /// The server did not recognize the key used for generating the
    /// signature.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BADKEY => 17, b"BADKEY")

    /// Signature out of time window.
    ///
    /// The server time was outside the time interval specified by the
    /// request.
    ///
    /// Defined in [RFC 2845].
    ///
    /// [RFC 2845]: https://tools.ietf.org/html/rfc2845
    (BADTIME => 18, b"BADTIME")

    /// Bad TKEY mode.
    ///
    /// The mode field in a TKEY resource record contained a mode not
    /// supported by the server.
    ///
    /// Defined in [RFC 2930].
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BADMODE => 19, b"BADMODE")

    /// Duplicate key name.
    ///
    /// In TKEY records, when establishing a new key, the name used already
    /// exists at the server or when deleting a key, a key of this name does
    /// not exist.
    ///
    /// Defined in [RFC 2930].
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BADNAME => 20, b"BADNAME")

    /// Algorithm not supported.
    ///
    /// The value is defined in [RFC 2930] but never actually explained.
    /// Presumably, it will be returned when the algorithm field of a TKEY
    /// record contains a value not supported by the server.
    ///
    /// [RFC 2930]: https://tools.ietf.org/html/rfc2930
    (BADALG => 21, b"BADALG")

    /// Bad truncation.
    ///
    /// A TSIG record was received with a MAC too short for the local
    /// policy in force.
    ///
    /// Defined in [RFC 4635].
    ///
    /// [RFC 4635]: https://tools.ietf.org/html/rfc4635
    (BADTRUNC => 22, b"BADTRUNC")

    /// Bad or missing server cookie.
    ///
    /// The request contained a COOKIE option either without a server cookie
    /// or with a server cookie that did not validate.
    ///
    /// Defined in [RFC 7873].
    ///
    /// [RFC 7873]: https://tools.ietf.org/html/rfc7873
    (BADCOOKIE => 23, b"BADCOOKIE")
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

//============ Error Types ===================================================

/// An integer couldn’t be converted into an rcode.
#[derive(Clone, Copy, Debug)]
pub struct InvalidRcode(());

impl fmt::Display for InvalidRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid rcode value")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidRcode {}

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

        // Test RFC 6891 OptRcode enum variants that domain defines, plus any
        // boundary cases not included in that set:
        assert_opt_rcode_parts_eq!(OptRcode::NOERROR, 0b000_0000, 0b0000);
        assert_opt_rcode_parts_eq!(OptRcode::FORMERR, 0b000_0000, 0b0001);
        assert_opt_rcode_parts_eq!(OptRcode::SERVFAIL, 0b000_0000, 0b0010);
        assert_opt_rcode_parts_eq!(OptRcode::NXDOMAIN, 0b000_0000, 0b0011);
        assert_opt_rcode_parts_eq!(OptRcode::NOTIMP, 0b000_0000, 0b0100);
        assert_opt_rcode_parts_eq!(OptRcode::REFUSED, 0b000_0000, 0b0101);
        assert_opt_rcode_parts_eq!(OptRcode::YXDOMAIN, 0b000_0000, 0b0110);
        assert_opt_rcode_parts_eq!(OptRcode::YXRRSET, 0b000_0000, 0b0111);
        assert_opt_rcode_parts_eq!(OptRcode::NXRRSET, 0b000_0000, 0b1000);
        assert_opt_rcode_parts_eq!(OptRcode::NOTAUTH, 0b000_0000, 0b1001);
        assert_opt_rcode_parts_eq!(OptRcode::NOTZONE, 0b000_0000, 0b1010);
        assert_opt_rcode_parts_eq!(OptRcode(15), 0b0000_0000, 0b1111);
        assert_opt_rcode_parts_eq!(OptRcode::BADVERS, 0b0000_0001, 0b0000);
        assert_opt_rcode_parts_eq!(OptRcode(17), 0b0000_0001, 0b0001);
        assert_opt_rcode_parts_eq!(OptRcode::BADCOOKIE, 0b000_0001, 0b0111);
        assert_opt_rcode_parts_eq!(OptRcode(4094), 0b1111_1111, 0b1110);
        assert_opt_rcode_parts_eq!(OptRcode(4095), 0b1111_1111, 0b1111);
    }

    #[test]
    fn rcode_fromstr() {
        assert_eq!(Ok(Rcode::NOERROR), "NOERROR".parse());
        assert_eq!(Ok(Rcode::FORMERR), "FORMERR".parse());
        assert_eq!(Ok(Rcode::SERVFAIL), "SERVFAIL".parse());
        assert_eq!(Ok(Rcode::NXDOMAIN), "NXDOMAIN".parse());
        assert_eq!(Ok(Rcode::NOTIMP), "NOTIMP".parse());
        assert_eq!(Ok(Rcode::REFUSED), "REFUSED".parse());
        assert_eq!(Ok(Rcode::YXDOMAIN), "YXDOMAIN".parse());
        assert_eq!(Ok(Rcode::YXRRSET), "YXRRSET".parse());
        assert_eq!(Ok(Rcode::NXRRSET), "NXRRSET".parse());
        assert_eq!(Ok(Rcode::NOTAUTH), "NOTAUTH".parse());
        assert_eq!(Ok(Rcode::NOTZONE), "NOTZONE".parse());
        assert!("#$%!@".parse::<Rcode>().is_err());
    }

    #[test]
    fn optrcode_fromstr() {
        assert_eq!(Ok(OptRcode::NOERROR), "NOERROR".parse());
        assert_eq!(Ok(OptRcode::FORMERR), "FORMERR".parse());
        assert_eq!(Ok(OptRcode::SERVFAIL), "SERVFAIL".parse());
        assert_eq!(Ok(OptRcode::NXDOMAIN), "NXDOMAIN".parse());
        assert_eq!(Ok(OptRcode::NOTIMP), "NOTIMP".parse());
        assert_eq!(Ok(OptRcode::REFUSED), "REFUSED".parse());
        assert_eq!(Ok(OptRcode::YXDOMAIN), "YXDOMAIN".parse());
        assert_eq!(Ok(OptRcode::YXRRSET), "YXRRSET".parse());
        assert_eq!(Ok(OptRcode::NXRRSET), "NXRRSET".parse());
        assert_eq!(Ok(OptRcode::NOTAUTH), "NOTAUTH".parse());
        assert_eq!(Ok(OptRcode::NOTZONE), "NOTZONE".parse());
        assert_eq!(Ok(OptRcode::BADVERS), "BADVERS".parse());
        assert_eq!(Ok(OptRcode::BADCOOKIE), "BADCOOKIE".parse());
        assert!("#$%!@".parse::<Rcode>().is_err());
    }

    #[test]
    fn optrcode_isext() {
        assert!(!OptRcode::NOERROR.is_ext());
        assert!(!OptRcode::FORMERR.is_ext());
        assert!(!OptRcode::SERVFAIL.is_ext());
        assert!(!OptRcode::NXDOMAIN.is_ext());
        assert!(!OptRcode::NOTIMP.is_ext());
        assert!(!OptRcode::REFUSED.is_ext());
        assert!(!OptRcode::YXDOMAIN.is_ext());
        assert!(!OptRcode::YXRRSET.is_ext());
        assert!(!OptRcode::NXRRSET.is_ext());
        assert!(!OptRcode::NOTAUTH.is_ext());
        assert!(!OptRcode::NOTZONE.is_ext());
        assert!(OptRcode::BADVERS.is_ext());
        assert!(OptRcode::BADCOOKIE.is_ext());
    }
}
