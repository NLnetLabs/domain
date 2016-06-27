//! DNS RCODEs.

use std::cmp;
use std::convert;
use std::fmt;
use std::hash;


/// DNS RCODEs.
///
/// The response code of a response indicates what happend on the server
/// when trying to answer the query. The code is a 4 bit value.
///
/// See RFC 1035 for response codes in general and 
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
/// for all currently assigned values. Not that this registry shows a 16
/// bit response code. This is because it includes codes used in the TSIG,
/// TKEY, and OPT resource records as well. We will define separate types
/// for these.
#[derive(Clone, Copy, Debug)]
pub enum Rcode {
    /// No error condition.
    ///
    /// (Otherwise known as success.)
    ///
    /// Defined in RFC1035.
    NoError,

    /// Format error.
    ///
    /// The name server was unable to interpret the query.
    ///
    /// Defined in RFC 1035.
    FormErr,

    /// Server failure.
    ///
    /// The name server was unable to process this query due to a problem
    /// with the name server.
    ///
    /// Defined in RFC 1035.
    ServFail,

    /// Name error.
    ///
    /// The domain name given in the query does not exist at the name server.
    ///
    /// Defined in RFC 1035.
    NXDomain,

    /// Not implemented.
    ///
    /// The name server does not support the requested kind of query.
    ///
    /// Defined in RFC 1035.
    NotImp,

    /// Query refused.
    ///
    /// The name server refused to perform the operation requested by the
    /// query for policy reasons.
    ///
    /// Defined in RFC 1035.
    Refused,

    /// Name exists when it should not.
    ///
    /// Returned for an UPDATE query when a domain requested to not exist
    /// does in fact exist.
    ///
    /// Defined in RFC 2136.
    YXDomain,

    /// RR set exists when it should not.
    ///
    /// Returned for an UPDATE query when an RRset requested to not exist
    /// does in fact exist.
    ///
    /// Defined in RFC 2136.
    YXRRSet,

    /// RR set that should exist does not.
    ///
    /// Returned for an UPDATE query when an RRset requested to exist
    /// does not.
    ///
    /// Defined in RFC 2136.
    NXRRSet,

    /// Server not authoritative for zone [RFC2136] or not authorized [RFC2845]
    ///
    /// Returned for an UPDATE query when the server is not an authoritative
    /// name server for the requested domain.
    ///
    /// Returned for queries using TSIG when authorisation failed.
    ///
    /// Defined in RFC 2136 for UPDATE and RFC 2845 for TSIG.
    NotAuth,

    /// Name not contained in zone.
    ///
    /// A name used in the prerequisite or update section is not within the
    /// zone given in the zone section.
    ///
    /// Defined in RFC 2136.
    NotZone,

    /// A raw, integer rcode value.
    ///
    /// When converting to an `u8`, only the lower four bits are used.
    Int(u8)
}

impl Rcode {
    /// Creates an rcode from an integer.
    ///
    /// Only the lower four bits of `value` are considered.
    pub fn from_int(value: u8) -> Rcode {
        match value & 0x0F {
            0 => Rcode::NoError,
            1 => Rcode::FormErr,
            2 => Rcode::ServFail,
            3 => Rcode::NXDomain,
            4 => Rcode::NotImp,
            5 => Rcode::Refused,
            6 => Rcode::YXDomain,
            7 => Rcode::YXRRSet,
            8 => Rcode::NXRRSet,
            9 => Rcode::NotAuth,
            10 => Rcode::NotZone,
            value @ _ => Rcode::Int(value)
        }
    }

    /// Returns the integer value for this rcode.
    pub fn to_int(self) -> u8 {
        match self {
            Rcode::NoError => 0,
            Rcode::FormErr => 1,
            Rcode::ServFail => 2,
            Rcode::NXDomain => 3,
            Rcode::NotImp => 4,
            Rcode::Refused => 5,
            Rcode::YXDomain => 6,
            Rcode::YXRRSet => 7,
            Rcode::NXRRSet => 8,
            Rcode::NotAuth => 9,
            Rcode::NotZone => 10,
            Rcode::Int(value) => value & 0x0F
        }
    }
}


//--- From

impl convert::From<u8> for Rcode {
    fn from(value: u8) -> Rcode { Rcode::from_int(value) }
}

impl convert::From<Rcode> for u8 {
    fn from(value: Rcode) -> u8 { Rcode::to_int(value) }
}


//--- Display

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Rcode::NoError => "NOERROR".fmt(f),
            Rcode::FormErr => "FORMERR".fmt(f),
            Rcode::ServFail => "SERVFAIL".fmt(f),
            Rcode::NXDomain => "NXDOMAIN".fmt(f),
            Rcode::NotImp => "NOTIMP".fmt(f),
            Rcode::Refused => "REFUSED".fmt(f),
            Rcode::YXDomain => "YXDOMAIN".fmt(f),
            Rcode::YXRRSet => "YXRRSET".fmt(f),
            Rcode::NXRRSet => "NXRRSET".fmt(f),
            Rcode::NotAuth => "NOAUTH".fmt(f),
            Rcode::NotZone => "NOTZONE".fmt(f),
            Rcode::Int(i) => {
                match Rcode::from_int(i) {
                    Rcode::Int(i) => i.fmt(f),
                    value @ _ => value.fmt(f)
                }
            }
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

impl cmp::Eq for Rcode { }


//--- PartialOrd and Ord

impl cmp::PartialOrd for Rcode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
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
