//! DNS RCODEs.

use std::cmp;
use std::convert;
use std::fmt;


/// DNS RCODEs.
///
#[derive(Clone, Copy, Debug)]
pub enum Rcode {
    /// no error condition [RFC1035]
    NoError,

    /// format error [RFC1035]
    FormErr,

    /// server failure [RFC1035]
    ServFail,

    /// name error [RFC1035]
    NXDomain,

    /// not implemented [RFC1035]
    NotImp,

    /// query refused [RFC1035]
    Refused,

    /// name exists when it should not [RFC2136]
    YXDomain,

    /// RR set exists when it should not [RFC2136]
    YXRRSet,

    /// RR set that should exist does not [RFC2136]
    NXRRSet,

    /// server not authoritative for zone [RFC2136] or not authorized [RFC2845]
    NotAuth,

    /// name not contained in zone [RFC2136]
    NotZone,

    /// a raw, integer rcode value.
    ///
    /// When converting to an `u8`, only the lower four bits are used.
    Int(u8)
}

impl Rcode {
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

impl convert::From<u8> for Rcode {
    fn from(value: u8) -> Rcode { Rcode::from_int(value) }
}

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
            Rcode::Int(i) => i.fmt(f)
        }
    }
}


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

