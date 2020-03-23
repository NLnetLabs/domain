//! DNS EDNS0 Option Codes (OPT)

use core::{cmp, fmt, hash};
use super::super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};


//------------ OptionCode ---------------------------------------------------

/// DNS EDNS0 Option Codes (OPT).
///
/// The record data of OPT records is a sequence of options. The type of each
/// of these options is given through an option code, a 16 bit value.
///
/// The currently assigned option codes can be found in the [IANA registry].
/// The type is complete as of 2019-01-28.
///
/// [IANA registry]: http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
#[derive(Clone, Copy, Debug)]
pub enum OptionCode {
    Llq,
    Ul,
    Nsid,
    Dau,
    Dhu,
    N3u,
    ClientSubnet,
    Expire,
    Cookie,
    TcpKeepalive,
    Padding,
    Chain,
    KeyTag,
    DeviceId,

    /// A raw class value given through its integer. 
    Int(u16),
}

impl OptionCode {
    /// Returns the option code for the given raw integer value.
    pub fn from_int(value: u16) -> Self {
        use self::OptionCode::*;

        match value {
            1 => Llq,
            2 => Ul,
            3 => Nsid,
            5 => Dau,
            6 => Dhu,
            7 => N3u,
            8 => ClientSubnet,
            9 => Expire,
            10 => Cookie,
            11 => TcpKeepalive,
            12 => Padding,
            13 => Chain,
            14 => KeyTag,
            26946 => DeviceId,
            _ => Int(value)
        }
    }

    /// Returns the raw integer value for this option code.
    pub fn to_int(self) -> u16 {
        use self::OptionCode::*;

        match self {
            Llq => 1,
            Ul => 2,
            Nsid => 3,
            Dau => 5,
            Dhu => 6,
            N3u => 7,
            ClientSubnet => 8,
            Expire => 9,
            Cookie => 10,
            TcpKeepalive => 11,
            Padding => 12,
            Chain => 13,
            KeyTag => 14,
            DeviceId => 26946,
            Int(v) => v
        }
    }
}


//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for OptionCode {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        u16::parse(parser).map(OptionCode::from_int)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        u16::skip(parser)
    }
}

impl Compose for OptionCode {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.to_int().compose(target)
    }
}


//--- From

impl From<u16> for OptionCode {
    fn from(value: u16) -> Self {
        OptionCode::from_int(value)
    }
}

impl From<OptionCode> for u16 {
    fn from(value: OptionCode) -> Self {
        value.to_int()
    }
}


//--- Display

impl fmt::Display for OptionCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::OptionCode::*;

        match *self {
            Llq => "LLQ".fmt(f),
            Ul => "UL".fmt(f),
            Nsid => "NSID".fmt(f),
            Dau => "DAU".fmt(f),
            Dhu => "DHU".fmt(f),
            N3u => "N3U".fmt(f),
            ClientSubnet => "edns-client-subnet".fmt(f),
            Expire => "EDNS EXPIRE".fmt(f),
            Cookie => "COOKIE".fmt(f),
            TcpKeepalive => "edns-tcp-keepalive".fmt(f),
            Padding => "Padding".fmt(f),
            Chain => "CHAIN".fmt(f),
            KeyTag => "edns-key-tag".fmt(f),
            DeviceId => "DeviceID".fmt(f),
            Int(value) => {
                match OptionCode::from_int(value) {
                    Int(value) => value.fmt(f),
                    value => value.fmt(f),
                }
            }
        }
    }
}


//--- PartialEq and Eq

impl PartialEq for OptionCode {
    fn eq(&self, other: &Self) -> bool {
        self.to_int() == other.to_int()
    }
}

impl PartialEq<u16> for OptionCode {
    fn eq(&self, other: &u16) -> bool {
        self.to_int() == *other
    }
}

impl PartialEq<OptionCode> for u16 {
    fn eq(&self, other: &OptionCode) -> bool {
        *self == other.to_int()
    }
}

impl Eq for OptionCode { }


//--- PartialOrd and Ord

impl PartialOrd for OptionCode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
    }
}

impl PartialOrd<u16> for OptionCode {
    fn partial_cmp(&self, other: &u16) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl PartialOrd<OptionCode> for u16 {
    fn partial_cmp(&self, other: &OptionCode) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl Ord for OptionCode {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}


//--- Hash

impl hash::Hash for OptionCode {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}

