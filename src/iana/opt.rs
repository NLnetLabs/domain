//! DNS EDNS0 Option Codes (OPT)

use std::cmp;
use std::fmt;
use std::hash;
use bytes::BufMut;
use ::bits::compose::Compose;
use ::bits::parse::{Parse, Parser, ShortBuf};


//------------ OptionCode ---------------------------------------------------

/// DNS EDNS0 Option Codes (OPT)
///
/// The record data of OPT records is a sequence of options. The type of each
/// of these options is given through an option code, a 16 bit value.
///
/// The currently assigned option codes can be found in
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
#[derive(Clone, Copy, Debug)]
pub enum OptionCode {
    Llq,
    Ul,
    Nsid,
    Dau,
    Dhu,
    N3u,
    EdnsClientSubnet,
    EdnsExpire,
    Cookie,
    EdnsTcpKeepalive,
    Padding,
    Chain,
    EdnsKeyTag,

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
            8 => EdnsClientSubnet,
            9 => EdnsExpire,
            10 => Cookie,
            11 => EdnsTcpKeepalive,
            12 => Padding,
            13 => Chain,
            14 => EdnsKeyTag,
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
            EdnsClientSubnet => 8,
            EdnsExpire => 9,
            Cookie => 10,
            EdnsTcpKeepalive => 11,
            Padding => 12,
            Chain => 13,
            EdnsKeyTag => 14,
            Int(v) => v
        }
    }
}


//--- Parse and Compose

impl Parse for OptionCode {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        u16::parse(parser).map(OptionCode::from_int)
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        u16::skip(parser)
    }
}

impl Compose for OptionCode {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.to_int().compose(buf)
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
            EdnsClientSubnet => "edns-client-subnet".fmt(f),
            EdnsExpire => "EDNS EXPIRE".fmt(f),
            Cookie => "COOKIE".fmt(f),
            EdnsTcpKeepalive => "edns-tcp-keepalive".fmt(f),
            Padding => "Padding".fmt(f),
            Chain => "CHAIN".fmt(f),
            EdnsKeyTag => "edns-key-tag".fmt(f),
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

