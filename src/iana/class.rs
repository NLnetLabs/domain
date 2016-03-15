//! DNS CLASSes.

use std::convert;
use std::fmt;
use super::super::bytes::BytesBuf;


/// DNS CLASSes.
///
#[derive(Clone, Copy, Debug)]
pub enum Class {
    /// Internet
    IN,

    /// Chaos
    CH,

    /// Hesiod
    ///
    HS,

    /// Query class None
    ///
    /// See RFC 2136.
    NONE,

    /// Query class *
    ANY,

    /// A raw class value given through its integer. 
    Int(u16),
}

impl Class {
    pub fn from_int(value: u16) -> Class {
        use self::Class::*;

        match value {
            0x0001 => IN,
            0x0003 => CH,
            0x0004 => HS,
            0x00FE => NONE,
            0x00FF => ANY,
            _ => Int(value)
            
        }
    }

    pub fn to_int(self) -> u16 {
        use self::Class::*;

        match self {
            IN => 0x0001,
            CH => 0x0003,
            HS => 0x0004,
            NONE => 0x00FE,
            ANY => 0x00FF,
            Int(value) => value
        }
    }

    pub fn push_buf<B: BytesBuf>(self, buf: &mut B) {
        buf.push_u16(self.to_int());
    }
}

impl convert::From<u16> for Class {
    fn from(value: u16) -> Class {
        Class::from_int(value)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Class::*;

        match *self {
            IN => "IN".fmt(f),
            CH => "CH".fmt(f),
            HS => "HS".fmt(f),
            NONE => "NONE".fmt(f),
            ANY => "ANY".fmt(f),
            Int(value) => value.fmt(f)
        }
    }
}


impl PartialEq for Class {
    fn eq(&self, other: &Class) -> bool {
        self.to_int() == other.to_int()
    }
}

impl PartialEq<u16> for Class {
    fn eq(&self, other: &u16) -> bool {
        self.to_int() == *other
    }
}

impl PartialEq<Class> for u16 {
    fn eq(&self, other: &Class) -> bool {
        *self == other.to_int()
    }
}

impl Eq for Class { }
