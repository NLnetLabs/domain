//! DNS OpCodes

use std::cmp;
use std::convert;
use std::fmt;


/// DNS OpCodes
///
#[derive(Clone, Copy, Debug)]
pub enum Opcode {
    /// a standard query [RFC1035]
    Query,

    /// a inverse query [RFC1035]
    IQuery,

    /// a server status request [RFC1035]
    Status,

    /// a NOTIFY query [RFC1996]
    Notify,

    /// an UPDATE query [RFC2136]
    Update,

    /// a raw integer opcode value.
    ///
    /// When converting to an `u8`, only the lower four bits are used.
    Int(u8)
}

impl Opcode {
    pub fn from_int(value: u8) -> Opcode {
        match value & 0x0F {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            4 => Opcode::Notify,
            5 => Opcode::Update,
            value @ _ => Opcode::Int(value)
        }
    }

    pub fn to_int(self) -> u8{
        match self {
            Opcode::Query => 0,
            Opcode::IQuery => 1,
            Opcode::Status => 2,
            Opcode::Notify => 4,
            Opcode::Update => 5,
            Opcode::Int(value) => value & 0x0F
        }
    }
}

impl convert::From<u8> for Opcode {
    fn from(value: u8) -> Opcode { Opcode::from_int(value) }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Opcode::Query => "QUERY".fmt(f),
            Opcode::IQuery => "IQUERY".fmt(f),
            Opcode::Status => "STATUS".fmt(f),
            Opcode::Notify => "NOTIFY".fmt(f),
            Opcode::Update => "UPDATE".fmt(f),
            Opcode::Int(code) => code.fmt(f)
        }
    }
}


impl cmp::PartialEq for Opcode {
    fn eq(&self, other: &Opcode) -> bool {
        self.to_int() == other.to_int()
    }
}

impl cmp::PartialEq<u8> for Opcode {
    fn eq(&self, other: &u8) -> bool {
        self.to_int() == *other
    }
}

impl cmp::PartialEq<Opcode> for u8 {
    fn eq(&self, other: &Opcode) -> bool {
        *self == other.to_int()
    }
}

impl cmp::Eq for Opcode { }
