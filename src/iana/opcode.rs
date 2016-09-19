//! DNS OpCodes

use std::cmp;
use std::convert;
use std::fmt;
use std::hash;


/// DNS OpCodes.
///
/// The opcode specifies the kind of query to be performed.
///
/// The opcode is initially defined in RFC 1035. All currently assigned
/// values can be found at
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
#[derive(Clone, Copy, Debug)]
pub enum Opcode {
    /// A standard query.
    ///
    /// This query requests all records matching the name, class, and record
    /// type given in the query’s question section.
    ///
    /// This value is defined in RFC 1035.
    Query,

    /// An inverse query (IQUERY) (obsolete).
    ///
    /// The idea behind inverse queries was to provide a single answer and
    /// ask the DNS for all the questions that would lead to this answer.
    /// This kind of query has always been optional, was never widely
    /// supported, and has therefore been declared obsolete.
    ///
    /// This value was defined in RFC 1035 and obsoleted by RFC 3425.
    IQuery,

    /// A server status request.
    ///
    /// This value is defined in RFC 1035. The status request itself was
    /// defined as experimental and ‘to be defined’ in RFC 1034 and seems
    /// to never have been mentioned ever again.
    Status,

    /// A NOTIFY query.
    ///
    /// NOTIFY queries allow master servers to inform slave servers when a
    /// zone has changed.
    ///
    /// This value and the NOTIFY query are defined in RFC 1996.
    Notify,

    /// An UPDATE query.
    ///
    /// The UPDATE query can be used to alter zone content managed by a
    /// master server.
    ///
    /// This value and the UPDATE query are defined in RFC 2136.
    Update,

    /// A raw integer opcode value.
    ///
    /// When converting to an `u8`, only the lower four bits are used.
    Int(u8)
}

impl Opcode {
    /// Creates an Opcode value from an integer value.
    ///
    /// Only considers the lower four bits of `value`.
    pub fn from_int(value: u8) -> Opcode {
        use self::Opcode::*;

        match value & 0x0F {
            0 => Query,
            1 => IQuery,
            2 => Status,
            4 => Notify,
            5 => Update,
            value => Int(value)
        }
    }

    /// Returns the integer value for this opcode.
    pub fn to_int(self) -> u8 {
        use self::Opcode::*;

        match self {
            Query => 0,
            IQuery => 1,
            Status => 2,
            Notify => 4,
            Update => 5,
            Int(value) => value & 0x0F
        }
    }
}


//--- From

impl convert::From<u8> for Opcode {
    fn from(value: u8) -> Opcode { Opcode::from_int(value) }
}

impl convert::From<Opcode> for u8 {
    fn from(value: Opcode) -> u8 { Opcode::to_int(value) }
}


//--- Display

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Opcode::*;

        match *self {
            Query => "QUERY".fmt(f),
            IQuery => "IQUERY".fmt(f),
            Status => "STATUS".fmt(f),
            Notify => "NOTIFY".fmt(f),
            Update => "UPDATE".fmt(f),
            Int(value) => {
                match Opcode::from_int(value) {
                    Int(value) => value.fmt(f),
                    value => value.fmt(f)
                }
            }
        }
    }
}


//--- PartialEq and Eq

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


//--- PartialCmp and Cmp

impl cmp::PartialOrd for Opcode {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
    }
}

impl cmp::PartialOrd<u8> for Opcode {
    fn partial_cmp(&self, other: &u8) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl cmp::PartialOrd<Opcode> for u8 {
    fn partial_cmp(&self, other: &Opcode) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl cmp::Ord for Opcode {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}


//--- Hash

impl hash::Hash for Opcode {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}
