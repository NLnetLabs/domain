//! DNS CLASSes.

use std::convert;
use std::fmt;
use std::str;
use super::super::error::{FromStrError, FromStrResult};


/// DNS CLASSes.
#[derive(Clone, Copy, Debug)]
pub enum Class {
    /// Internet (IN).
    ///
    /// This class is defined in RFC 1035 and really the only one relevant
    /// at all.
    IN,

    /// Chaos (CH)
    CH,

    /// Hesiod (HS)
    HS,

    /// Query class None
    ///
    /// Defined in RFC 2136, this class is used in UPDATE queries to
    /// require that an RRset does not exist prior to the update.
    NONE,

    /// Query class * (ANY)
    ///
    /// This class can be used in a query to indicate that records for the
    /// given name from any class are requested.
    ANY,

    /// A raw class value given through its integer. 
    Int(u16),
}

impl Class {
    /// Returns the class value for the given raw integer class value.
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

    /// Returns the raw integer class value for this class.
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
}

impl convert::From<u16> for Class {
    fn from(value: u16) -> Class {
        Class::from_int(value)
    }
}

impl convert::From<Class> for u16 {
    fn from(value: Class) -> u16 {
        value.to_int()
    }
}

impl str::FromStr for Class {
    type Err = FromStrError;

    /// Returns the class value for the given string.
    ///
    /// Recognized are the mnemonics equivalent to the variant names, an
    /// asterisk for `Class::ANY`, and the generic class names from RFC 3597
    /// in the form of the string `CLASS` followed immediately by decimal
    /// class number.
    fn from_str(s: &str) -> FromStrResult<Self> {
        use std::ascii::AsciiExt;
        use self::Class::*;

        if s.eq_ignore_ascii_case("IN") { Ok(IN) }
        else if s.eq_ignore_ascii_case("CH") { Ok(CH) }
        else if s.eq_ignore_ascii_case("HS") { Ok(HS) }
        else if s.eq_ignore_ascii_case("NONE") { Ok(NONE) }
        else if s.eq_ignore_ascii_case("*") { Ok(ANY) }
        else {
            if let Some((n, _)) = s.char_indices().nth(5) {
                let (l, r) = s.split_at(n);
                if l.eq_ignore_ascii_case("CLASS") {
                    let value = match u16::from_str_radix(r, 10) {
                        Ok(x) => x,
                        Err(..) => return Err(FromStrError::UnknownClass)
                    };
                    Ok(Int(value))
                }
                else {
                    Err(FromStrError::UnknownClass)
                }
            }
            else {
                Err(FromStrError::UnknownClass)
            }
        }
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
            Int(value) => {
                // Maybe value is actually for a well-known variant.
                match Class::from_int(value) {
                    Int(value) => write!(f, "CLASS{}", value),
                    value @ _ => value.fmt(f),
                }
            }
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

