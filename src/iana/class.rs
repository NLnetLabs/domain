//! DNS CLASSes.

use std::cmp;
use std::fmt;
use std::hash;
use std::str;
use bits::error::{FromStrError, FromStrResult};


//------------ Class --------------------------------------------------------

/// DNS CLASSes.
///
/// The domain name space is partitioned into separate classes for different
/// network types. Classes are represented by a 16 bit value. This type
/// wraps these values. It includes the query classes that can only be used
/// in a question.
///
/// See RFC 1034 for classes in general and
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
/// for all currently assigned classes.
#[derive(Clone, Copy, Debug)]
pub enum Class {
    /// Internet (IN).
    ///
    /// This class is defined in RFC 1035 and really the only one relevant
    /// at all.
    In,

    /// Chaos (CH)
    Ch,

    /// Hesiod (HS)
    Hs,

    /// Query class None
    ///
    /// Defined in RFC 2136, this class is used in UPDATE queries to
    /// require that an RRset does not exist prior to the update.
    None,

    /// Query class * (ANY)
    ///
    /// This class can be used in a query to indicate that records for the
    /// given name from any class are requested.
    Any,

    /// A raw class value given through its integer. 
    Int(u16),
}

impl Class {
    /// Returns the class value for the given raw integer value.
    pub fn from_int(value: u16) -> Class {
        use self::Class::*;

        match value {
            0x0001 => In,
            0x0003 => Ch,
            0x0004 => Hs,
            0x00FE => None,
            0x00FF => Any,
            _ => Int(value)
            
        }
    }

    /// Returns the raw integer value for this class value.
    pub fn to_int(self) -> u16 {
        use self::Class::*;

        match self {
            In => 0x0001,
            Ch => 0x0003,
            Hs => 0x0004,
            None => 0x00FE,
            Any => 0x00FF,
            Int(value) => value
        }
    }
}


//--- From

impl From<u16> for Class {
    fn from(value: u16) -> Class {
        Class::from_int(value)
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> u16 {
        value.to_int()
    }
}


//--- FromStr

impl str::FromStr for Class {
    type Err = FromStrError;

    /// Returns the class value for the given string.
    ///
    /// Recognized are the mnemonics equivalent to the variant names, an
    /// asterisk for `Class::ANY`, and the generic class names from RFC 3597
    /// in the form of the string `CLASS` followed immediately by decimal
    /// class number. Case is ignored in all these, er, cases.
    ///
    /// Returns either the class value or `FromStrError::UnknownClass`.
    fn from_str(s: &str) -> FromStrResult<Self> {
        use std::ascii::AsciiExt;
        use self::Class::*;

        if s.eq_ignore_ascii_case("IN") { Ok(In) }
        else if s.eq_ignore_ascii_case("CH") { Ok(Ch) }
        else if s.eq_ignore_ascii_case("HS") { Ok(Hs) }
        else if s.eq_ignore_ascii_case("NONE") { Ok(None) }
        else if s.eq_ignore_ascii_case("*") { Ok(Any) }
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


//--- Display

impl fmt::Display for Class {
    /// Formats the class using the given formatter.
    ///
    /// Uses the standard mnemonic for all known classes, even if they are
    /// hidden behind `Class::Int`. Uses the generic class value `CLASS`
    /// followed directly by the decimal representation of the value for
    /// any unknown value.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Class::*;

        match *self {
            In => "IN".fmt(f),
            Ch => "CH".fmt(f),
            Hs => "HS".fmt(f),
            None => "NONE".fmt(f),
            Any => "*".fmt(f),
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


//--- PartialEq and Eq

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


//--- PartialOrd and Ord

impl PartialOrd for Class {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(&other.to_int())
    }
}

impl PartialOrd<u16> for Class {
    fn partial_cmp(&self, other: &u16) -> Option<cmp::Ordering> {
        self.to_int().partial_cmp(other)
    }
}

impl PartialOrd<Class> for u16 {
    fn partial_cmp(&self, other: &Class) -> Option<cmp::Ordering> {
        self.partial_cmp(&other.to_int())
    }
}

impl Ord for Class {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.to_int().cmp(&other.to_int())
    }
}


//--- Hash

impl hash::Hash for Class {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.to_int().hash(state)
    }
}

