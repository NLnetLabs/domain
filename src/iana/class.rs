//! DNS CLASSes.

use ::master::{ScanResult, Scanner, SyntaxError};
use ::bits::{Composer, ComposeResult, Parser, ParseResult};


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
int_enum!{
    Class, u16;

    /// Internet (IN).
    /// 
    /// This class is defined in RFC 1035 and really the only one relevant
    /// at all.
    (In => 1, b"IN")

    /// Chaosnet (CH).
    /// 
    /// A network protocol developed at MIT in the 1970s. Reused by BIND for
    /// built-in server information zones.",
    (Ch => 3, b"CH")

    /// Hesiod (HS).
    /// 
    /// A system information protocol part of MIT's Project Athena.",
    (Hs => 4, b"HS")

    /// Query class None.
    /// 
    /// Defined in RFC 2136, this class is used in UPDATE queries to
    /// require that an RRset does not exist prior to the update.",
    (None => 0xFE, b"NONE")

    /// Query class * (ANY).
    /// 
    /// This class can be used in a query to indicate that records for the
    /// given name from any class are requested.",
    (Any => 0xFF, b"*")
}

int_enum_str_with_prefix!(Class, "CLASS", b"CLASS", u16, "unknown class");

impl Class {
    pub fn parse(parser: &mut Parser) -> ParseResult<Self> {
        parser.parse_u16().map(Class::from)
    }

    pub fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                       -> ComposeResult<()> {
        composer.as_mut().compose_u16(self.into())
    }

    pub fn scan<S: Scanner>(scanner: &mut S) -> ScanResult<Self> {
        scanner.scan_word(|slice| {
            Class::from_bytes(slice)
                  .ok_or_else(|| SyntaxError::UnknownClass(slice.into()))
        })
    }
}
