//! DNS questions.

use zerocopy::{network_endian::U16, FromBytes};
use zerocopy_derive::*;

use super::{
    name::ParsedName,
    parse::{ParseError, ParseFrom, SplitFrom},
};

//----------- Question -------------------------------------------------------

/// A DNS question.
pub struct Question<'a> {
    /// The domain name being requested.
    pub qname: &'a ParsedName,

    /// The type of the requested records.
    pub qtype: QType,

    /// The class of the requested records.
    pub qclass: QClass,
}

//--- Construction

impl<'a> Question<'a> {
    /// Construct a new [`Question`].
    pub fn new(qname: &'a ParsedName, qtype: QType, qclass: QClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for Question<'a> {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (qname, rest) = <&ParsedName>::split_from(bytes)?;
        let (qtype, rest) = QType::read_from_prefix(rest)?;
        let (qclass, rest) = QClass::read_from_prefix(rest)?;
        Ok((Self::new(qname, qtype, qclass), rest))
    }
}

impl<'a> ParseFrom<'a> for Question<'a> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (qname, rest) = <&ParsedName>::split_from(bytes)?;
        let (qtype, rest) = QType::read_from_prefix(rest)?;
        let qclass = QClass::read_from_bytes(rest)?;
        Ok(Self::new(qname, qtype, qclass))
    }
}

//----------- QType ----------------------------------------------------------

/// The type of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct QType {
    /// The type code.
    pub code: U16,
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct QClass {
    /// The class code.
    pub code: U16,
}
