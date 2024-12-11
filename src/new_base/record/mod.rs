//! DNS records.

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes,
};
use zerocopy_derive::*;

use super::{
    name::ParsedName,
    parse::{ParseError, ParseFrom, SplitFrom},
};

//----------- Record ---------------------------------------------------------

/// An unparsed DNS record.
pub struct Record<'a> {
    /// The name of the record.
    pub rname: &'a ParsedName,

    /// The type of the record.
    pub rtype: RType,

    /// The class of the record.
    pub rclass: RClass,

    /// How long the record is reliable for.
    pub ttl: TTL,

    /// Unparsed record data.
    pub rdata: &'a [u8],
}

//--- Construction

impl<'a> Record<'a> {
    /// Construct a new [`Record`].
    pub fn new(
        rname: &'a ParsedName,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
        rdata: &'a [u8],
    ) -> Self {
        Self {
            rname,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for Record<'a> {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (rname, rest) = <&ParsedName>::split_from(bytes)?;
        let (rtype, rest) = RType::read_from_prefix(rest)?;
        let (rclass, rest) = RClass::read_from_prefix(rest)?;
        let (ttl, rest) = TTL::read_from_prefix(rest)?;
        let (size, rest) = U16::read_from_prefix(rest)?;
        let size = size.get() as usize;
        let (rdata, rest) = <[u8]>::ref_from_prefix_with_elems(rest, size)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a> ParseFrom<'a> for Record<'a> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (rname, rest) = <&ParsedName>::split_from(bytes)?;
        let (rtype, rest) = RType::read_from_prefix(rest)?;
        let (rclass, rest) = RClass::read_from_prefix(rest)?;
        let (ttl, rest) = TTL::read_from_prefix(rest)?;
        let (size, rest) = U16::read_from_prefix(rest)?;
        let size = size.get() as usize;
        let rdata = <[u8]>::ref_from_bytes_with_elems(rest, size)?;

        Ok(Self::new(rname, rtype, rclass, ttl, rdata))
    }
}

//----------- RType ----------------------------------------------------------

/// The type of a record.
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
pub struct RType {
    /// The type code.
    pub code: U16,
}

//----------- RClass ---------------------------------------------------------

/// The class of a record.
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
pub struct RClass {
    /// The class code.
    pub code: U16,
}

//----------- TTL ------------------------------------------------------------

/// How long a record can be cached.
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
pub struct TTL {
    /// The underlying value.
    pub value: U32,
}
