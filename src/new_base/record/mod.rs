//! DNS records.

use core::{
    borrow::Borrow,
    ops::{Deref, Range},
};

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, IntoBytes,
};
use zerocopy_derive::*;

use super::{
    name::RevNameBuf,
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    Message,
};

//----------- Record ---------------------------------------------------------

/// A DNS record.
#[derive(Clone)]
pub struct Record<N, D> {
    /// The name of the record.
    pub rname: N,

    /// The type of the record.
    pub rtype: RType,

    /// The class of the record.
    pub rclass: RClass,

    /// How long the record is reliable for.
    pub ttl: TTL,

    /// Unparsed record data.
    pub rdata: D,
}

/// An unparsed DNS record.
pub type UnparsedRecord<'a> = Record<RevNameBuf, &'a UnparsedRecordData>;

//--- Construction

impl<N, D> Record<N, D> {
    /// Construct a new [`Record`].
    pub fn new(
        rname: N,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
        rdata: D,
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

//--- Parsing from bytes

impl<'a, N, D> SplitFrom<'a> for Record<N, D>
where
    N: SplitFrom<'a>,
    D: SplitFrom<'a>,
{
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (rname, rest) = N::split_from(bytes)?;
        let (rtype, rest) = RType::read_from_prefix(rest)?;
        let (rclass, rest) = RClass::read_from_prefix(rest)?;
        let (ttl, rest) = TTL::read_from_prefix(rest)?;
        let (rdata, rest) = D::split_from(rest)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a, N, D> ParseFrom<'a> for Record<N, D>
where
    N: SplitFrom<'a>,
    D: ParseFrom<'a>,
{
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (rname, rest) = N::split_from(bytes)?;
        let (rtype, rest) = RType::read_from_prefix(rest)?;
        let (rclass, rest) = RClass::read_from_prefix(rest)?;
        let (ttl, rest) = TTL::read_from_prefix(rest)?;
        let rdata = D::parse_from(rest)?;

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

//----------- UnparsedRecordData ---------------------------------------------

/// Unparsed DNS record data.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct UnparsedRecordData([u8]);

//--- Construction

impl UnparsedRecordData {
    /// Assume a byte string is a valid [`UnparsedRecordData`].
    ///
    /// # Safety
    ///
    /// The byte string must be 65,535 bytes or shorter.
    pub const unsafe fn new_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'UnparsedRecordData' is 'repr(transparent)' to '[u8]', so
        // casting a '[u8]' into an 'UnparsedRecordData' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for &'a UnparsedRecordData {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(start..).ok_or(ParseError)?;
        let (this, rest) = Self::split_from(bytes)?;
        Ok((this, message.len() - rest.len()))
    }
}

impl<'a> ParseFromMessage<'a> for &'a UnparsedRecordData {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(range).ok_or(ParseError)?;
        Self::parse_from(bytes)
    }
}

//--- Parsing from bytes

impl<'a> SplitFrom<'a> for &'a UnparsedRecordData {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (size, rest) = U16::read_from_prefix(bytes)?;
        let size = size.get() as usize;
        let (data, rest) = <[u8]>::ref_from_prefix_with_elems(rest, size)?;
        // SAFETY: 'data.len() == size' which is a 'u16'.
        let this = unsafe { UnparsedRecordData::new_unchecked(data) };
        Ok((this, rest))
    }
}

impl<'a> ParseFrom<'a> for &'a UnparsedRecordData {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (size, rest) = U16::read_from_prefix(bytes)?;
        let size = size.get() as usize;
        let data = <[u8]>::ref_from_bytes_with_elems(rest, size)?;
        // SAFETY: 'data.len() == size' which is a 'u16'.
        Ok(unsafe { UnparsedRecordData::new_unchecked(data) })
    }
}

//--- Access to the underlying bytes

impl Deref for UnparsedRecordData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<[u8]> for UnparsedRecordData {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl AsRef<[u8]> for UnparsedRecordData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
