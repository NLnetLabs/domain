//! DNS records.

use core::{
    borrow::Borrow,
    ops::{Deref, Range},
};

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, IntoBytes, SizeError,
};
use zerocopy_derive::*;

use super::{
    build::{self, BuildInto, BuildIntoMessage, TruncationError},
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

//--- Parsing from DNS messages

impl<'a, N, D> SplitFromMessage<'a> for Record<N, D>
where
    N: SplitFromMessage<'a>,
    D: ParseFromMessage<'a>,
{
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (rname, rest) = N::split_from_message(message, start)?;
        let (&rtype, rest) = <&RType>::split_from_message(message, rest)?;
        let (&rclass, rest) = <&RClass>::split_from_message(message, rest)?;
        let (&ttl, rest) = <&TTL>::split_from_message(message, rest)?;
        let (&size, rest) = <&U16>::split_from_message(message, rest)?;
        let size: usize = size.get().into();
        let rdata = if message.as_bytes().len() - rest >= size {
            D::parse_from_message(message, rest..rest + size)?
        } else {
            return Err(ParseError);
        };

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest + size))
    }
}

impl<'a, N, D> ParseFromMessage<'a> for Record<N, D>
where
    N: SplitFromMessage<'a>,
    D: ParseFromMessage<'a>,
{
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let message = &message.as_bytes()[..range.end];
        let message = Message::ref_from_bytes(message)
            .map_err(SizeError::from)
            .expect("The input range ends past the message header");

        let (this, rest) = Self::split_from_message(message, range.start)?;

        if rest == range.end {
            Ok(this)
        } else {
            Err(ParseError)
        }
    }
}

//--- Building into DNS messages

impl<N, D> BuildIntoMessage for Record<N, D>
where
    N: BuildIntoMessage,
    D: BuildIntoMessage,
{
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.rname.build_into_message(builder.delegate())?;
        builder.append_bytes(self.rtype.as_bytes())?;
        builder.append_bytes(self.rclass.as_bytes())?;
        builder.append_bytes(self.ttl.as_bytes())?;

        // The offset of the record data size.
        let offset = builder.appended().len();
        builder.append_bytes(&0u16.to_be_bytes())?;
        self.rdata.build_into_message(builder.delegate())?;
        let size = builder.appended().len() - 2 - offset;
        let size =
            u16::try_from(size).expect("the record data never exceeds 64KiB");
        builder.appended_mut()[offset..offset + 2]
            .copy_from_slice(&size.to_be_bytes());

        builder.commit();
        Ok(())
    }
}

//--- Parsing from bytes

impl<'a, N, D> SplitFrom<'a> for Record<N, D>
where
    N: SplitFrom<'a>,
    D: ParseFrom<'a>,
{
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (rname, rest) = N::split_from(bytes)?;
        let (rtype, rest) = RType::read_from_prefix(rest)?;
        let (rclass, rest) = RClass::read_from_prefix(rest)?;
        let (ttl, rest) = TTL::read_from_prefix(rest)?;
        let (size, rest) = U16::read_from_prefix(rest)?;
        let size: usize = size.get().into();
        let (rdata, rest) = <[u8]>::ref_from_prefix_with_elems(rest, size)?;
        let rdata = D::parse_from(rdata)?;

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
        let (size, rest) = U16::read_from_prefix(rest)?;
        let size: usize = size.get().into();
        let rdata = <[u8]>::ref_from_bytes_with_elems(rest, size)?;
        let rdata = D::parse_from(rdata)?;

        Ok(Self::new(rname, rtype, rclass, ttl, rdata))
    }
}

//--- Building into byte strings

impl<N, D> BuildInto for Record<N, D>
where
    N: BuildInto,
    D: BuildInto,
{
    fn build_into<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.rname.build_into(bytes)?;
        bytes = self.rtype.as_bytes().build_into(bytes)?;
        bytes = self.rclass.as_bytes().build_into(bytes)?;
        bytes = self.ttl.as_bytes().build_into(bytes)?;

        let (size, bytes) =
            <U16>::mut_from_prefix(bytes).map_err(|_| TruncationError)?;
        let bytes_len = bytes.len();

        let rest = self.rdata.build_into(bytes)?;
        *size = u16::try_from(bytes_len - rest.len())
            .expect("the record data never exceeds 64KiB")
            .into();

        Ok(rest)
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

//--- Building into DNS messages

impl BuildIntoMessage for UnparsedRecordData {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.0.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a> ParseFrom<'a> for &'a UnparsedRecordData {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() > 65535 {
            // Too big to fit in an 'UnparsedRecordData'.
            return Err(ParseError);
        }

        // SAFETY: 'bytes.len()' fits within a 'u16'.
        Ok(unsafe { UnparsedRecordData::new_unchecked(bytes) })
    }
}

//--- Building into byte strings

impl BuildInto for UnparsedRecordData {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.0.build_into(bytes)
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
