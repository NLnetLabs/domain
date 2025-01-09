//! DNS records.

use core::{borrow::Borrow, ops::Deref};

use super::{
    build::{self, BuildIntoMessage, BuildResult},
    name::RevNameBuf,
    parse::{ParseFromMessage, SplitFromMessage},
    wire::{
        AsBytes, BuildBytes, ParseBytes, ParseBytesByRef, ParseError,
        SizePrefixed, SplitBytes, SplitBytesByRef, TruncationError, U16, U32,
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
    D: ParseRecordData<'a>,
{
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (rname, rest) = N::split_from_message(message, start)?;
        let (&rtype, rest) = <&RType>::split_from_message(message, rest)?;
        let (&rclass, rest) = <&RClass>::split_from_message(message, rest)?;
        let (&ttl, rest) = <&TTL>::split_from_message(message, rest)?;
        let rdata_start = rest;
        let (_, rest) =
            <&SizePrefixed<[u8]>>::split_from_message(message, rest)?;
        let message = message.slice_to(rest);
        let rdata = D::parse_record_data(message, rdata_start, rtype)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a, N, D> ParseFromMessage<'a> for Record<N, D>
where
    N: SplitFromMessage<'a>,
    D: ParseRecordData<'a>,
{
    fn parse_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<Self, ParseError> {
        let (rname, rest) = N::split_from_message(message, start)?;
        let (&rtype, rest) = <&RType>::split_from_message(message, rest)?;
        let (&rclass, rest) = <&RClass>::split_from_message(message, rest)?;
        let (&ttl, rest) = <&TTL>::split_from_message(message, rest)?;
        let _ = <&SizePrefixed<[u8]>>::parse_from_message(message, rest)?;
        let rdata = D::parse_record_data(message, rest, rtype)?;

        Ok(Self::new(rname, rtype, rclass, ttl, rdata))
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
    ) -> BuildResult {
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

        Ok(builder.commit())
    }
}

//--- Parsing from bytes

impl<'a, N, D> SplitBytes<'a> for Record<N, D>
where
    N: SplitBytes<'a>,
    D: ParseRecordData<'a>,
{
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (rname, rest) = N::split_bytes(bytes)?;
        let (rtype, rest) = RType::split_bytes(rest)?;
        let (rclass, rest) = RClass::split_bytes(rest)?;
        let (ttl, rest) = TTL::split_bytes(rest)?;
        let (rdata, rest) = <&SizePrefixed<[u8]>>::split_bytes(rest)?;
        let rdata = D::parse_record_data_bytes(rdata, rtype)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a, N, D> ParseBytes<'a> for Record<N, D>
where
    N: SplitBytes<'a>,
    D: ParseRecordData<'a>,
{
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (rname, rest) = N::split_bytes(bytes)?;
        let (rtype, rest) = RType::split_bytes(rest)?;
        let (rclass, rest) = RClass::split_bytes(rest)?;
        let (ttl, rest) = TTL::split_bytes(rest)?;
        let rdata = <&SizePrefixed<[u8]>>::parse_bytes(rest)?;
        let rdata = D::parse_record_data_bytes(rdata, rtype)?;

        Ok(Self::new(rname, rtype, rclass, ttl, rdata))
    }
}

//--- Building into byte strings

impl<N, D> BuildBytes for Record<N, D>
where
    N: BuildBytes,
    D: BuildBytes,
{
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.rname.build_bytes(bytes)?;
        bytes = self.rtype.as_bytes().build_bytes(bytes)?;
        bytes = self.rclass.as_bytes().build_bytes(bytes)?;
        bytes = self.ttl.as_bytes().build_bytes(bytes)?;
        bytes = SizePrefixed::new(&self.rdata).build_bytes(bytes)?;

        Ok(bytes)
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct RType {
    /// The type code.
    pub code: U16,
}

//--- Associated Constants

impl RType {
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of an [`A`](crate::new_rdata::A) record.
    pub const A: Self = Self::new(1);

    /// The type of an [`Ns`](crate::new_rdata::Ns) record.
    pub const NS: Self = Self::new(2);

    /// The type of a [`CName`](crate::new_rdata::CName) record.
    pub const CNAME: Self = Self::new(5);

    /// The type of an [`Soa`](crate::new_rdata::Soa) record.
    pub const SOA: Self = Self::new(6);

    /// The type of a [`Wks`](crate::new_rdata::Wks) record.
    pub const WKS: Self = Self::new(11);

    /// The type of a [`Ptr`](crate::new_rdata::Ptr) record.
    pub const PTR: Self = Self::new(12);

    /// The type of a [`HInfo`](crate::new_rdata::HInfo) record.
    pub const HINFO: Self = Self::new(13);

    /// The type of a [`Mx`](crate::new_rdata::Mx) record.
    pub const MX: Self = Self::new(15);

    /// The type of a [`Txt`](crate::new_rdata::Txt) record.
    pub const TXT: Self = Self::new(16);

    /// The type of an [`Aaaa`](crate::new_rdata::Aaaa) record.
    pub const AAAA: Self = Self::new(28);

    /// The type of an [`Opt`](crate::new_rdata::Opt) record.
    pub const OPT: Self = Self::new(41);
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct TTL {
    /// The underlying value.
    pub value: U32,
}

//----------- ParseRecordData ------------------------------------------------

/// Parsing DNS record data.
pub trait ParseRecordData<'a>: Sized {
    /// Parse DNS record data of the given type from a DNS message.
    fn parse_record_data(
        message: &'a Message,
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        let bytes = message.contents.get(start..).ok_or(ParseError)?;
        Self::parse_record_data_bytes(bytes, rtype)
    }

    /// Parse DNS record data of the given type from a byte string.
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError>;
}

//----------- UnparsedRecordData ---------------------------------------------

/// Unparsed DNS record data.
#[derive(AsBytes, BuildBytes)]
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

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a UnparsedRecordData {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        _rtype: RType,
    ) -> Result<Self, ParseError> {
        if bytes.len() > 65535 {
            // Too big to fit in an 'UnparsedRecordData'.
            return Err(ParseError);
        }

        // SAFETY: 'bytes.len()' fits within a 'u16'.
        Ok(unsafe { UnparsedRecordData::new_unchecked(bytes) })
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for UnparsedRecordData {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.0.build_into_message(builder)
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
