//! DNS records.

use core::{marker::PhantomData, ops::Deref};
use std::ops::DerefMut;

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes,
};
use zerocopy_derive::*;

use super::{
    name::ParsedName,
    parse::{ParseError, SplitFrom},
};

//----------- Record ---------------------------------------------------------

/// A DNS record.
///
/// # Memory Layout
///
/// A [`Record`] is laid out in memory as:
///
/// ```text
/// +- .. -+------+-------+-----+------+- .. -+
/// | name | type | class | ttl | size | data |
/// +- .. -+------+-------+-----+------+- .. -+
/// ```
///
/// The name and data fields are dynamically sized.  The type, class, and TTL
///  are packaged in a [`RecordFields`] and can be accessed implicitly via
/// [`Deref`].  The record data can be accessed via [`Self::data()`].
///
/// [`Record`] is declared `repr(transparent)`, and can be transmuted to and
/// from a [`ParsedName`] directly.  A [`Record`] must only be constructed
/// when all the fields are present, following the name.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct Record {
    /// A marker for the fields in the record.
    _fields: PhantomData<RecordFields>,

    /// A marker for the data in the record.
    _data: PhantomData<RecordData>,

    /// The name of the record.
    pub name: ParsedName,
}

//--- Construction

impl Record {
    /// Assume a [`ParsedName`] is the start of a [`Record`].
    ///
    /// # Safety
    ///
    /// The [`ParsedName`] must be followed in memory by a [`RecordFields`],
    /// and valid record data.  The fields will be borrowed by the returned
    /// [`Record`], so they must be immutably borrowed for the lifetime of the
    /// reference.
    pub const unsafe fn from_name_unchecked(name: &ParsedName) -> &Self {
        // SAFETY: The caller has verified that a 'RecordFields' follows.
        unsafe { core::mem::transmute(name) }
    }
}

//--- Inspection

impl Record {
    /// The record data.
    pub fn data(&self) -> &[u8] {
        let fields = self.deref() as *const RecordFields;
        // SAFETY: In a 'Record', 'RecordFields' is followed by 'RecordData'.
        unsafe { &*fields.offset(1).cast::<RecordData>() }
    }

    /// The record data, mutably.
    pub fn data_mut(&mut self) -> &mut [u8] {
        let fields = self.deref_mut() as *mut RecordFields;
        // SAFETY: In a 'Record', 'RecordFields' is followed by 'RecordData'.
        unsafe { &mut *fields.offset(1).cast::<RecordData>() }
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a Record {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (name, rest) = <&ParsedName>::split_from(bytes)?;
        let (_, rest) = RecordFields::ref_from_prefix(rest)?;
        let (_, rest) = <&RecordData>::split_from(rest)?;

        // SAFETY: All required fields are present.
        Ok((unsafe { Record::from_name_unchecked(name) }, rest))
    }
}

//--- Access to variably-offset record fields

impl Deref for Record {
    type Target = RecordFields;

    fn deref(&self) -> &Self::Target {
        // SAFETY: 'self' is always followed by a valid 'RecordFields'.
        let range = self.name.as_bytes().as_ptr_range();
        unsafe { &*range.end.cast::<RecordFields>() }
    }
}

impl DerefMut for Record {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: 'self' is always followed by a valid 'RecordFields'.
        let range = self.name.as_bytes().as_ptr_range();
        unsafe { &mut *range.end.cast_mut().cast::<RecordFields>() }
    }
}

//----------- RecordFields ---------------------------------------------------

/// The fields of a DNS record.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct RecordFields {
    /// The type of the record.
    pub rtype: RType,

    /// The class of the record.
    pub rclass: RClass,

    /// How long the record can be cached.
    pub ttl: TTL,
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

//----------- RecordData -----------------------------------------------------

/// DNS record data.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
struct RecordData {
    /// The size of the record data.
    size: U16,

    /// The beginning of the actual data.
    data: [u8; 0],
}

//--- Access to the byte slice

impl Deref for RecordData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        let len = self.size.get() as _;
        let ptr = self.data.as_ptr();
        // SAFETY: A 'RecordData' always borrows the record data following it
        // when it is constructed, and so that data exists and can be read.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

impl DerefMut for RecordData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let len = self.size.get() as _;
        let ptr = self.data.as_mut_ptr();
        // SAFETY: A 'RecordData' always borrows the record data following it
        // when it is constructed, and so that data exists and is mutable.
        unsafe { core::slice::from_raw_parts_mut(ptr, len) }
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a RecordData {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (size, rest) = U16::ref_from_prefix(bytes)?;
        let length: usize = size.get() as _;
        let (_, rest) = <[u8]>::ref_from_prefix_with_elems(rest, length)?;
        // SAFETY: 'RecordData' is 'repr(transparent)' to 'U16'.
        Ok((unsafe { core::mem::transmute(size) }, rest))
    }
}
