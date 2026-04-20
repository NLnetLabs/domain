//! The DNAME record data type.
//!
//! See [RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672).

use core::cmp::Ordering;

use crate::new::base::build::{
    AsBytes, BuildBytes, BuildInMessage, NameCompressor,
};
use crate::new::base::name::{CanonicalName, Name};
use crate::new::base::wire::{
    ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- DName ----------------------------------------------------------

/// Redirection for the descendants of this domain.
///
/// A [`DName`] record indicates that a doamin name is a (partial!) alias.
/// Queries for data _under_ that domain name (not that domain name itself)
/// are redirected to the specified target.  A domain name can have at most
/// one [`DName`] record; in this case, it cannot define subordinate records
/// nor have a [`CName`] record.  It is conceptually similar to [`CName`].
///
/// [`DName`] is specified by [RFC 6672].
///
/// [`CName`]: super::CName
/// [RFC 6672]: https://datatracker.ietf.org/doc/html/rfc6672
///
/// ## Wire Format
///
/// The wire format of a [`DName`] record is simply the target domain name.
/// This domain name *cannot* be compressed in DNS messages.
///
/// The memory layout of the [`DName`] type is identical to its serialization
/// in the wire format.  This means that it can be parsed from the wire format
/// in a zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`DName`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// [`DName`] is a _dynamically sized type_ (DST).  It is not possible to
/// store an [`DName`] in place (e.g. in a local variable); it must be held
/// indirectly, via a reference or a smart pointer type like [`Box`].  This
/// makes it more difficult to _create_ new [`DName`]s; but once they are
/// placed somewhere, they can be used by reference (i.e. `&DName`) exactly
/// like any other type.
///
/// [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
///
/// It is currently a bit difficult to build a new [`DName`] from scratch.  It
/// is easiest to use [`DName::new()`] on a reference to a [`Name`], or to
/// build the wire format representation of the [`DName`] manually and then to
/// parse it.
///
/// ```
/// # use domain::new::base::wire::{AsBytes, ParseBytes};
/// # use domain::new::base::name::NameBuf;
/// # use domain::new::rdata::DName;
/// # use domain::utils::dst::UnsizedCopy;
/// #
/// // Parse a 'Name' and build a 'DName' from there:
/// let name = "example.org".parse::<NameBuf>().unwrap();
/// let dname = DName::new(&name);
///
/// // Parse a 'DName' from the DNS wire format:
/// let bytes = b"\x07example\x03org\x00";
/// let from_bytes: &DName = <&DName>::parse_bytes(bytes).unwrap();
/// assert_eq!(dname.as_bytes(), bytes);
///
/// // Copy a 'DName' onto the heap:
/// let heaped: Box<DName> = dname.unsized_copy_into();
/// ```
///
/// As a DST, [`DName`] does not implement [`Copy`] or [`Clone`].  Instead, it
/// implements [`UnsizedCopy`].  A [`DName`], held by reference, can be copied
/// into a different container (e.g. `Box`) using [`unsized_copy_into()`]
///
/// [`unsized_copy_into()`]: UnsizedCopy::unsized_copy_into()
///
/// For debugging, [`DName`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize a [`DName`] in the wire format, use [`BuildBytes`]
/// (which will serialize it to a given buffer) or [`AsBytes`] (which will
/// cast the [`DName`] into a byte sequence in place).  It also supports
/// [`BuildInMessage`].
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct DName {
    /// The target name.
    pub name: Name,
}

//--- Construction

impl DName {
    /// Wrap a domain name as a [`DName`].
    pub const fn new(target: &Name) -> &Self {
        // SAFETY: 'DName' is 'repr(transparent)' to 'Name'.
        unsafe { core::mem::transmute::<&Name, &Self>(target) }
    }
}

//--- Canonical operations

impl CanonicalRecordData for DName {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.name.build_lowercased_bytes(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.name.cmp_lowercase_composed(&other.name)
    }
}

//--- Building into DNS messages

impl BuildInMessage for DName {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        self.name.build_in_message(contents, start, compressor)
    }
}

//--- Parsing from bytes

impl<'a> ParseBytes<'a> for &'a DName {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        <&Name>::parse_bytes(bytes).map(DName::new)
    }
}

impl<'a> SplitBytes<'a> for &'a DName {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        <&Name>::split_bytes(bytes)
            .map(|(name, rest)| (DName::new(name), rest))
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a DName {}

impl<'a> ParseRecordDataBytes<'a> for &'a DName {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::DNAME => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
