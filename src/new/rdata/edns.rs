//! Record data types for EDNS (Extension Mechanism for DNS).
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use core::cmp::Ordering;
use core::fmt;
use core::iter::FusedIterator;

use crate::new::base::build::{
    BuildInMessage, NameCompressor, TruncationError,
};
use crate::new::base::wire::{
    AsBytes, BuildBytes, ParseBytesZC, ParseError, SplitBytesZC,
};
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::new::edns::{EdnsOption, UnparsedEdnsOption};
use crate::utils::dst::UnsizedCopy;

//----------- Opt ------------------------------------------------------------

/// EDNS options.
///
/// An [`Opt`] record holds an unordered set of [`EdnsOption`]s, which provide
/// additional non-critical information about the containing DNS message.  It
/// has fairly different semantics from other record data types, since it only
/// exists for communication between peers (it is not part of any zone, and it
/// is not cached).  As such, it is often called a "pseudo-RR".
///
/// A record containing [`Opt`] data is interpreted differently from records
/// containing normal data types (its class and TTL fields are different).
/// [`EdnsRecord`] provides this interpretation and offers way to convert to
/// and from normal [`Record`]s.
///
/// [`EdnsRecord`]: crate::new::edns::EdnsRecord
/// [`Record`]: crate::new::base::Record
///
/// [`Opt`] is specified by [RFC 6891, section 6].  For more information about
/// EDNS, see [`crate::new::edns`].
///
/// [RFC 6891, section 6]: https://datatracker.ietf.org/doc/html/rfc6891#section-6
///
/// ## Wire Format
///
/// The wire format of an [`Opt`] record is the concatenation of zero or more
/// EDNS options.  An EDNS option is serialized as a 16-bit big-endian code
/// (specifying the meaning of the option), a 16-bit big-endian size (the size
/// of the option data), and the variable-length option data.
///
/// The memory layout of the [`Opt`] type is identical to its serialization in
/// the wire format.  This means that it can be parsed from the wire format in
/// a zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`Opt`] is a record data type, it is usually handled within an
/// enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// [`Opt`] is a _dynamically sized type_ (DST).  It is not possible to
/// store an [`Opt`] in place (e.g. in a local variable); it must be held
/// indirectly, via a reference or a smart pointer type like [`Box`].  This
/// makes it more difficult to _create_ new [`Opt`]s; but once they are placed
/// somewhere, they can be used by reference (i.e. `&Opt`) exactly like any
/// other type.
///
/// [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
///
/// It is currently a bit difficult to build a new [`Opt`] from scratch.  It
/// is easiest to build the wire format representation of the [`Opt`] manually
/// (by building a sequence of [`EdnsOption`]s) and then to parse it.
///
/// ```
/// # use domain::new::base::wire::{BuildBytes, ParseBytesZC, U16};
/// # use domain::new::edns::{EdnsOption, OptionCode, UnknownOptionData};
/// # use domain::new::rdata::Opt;
/// #
/// // Parse an 'Opt' from the DNS wire format:
/// let bytes = [0, 10, 0, 8, 248, 80, 41, 151, 244, 171, 53, 202, 0, 0, 0, 0];
/// let from_bytes: &Opt = Opt::parse_bytes_by_ref(&bytes).unwrap();
/// // It is also possible to use '<&Opt>::parse_bytes()'.
///
/// let cookie = [248, 80, 41, 151, 244, 171, 53, 202].into();
/// let options = [
///     EdnsOption::ClientCookie(cookie),
///     EdnsOption::Unknown(
///         OptionCode { code: U16::new(0) },
///         UnknownOptionData::parse_bytes_by_ref(&[]).unwrap(),
///     ),
/// ];
///
/// // Iterate over the options in an 'Opt':
/// for (l, r) in from_bytes.options().zip(&options) {
///     assert_eq!(l.as_ref(), Ok(r));
/// }
///
/// // Build the DNS wire format for an 'Opt' manually:
/// let mut buffer = vec![0u8; options.built_bytes_size()];
/// options.build_bytes(&mut buffer).unwrap();
/// assert_eq!(buffer, bytes);
///
/// // Parse an 'Opt' from the wire format, but on the heap:
/// let buffer: Box<[u8]> = buffer.into_boxed_slice();
/// let from_boxed_bytes: Box<Opt> = Opt::parse_bytes_in(buffer).unwrap();
/// assert_eq!(from_bytes, &*from_boxed_bytes);
/// ```
///
/// As a DST, [`Opt`] does not implement [`Copy`] or [`Clone`].  Instead, it
/// implements [`UnsizedCopy`].  An [`Opt`], held by reference, can be copied
/// into a different container (e.g. `Box`) using [`unsized_copy_into()`]
///
/// [`unsized_copy_into()`]: UnsizedCopy::unsized_copy_into()
///
/// For debugging, [`Opt`] can be formatted using [`fmt::Debug`].
///
/// To serialize a [`Opt`] in the wire format, use [`BuildBytes`] (which
/// will serialize it to a given buffer) or [`AsBytes`] (which will
/// cast the [`Opt`] into a byte sequence in place).  It also supports
/// [`BuildInMessage`].
#[derive(AsBytes, BuildBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct Opt {
    /// The raw serialized options.
    contents: [u8],
}

//--- Associated Constants

impl Opt {
    /// Empty OPT record data.
    pub const EMPTY: &'static Self =
        unsafe { core::mem::transmute(&[] as &[u8]) };
}

//--- Construction

impl Opt {
    /// Assume a byte sequence is a valid [`Opt`].
    ///
    /// ## Safety
    ///
    /// The byte sequence must a valid instance of [`Opt`] in the wire format;
    /// it must contain a sequence of [`EdnsOption`]s, concatenated together.
    /// The contents of each [`EdnsOption`] need not be valid (i.e. they can
    /// be incorrect with respect to the underlying option type).  The byte
    /// sequence must be at most 65,535 bytes long.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Opt' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute::<&[u8], &Opt>(bytes) }
    }
}

//--- Inspection

impl Opt {
    /// Traverse the options in this record.
    ///
    /// Options that cannot be parsed are returned as [`UnparsedEdnsOption`]s.
    pub fn options(&self) -> EdnsOptionsIter<'_> {
        EdnsOptionsIter::new(&self.contents)
    }
}

//--- Equality

impl PartialEq for Opt {
    /// Compare two [`Opt`] records.
    ///
    /// This is primarily a debugging and testing aid; it will ensure that
    /// both records have the same EDNS options in the same order, even though
    /// order is semantically irrelevant.
    fn eq(&self, other: &Self) -> bool {
        self.options().eq(other.options())
    }
}

impl PartialEq<[EdnsOption<'_>]> for Opt {
    /// Compare an [`Opt`] to a sequence of [`EdnsOption`]s.
    ///
    /// This is primarily a debugging and testing aid; it will ensure that
    /// both records have the same EDNS options in the same order, even though
    /// order is semantically irrelevant.
    fn eq(&self, other: &[EdnsOption<'_>]) -> bool {
        self.options().eq(other.iter().map(|opt| Ok(opt.clone())))
    }
}

impl<const N: usize> PartialEq<[EdnsOption<'_>; N]> for Opt {
    /// Compare an [`Opt`] to a sequence of [`EdnsOption`]s.
    ///
    /// This is primarily a debugging and testing aid; it will ensure that
    /// both records have the same EDNS options in the same order, even though
    /// order is semantically irrelevant.
    fn eq(&self, other: &[EdnsOption<'_>; N]) -> bool {
        *self == *other.as_slice()
    }
}

impl PartialEq<[EdnsOption<'_>]> for &Opt {
    /// Compare an [`Opt`] to a sequence of [`EdnsOption`]s.
    ///
    /// This is primarily a debugging and testing aid; it will ensure that
    /// both records have the same EDNS options in the same order, even though
    /// order is semantically irrelevant.
    fn eq(&self, other: &[EdnsOption<'_>]) -> bool {
        **self == *other
    }
}

impl<const N: usize> PartialEq<[EdnsOption<'_>; N]> for &Opt {
    /// Compare an [`Opt`] to a sequence of [`EdnsOption`]s.
    ///
    /// This is primarily a debugging and testing aid; it will ensure that
    /// both records have the same EDNS options in the same order, even though
    /// order is semantically irrelevant.
    fn eq(&self, other: &[EdnsOption<'_>; N]) -> bool {
        **self == *other.as_slice()
    }
}

impl Eq for Opt {}

//--- Canonical operations

impl CanonicalRecordData for Opt {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.contents.cmp(&other.contents)
    }
}

//--- Building into DNS messages

impl BuildInMessage for Opt {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let end = start + self.contents.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(&self.contents);
        Ok(end)
    }
}

//--- Parsing from bytes

unsafe impl ParseBytesZC for Opt {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        // Make sure the slice is 64KiB or less.
        if bytes.len() > 65535 {
            return Err(ParseError);
        }

        let mut offset = 0usize;
        while offset < bytes.len() {
            // NOTE: We don't check the code here, since we won't validate the
            //   option by its actual type (even if we know how to).
            offset += 2;

            let size = bytes.get(offset..offset + 2).ok_or(ParseError)?;
            let size: usize = u16::from_be_bytes([size[0], size[1]]).into();
            offset += 2;

            // Make sure the entire data section exists.
            let _ = bytes.get(offset..offset + size).ok_or(ParseError)?;
            offset += size;
        }

        // Now, 'offset == bytes.len()', and the whole slice is valid.

        // SAFETY: 'Opt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], &Opt>(bytes) })
    }
}

//--- Formatting

impl fmt::Debug for Opt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Opt").field(&self.options()).finish()
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a Opt {}

impl<'a> ParseRecordDataBytes<'a> for &'a Opt {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::OPT => Opt::parse_bytes_by_ref(bytes),
            _ => Err(ParseError),
        }
    }
}

//----------- EdnsOptionsIter ------------------------------------------------

/// An iterator over EDNS options in an [`Opt`] record.
#[derive(Clone)]
pub struct EdnsOptionsIter<'a> {
    /// The serialized options to parse from.
    options: &'a [u8],
}

//--- Construction

impl<'a> EdnsOptionsIter<'a> {
    /// Construct a new [`EdnsOptionsIter`].
    pub const fn new(options: &'a [u8]) -> Self {
        Self { options }
    }
}

//--- Inspection

impl<'a> EdnsOptionsIter<'a> {
    /// The serialized options yet to be parsed.
    pub const fn remaining(&self) -> &'a [u8] {
        self.options
    }
}

//--- Formatting

impl fmt::Debug for EdnsOptionsIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut entries = f.debug_set();
        for option in self.clone() {
            match option {
                Ok(option) => entries.entry(&option),
                Err(_err) => entries.entry(&format_args!("<error>")),
            };
        }
        entries.finish()
    }
}

//--- Iteration

impl<'a> Iterator for EdnsOptionsIter<'a> {
    type Item = Result<EdnsOption<'a>, &'a UnparsedEdnsOption>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.options.is_empty() {
            let (option, rest) = UnparsedEdnsOption::split_bytes_by_ref(
                self.options,
            )
            .expect("An 'Opt' always contains valid 'UnparsedEdnsOption's");
            self.options = rest;
            Some(EdnsOption::try_from(option).map_err(|_| option))
        } else {
            None
        }
    }
}

impl FusedIterator for EdnsOptionsIter<'_> {}
