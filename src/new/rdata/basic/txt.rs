//! The TXT record data type.

use core::{cmp::Ordering, fmt};

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, CharStr, ParseRecordData, ParseRecordDataBytes,
    RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- Txt ------------------------------------------------------------

/// Free-form text strings about this domain.
///
/// A [`Txt`] record holds a collection of "strings" (really byte sequences),
/// with no fixed purpose.  Usually, a [`Txt`] record holds a single string;
/// if data has to be stored for different purposes, multiple [`Txt`] records
/// would be used.
///
/// Currently, [`Txt`] records are used systematically for e-mail security,
/// e.g. in SPF ([RFC 7208, section 3]), DKIM ([RFC 6376, section 3.6.2]), and
/// DMARC ([RFC 7489, section 6.1]).  As a record data type with no strict
/// semantics and arbitrary data storage, it is likely to continue being
/// used.
///
/// [RFC 6376, section 3.6.2]: https://datatracker.ietf.org/doc/html/rfc6376#section-3.6.2
/// [RFC 7208, section 3]: https://datatracker.ietf.org/doc/html/rfc7208#section-3
/// [RFC 7489, section 6.1]: https://datatracker.ietf.org/doc/html/rfc7489#section-6.1
///
/// [`Txt`] is specified by [RFC 1035, section 3.3.14].
///
/// [RFC 1035, section 3.3.14]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14
///
/// ## Wire Format
///
/// The wire format of a [`Txt`] record is the concatenation of a (non-empty)
/// sequence of "character strings" (see [`CharStr`]).  A character string is
/// serialized as a 1-byte length, followed by up to 255 bytes of content.
///
/// The memory layout of the [`Txt`] type is identical to its serialization in
/// the wire format.  This means it can be parsed from the wire format in a
/// zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`Txt`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// [`Txt`] is a _dynamically sized type_ (DST).  It is not possible to store
/// a [`Txt`] in place (e.g. in a local variable); it must be held indirectly,
/// via a reference or a smart pointer type like [`Box`].  This makes it more
/// difficult to _create_ new [`Txt`]s; but once they are placed somewhere,
/// they can be used by reference (i.e. `&Txt`) exactly like any other type.
///
/// [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
///
/// It is currently a bit difficult to build a new [`Txt`] from scratch.  It
/// is easiest to build the wire format representation of the [`Txt`] manually
/// (by building a sequence of [`CharStr`]s) and then to parse it.
///
/// ```
/// # use domain::new::base::CharStrBuf;
/// # use domain::new::base::wire::ParseBytesZC;
/// # use domain::new::rdata::Txt;
/// #
/// // From an existing wire-format representation.
/// let bytes = b"\x0DHello, World!\x0AAnd again!";
/// let from_bytes: &Txt = Txt::parse_bytes_by_ref(bytes).unwrap();
/// // It is also possible to use '<&Txt>::parse_bytes()'.
///
/// // To build a wire-format representation manually:
/// let strings: [CharStrBuf; 2] = [
///     "Hello, World!".parse().unwrap(),
///     "And again!".parse().unwrap(),
/// ];
/// let mut buffer: Vec<u8> = Vec::new();
/// for string in &strings {
///     buffer.extend_from_slice(string.wire_bytes());
/// }
/// assert_eq!(buffer.as_slice(), bytes);
///
/// // From an existing wire-format representation, but on the heap:
/// let buffer: Box<[u8]> = buffer.into_boxed_slice();
/// let from_boxed_bytes: Box<Txt> = Txt::parse_bytes_in(buffer).unwrap();
/// assert_eq!(from_bytes, &*from_boxed_bytes);
/// ```
///
/// As a DST, [`Txt`] does not implement [`Copy`] or [`Clone`].  Instead, it
/// implements [`UnsizedCopy`].  A [`Txt`], held by reference, can be copied
/// into a different container (e.g. `Box`) using [`unsized_copy_into()`].
///
/// [`unsized_copy_into()`]: UnsizedCopy::unsized_copy_into()
///
/// For debugging, [`Txt`] can be formatted using [`fmt::Debug`].
///
/// To serialize a [`Txt`] in the wire format, use [`BuildBytes`] (which
/// will serialize it to a given buffer) or [`AsBytes`] (which will
/// cast the [`Txt`] into a byte sequence in place).  It also supports
/// [`BuildInMessage`].
#[derive(AsBytes, BuildBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct Txt {
    /// The text strings, as concatenated [`CharStr`]s.
    content: [u8],
}

//--- Construction

impl Txt {
    /// Assume a byte sequence is a valid [`Txt`].
    ///
    /// ## Safety
    ///
    /// The byte sequence must a valid instance of [`Txt`] in the wire format;
    /// it must contain one or more serialized [`CharStr`]s, concatenated
    /// together.  The byte sequence must be at most 65,535 bytes long.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute::<&[u8], &Txt>(bytes) }
    }
}

//--- Interaction

impl Txt {
    /// Iterate over the [`CharStr`]s in this record.
    pub fn iter(&self) -> impl Iterator<Item = &CharStr> + '_ {
        // NOTE: A TXT record always has at least one 'CharStr' within.
        let first = <&CharStr>::split_bytes(&self.content)
            .expect("'Txt' records always contain valid 'CharStr's");
        core::iter::successors(Some(first), |(_, rest)| {
            (!rest.is_empty()).then(|| {
                <&CharStr>::split_bytes(rest)
                    .expect("'Txt' records always contain valid 'CharStr's")
            })
        })
        .map(|(elem, _rest)| elem)
    }
}

//--- Canonical operations

impl CanonicalRecordData for Txt {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.content.cmp(&other.content)
    }
}

//--- Building into DNS messages

impl BuildInMessage for Txt {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let end = start + self.content.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(&self.content);
        Ok(end)
    }
}

//--- Parsing from bytes

// SAFETY: The implementations of 'parse_bytes_by_{ref,mut}()' always parse
// the entirety of the input on success, satisfying the safety requirements.
unsafe impl ParseBytesZC for Txt {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        // Make sure the slice is 64KiB or less.
        if bytes.len() > 65535 {
            return Err(ParseError);
        }

        // The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_bytes(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_bytes(rest)?;
        }

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], &Self>(bytes) })
    }
}

//--- Formatting

impl fmt::Debug for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Content<'a>(&'a Txt);
        impl fmt::Debug for Content<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        f.debug_tuple("Txt").field(&Content(self)).finish()
    }
}

//--- Equality

impl PartialEq for Txt {
    /// Compare two [`Txt`]s for equality.
    ///
    /// Two [`Txt`]s are considered equal if they have an equal sequence of
    /// character strings, laid out in the same order; corresponding character
    /// strings are compared ASCII-case-insensitively.
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Txt {}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a Txt {}

impl<'a> ParseRecordDataBytes<'a> for &'a Txt {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::TXT => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
