//! The PTR record data type.

use core::cmp::Ordering;

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::name::CanonicalName;
use crate::new::base::parse::ParseMessageBytes;
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

#[cfg(feature = "zonefile")]
use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Ptr ------------------------------------------------------------

/// A pointer to another domain name.
///
/// A [`Ptr`] record is used with special domain names for pointing to other
/// locations in the domain name space.  It is conventionally used for reverse
/// lookups: for example, the [`Ptr`] record for `<addr>.in-addr.arpa` points
/// to the domain name using the IPv4 `<addr>` in an [`A`] record.  The same
/// technique works with `<addr>.ip6.arpa` for IPv6 addresses.
///
/// [`A`]: crate::new::rdata::A
///
/// [`Ptr`] is specified by [RFC 1035, section 3.3.12].
///
/// [RFC 1035, section 3.3.12]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.12
///
/// ## Wire format
///
/// The wire format of a [`Ptr`] record is simply the domain name of the name
/// server.  This domain name may be compressed in DNS messages.
///
/// ## Usage
///
/// Because [`Ptr`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// In order to build a [`Ptr`], it's first important to choose a domain name
/// type.  For short-term usage (where the [`Ptr`] is a local variable), it is
/// common to pick [`RevNameBuf`].  If the [`Ptr`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new::base::name::RevName
/// [`RevNameBuf`]: crate::new::base::name::RevNameBuf
///
/// The primary way to build a new [`Ptr`] is to construct each field manually.
/// To parse a [`Ptr`] from a DNS message, use [`ParseMessageBytes`].  In case
/// the input bytes don't use name compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new::base::name::{Name, RevNameBuf};
/// # use domain::new::base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new::rdata::Ptr;
/// #
/// // Build a 'Ptr' manually:
/// let manual: Ptr<RevNameBuf> = Ptr {
///     name: "example.org".parse().unwrap(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\x07example\x03org\x00";
/// # let mut buffer = [0u8; 13];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse a 'Ptr' from the wire format, without name decompression:
/// let from_wire: Ptr<RevNameBuf> = Ptr::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Ptr`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, this depends on
/// the domain name type.  It can be changed using [`Ptr::map_name()`] and
/// [`Ptr::map_name_by_ref()`].
///
/// For debugging, [`Ptr`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize a [`Ptr`] in the wire format, use [`BuildInMessage`] (which
/// supports name compression).  If name compression is not desired, use
/// [`BuildBytes`].
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BuildBytes,
    ParseBytes,
    SplitBytes,
)]
#[repr(transparent)]
pub struct Ptr<N> {
    /// The referenced domain name.
    pub name: N,
}

//--- Interaction

impl<N> Ptr<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Ptr<R> {
        Ptr {
            name: (f)(self.name),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Ptr<R> {
        Ptr {
            name: (f)(&self.name),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Ptr<N> {
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

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Ptr<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Ptr<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        self.name.build_in_message(contents, start, compressor)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for Ptr<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::PTR => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for Ptr<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::PTR => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N: Scan<'a>> Scan<'a> for Ptr<N> {
    /// Scan the data for a PTR record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-ptr = name ws*
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let name = N::scan(scanner, alloc, buffer)?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self { name })
        } else {
            Err(ScanError::Custom("unexpected data at end of PTR record"))
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new::base::name::RevNameBuf;
        use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

        use super::Ptr;

        let cases = [
            (
                b"example.org." as &[u8],
                Ok(b"\x00\x03org\x07example" as &[u8]),
            ),
            (b"", Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let mut tmp = None;
            assert_eq!(
                <Ptr<RevNameBuf>>::scan(&mut scanner, &alloc, &mut buffer)
                    .map(|s| tmp.insert(s.name).as_bytes()),
                expected
            );
        }
    }
}
