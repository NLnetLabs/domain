//! The CNAME record data type.

use core::cmp::Ordering;

use crate::new_base::build::{self, BuildIntoMessage, BuildResult};
use crate::new_base::name::CanonicalName;
use crate::new_base::parse::ParseMessageBytes;
use crate::new_base::wire::{
    BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::new_base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

//----------- CName ----------------------------------------------------------

/// The canonical name for this domain.
///
/// A [`CName`] record indicates that a domain name is an alias.  Any data
/// associated with that domain name originates from the "canonical" domain
/// name (with a few DNSSEC-related exceptions).  If a domain name is an
/// alias, it has a single canonical name (see [RFC 2181, section 10.1]); it
/// cannot have multiple distinct [`CName`] records.
///
/// [RFC 2181, section 10.1]: https://datatracker.ietf.org/doc/html/rfc2181#section-10.1
///
/// [`CName`] is specified by [RFC 1035, section 3.3.1].  The behaviour of DNS
/// lookups and name servers is specified by [RFC 1034, section 3.6.2].
///
/// [RFC 1034, section 3.6.2]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.6.2
/// [RFC 1035, section 3.3.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1
///
/// ## Wire Format
///
/// The wire format of a [`CName`] record is simply the canonical domain name.
/// This domain name may be compressed in DNS messages.
///
/// ## Usage
///
/// Because [`CName`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new_rdata::RecordData
///
/// In order to build a [`CName`], it's first important to choose a domain
/// name type.  For short-term usage (where the [`CName`] is a local
/// variable), it is common to pick [`RevNameBuf`].  If the [`CName`] will
/// be placed on the heap, <code>Box&lt;[`RevName`]&gt;</code> will be more
/// efficient.
///
/// [`RevName`]: crate::new_base::name::RevName
/// [`RevNameBuf`]: crate::new_base::name::RevNameBuf
///
/// The primary way to build a new [`CName`] is to construct each
/// field manually. To parse a [`CName`] from a DNS message, use
/// [`ParseMessageBytes`].  In case the input bytes don't use name
/// compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new_base::name::{Name, RevNameBuf};
/// # use domain::new_base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new_rdata::CName;
/// #
/// // Build a 'CName' manually:
/// let manual: CName<RevNameBuf> = CName {
///     name: "example.org".parse().unwrap(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\x07example\x03org\x00";
/// # let mut buffer = [0u8; 13];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse a 'CName' from the wire format, without name decompression:
/// let from_wire: CName<RevNameBuf> = CName::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`CName`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, this depends on
/// the domain name type.  It can be changed using [`CName::map_name()`] and
/// [`CName::map_name_by_ref()`].
///
/// For debugging, [`CName`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize a [`CName`] in the wire format, use [`BuildIntoMessage`]
/// (which supports name compression).  If name compression is not desired,
/// use [`BuildBytes`].
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
pub struct CName<N> {
    /// The canonical name.
    pub name: N,
}

//--- Interaction

impl<N> CName<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> CName<R> {
        CName {
            name: (f)(self.name),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> CName<R> {
        CName {
            name: (f)(&self.name),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for CName<N> {
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

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for CName<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: BuildIntoMessage> BuildIntoMessage for CName<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for CName<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::CNAME => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for CName<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::CNAME => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
