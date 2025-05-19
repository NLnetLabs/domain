//! The NS record data type.

use core::cmp::Ordering;

use crate::new_base::build::{BuildInMessage, NameCompressor};
use crate::new_base::name::CanonicalName;
use crate::new_base::parse::ParseMessageBytes;
use crate::new_base::wire::{
    BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::new_base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

//----------- Ns -------------------------------------------------------------

/// The authoritative name server for this domain.
///
/// An [`Ns`] record indicates that a domain name is the apex of a DNS zone,
/// and it specifies (the domain name of) the name server that queries about
/// the domain name (and its descendants) should be sent to.  A domain name
/// can be associated with multiple name servers (using multiple [`Ns`]
/// records).
///
/// DNS is designed around the concept of delegating responsibility for domain
/// names.  If a name server responds to a query with an empty answer section,
/// but with [`Ns`] records in the authority section, it is claiming to not be
/// the authoritative source of information about the queried domain name;
/// the [`Ns`] records specify name servers to whom that authority has been
/// delegated.
///
/// While [`Ns`] records are typically served by a name server to indicate a
/// zone cut, that name server is not authoritative for the record; the [`Ns`]
/// record belongs to the delegated zone and the delegated name server(s).
///
/// [`Ns`] is specified by [RFC 1035, section 3.3.11].
///
/// [RFC 1035, section 3.3.11]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11
///
/// ## Wire format
///
/// The wire format of an [`Ns`] record is simply the domain name of the name
/// server.  This domain name may be compressed in DNS messages.
///
/// ## Usage
///
/// Because [`Ns`] is a record data type, it is usually handled within an enum
/// like [`RecordData`].  This section describes how to use it independently
/// (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new_rdata::RecordData
///
/// In order to build an [`Ns`], it's first important to choose a domain name
/// type.  For short-term usage (where the [`Ns`] is a local variable), it is
/// common to pick [`RevNameBuf`].  If the [`Ns`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new_base::name::RevName
/// [`RevNameBuf`]: crate::new_base::name::RevNameBuf
///
/// The primary way to build a new [`Ns`] is to construct each field manually.
/// To parse an [`Ns`] from a DNS message, use [`ParseMessageBytes`].  In case
/// the input bytes don't use name compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new_base::name::{Name, RevNameBuf};
/// # use domain::new_base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new_rdata::Ns;
/// #
/// // Build an 'Ns' manually:
/// let manual: Ns<RevNameBuf> = Ns {
///     server: "example.org".parse().unwrap(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\x07example\x03org\x00";
/// # let mut buffer = [0u8; 13];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse an 'Ns' from the wire format, without name decompression:
/// let from_wire: Ns<RevNameBuf> = Ns::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Ns`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, this depends on
/// the domain name type.  It can be changed using [`Ns::map_name()`] and
/// [`Ns::map_name_by_ref()`].
///
/// For debugging, [`Ns`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize an [`Ns`] in the wire format, use [`BuildInMessage`] (which
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
pub struct Ns<N> {
    /// The name of the authoritative server.
    pub server: N,
}

//--- Interaction

impl<N> Ns<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Ns<R> {
        Ns {
            server: (f)(self.server),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Ns<R> {
        Ns {
            server: (f)(&self.server),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Ns<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.server.build_lowercased_bytes(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.server.cmp_lowercase_composed(&other.server)
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Ns<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|server| Self { server })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Ns<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        self.server.build_in_message(contents, start, compressor)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for Ns<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::NS => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for Ns<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::NS => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
