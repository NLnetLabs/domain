//! The Service Locator record data type.
//!
//! See [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782).

use core::cmp::Ordering;

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::name::CanonicalName;
use crate::new::base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

//----------- Srv ------------------------------------------------------------

/// The location of a service.
///
/// An [`Srv`] record advertises the host and port at which a particular
/// service can be reached for a given domain. Multiple [`Srv`] records may
/// exist for the same service; clients use the [`priority`](Self::priority)
/// and [`weight`](Self::weight) fields to choose between them.
///
/// [`Srv`] is specified by [RFC 2782].
///
/// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
///
/// ## Wire Format
///
/// The wire format of an [`Srv`] record is the concatenation of three 16-bit
/// big-endian integers (priority, weight, port) followed by the target domain
/// name. Per [RFC 2782], the labels in the target name MUST NOT be compressed
/// when sending; this implementation will still decompress target names that
/// it receives, for compatibility with non-conforming senders.
///
/// ## Usage
///
/// Because [`Srv`] is a record data type, it is usually handled within an enum
/// like [`RecordData`]. This section describes how to use it independently
/// (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// In order to build an [`Srv`], it's first important to choose a domain name
/// type. For short-term usage (where the [`Srv`] is a local variable), it is
/// common to pick [`RevNameBuf`]. If the [`Srv`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new::base::name::RevName
/// [`RevNameBuf`]: crate::new::base::name::RevNameBuf
///
/// The primary way to build a new [`Srv`] is to construct each field manually.
/// To parse an [`Srv`] from a DNS message, use [`ParseMessageBytes`]. In case
/// the input bytes don't use name compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new::base::name::{Name, RevNameBuf};
/// # use domain::new::base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new::rdata::Srv;
/// #
/// // Build an 'Srv' manually:
/// let manual: Srv<RevNameBuf> = Srv {
///     priority: 10.into(),
///     weight: 20.into(),
///     port: 5060.into(),
///     target: "sip.example.org".parse().unwrap(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\
///     \x00\x0A\x00\x14\x13\xC4\
///     \x03sip\x07example\x03org\x00";
/// # let mut buffer = [0u8; 23];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse an 'Srv' from the wire format, without name decompression:
/// let from_wire: Srv<RevNameBuf> = Srv::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Srv`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around. However, this depends on
/// the domain name type. It can be changed using [`Srv::map_name()`] and
/// [`Srv::map_name_by_ref()`].
///
/// For debugging, [`Srv`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize an [`Srv`] in the wire format, use [`BuildInMessage`] (which
/// supports name compression). If name compression is not desired, use
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
pub struct Srv<N> {
    /// The priority of this target host.
    ///
    /// Clients MUST attempt to contact target hosts in order of increasing
    /// priority; targets at the same priority are selected using
    /// [`weight`](Self::weight).
    pub priority: U16,

    /// The relative weight for selection among targets of equal priority.
    ///
    /// Larger values are more likely to be selected. A weight of zero
    /// indicates that the target should only be selected if no other targets
    /// of the same priority are available.
    pub weight: U16,

    /// The TCP/UDP port on which the service is offered.
    pub port: U16,

    /// The domain name of the target host.
    ///
    /// A target equal to the root domain (`.`) means that the service is
    /// decidedly not available at this domain.
    pub target: N,
}

//--- Interaction

impl<N> Srv<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Srv<R> {
        Srv {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: (f)(self.target),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Srv<R> {
        Srv {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: (f)(&self.target),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Srv<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.priority.build_bytes(bytes)?;
        let bytes = self.weight.build_bytes(bytes)?;
        let bytes = self.port.build_bytes(bytes)?;
        let bytes = self.target.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.weight.cmp(&other.weight))
            .then_with(|| self.port.cmp(&other.port))
            .then_with(|| self.target.cmp_lowercase_composed(&other.target))
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Srv<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (&priority, rest) = <&U16>::split_message_bytes(contents, start)?;
        let (&weight, rest) = <&U16>::split_message_bytes(contents, rest)?;
        let (&port, rest) = <&U16>::split_message_bytes(contents, rest)?;
        let target = N::parse_message_bytes(contents, rest)?;
        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Srv<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self
            .priority
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self
            .weight
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self
            .port
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self.target.build_in_message(contents, start, compressor)?;
        Ok(start)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for Srv<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SRV => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for Srv<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SRV => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
