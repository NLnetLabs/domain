//! The MX record data type.

use core::cmp::Ordering;

use crate::new_base::build::{BuildInMessage, NameCompressor};
use crate::new_base::name::CanonicalName;
use crate::new_base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new_base::wire::*;
use crate::new_base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

//----------- Mx -------------------------------------------------------------

/// A host that can exchange mail for this domain.
///
/// An [`Mx`] record indicates that a domain name can receive e-mail, and it
/// specifies (the domain name of) the mail server that e-mail for that domain
/// should be sent to.  A domain name can be associated with multiple mail
/// servers (using multiple [`Mx`] records); each one is assigned a priority
/// for load balancing.
///
// TODO: If there's a conventional algorithm for picking a mail server (i.e.
// how the probabilities are calculated for a random selection), add it here.
//
/// [`Mx`] is specified by [RFC 1035, section 3.3.9].
///
/// [RFC 1035, section 3.3.9]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.9
///
/// ## Wire Format
///
/// The wire format of an [`Mx`] record is the 16-bit preference number (as a
/// big-endian integer) followed by the domain name of the mail server.  This
/// domain name may be compressed in DNS messages.
///
/// ## Usage
///
/// Because [`Mx`] is a record data type, it is usually handled within an enum
/// like [`RecordData`].  This section describes how to use it independently
/// (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new_rdata::RecordData
///
/// In order to build an [`Mx`], it's first important to choose a domain name
/// type.  For short-term usage (where the [`Mx`] is a local variable), it is
/// common to pick [`RevNameBuf`].  If the [`Mx`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new_base::name::RevName
/// [`RevNameBuf`]: crate::new_base::name::RevNameBuf
///
/// The primary way to build a new [`Mx`] is to construct each field manually.
/// To parse an [`Mx`] from a DNS message, use [`ParseMessageBytes`].  In case
/// the input bytes don't use name compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new_base::name::{Name, RevNameBuf};
/// # use domain::new_base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new_rdata::Mx;
/// #
/// // Build an 'Mx' manually:
/// let manual: Mx<RevNameBuf> = Mx {
///     preference: 10.into(),
///     exchange: "example.org".parse().unwrap(),
/// };
///
/// let bytes = b"\x00\x0A\x07example\x03org\x00";
/// # let mut buffer = [0u8; 15];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse an 'Mx' from the wire format, without name decompression:
/// let from_wire: Mx<RevNameBuf> = Mx::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Mx`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, this depends on
/// the domain name type.  It can be changed using [`Mx::map_name()`] and
/// [`Mx::map_name_by_ref()`].
///
/// For debugging, [`Mx`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize an [`Mx`] in the wire format, use [`BuildInMessage`] (which
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    SplitBytes,
)]
#[repr(C)]
pub struct Mx<N> {
    /// The preference for this host over others.
    pub preference: U16,

    /// The domain name of the mail exchanger.
    pub exchange: N,
}

//--- Interaction

impl<N> Mx<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Mx<R> {
        Mx {
            preference: self.preference,
            exchange: (f)(self.exchange),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Mx<R> {
        Mx {
            preference: self.preference,
            exchange: (f)(&self.exchange),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Mx<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.preference.build_bytes(bytes)?;
        let bytes = self.exchange.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.preference.cmp(&other.preference).then_with(|| {
            self.exchange.cmp_lowercase_composed(&other.exchange)
        })
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Mx<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (&preference, rest) =
            <&U16>::split_message_bytes(contents, start)?;
        let exchange = N::parse_message_bytes(contents, rest)?;
        Ok(Self {
            preference,
            exchange,
        })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Mx<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self
            .preference
            .as_bytes()
            .build_in_message(contents, start, name)?;
        start = self.exchange.build_in_message(contents, start, name)?;
        Ok(start)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for Mx<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::MX => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for Mx<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::MX => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
