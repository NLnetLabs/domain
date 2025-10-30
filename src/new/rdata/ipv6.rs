//! IPv6 record data types.
//!
//! See [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596).

use core::cmp::Ordering;
use core::fmt;
use core::net::Ipv6Addr;
use core::str::FromStr;

use crate::new::base::build::{
    BuildInMessage, NameCompressor, TruncationError,
};
use crate::new::base::parse::ParseMessageBytes;
use crate::new::base::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError, SplitBytes,
    SplitBytesZC,
};
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- Aaaa -----------------------------------------------------------

/// The IPv6 address of a host responsible for this domain.
///
/// A [`Aaaa`] record indicates that a domain name is backed by a server that
/// can be reached over the Internet at the specified IPv6 address.  It does
/// not specify the server's capabilities (e.g. what protocols it supports);
/// those have to be communicated elsewhere.
///
/// [`Aaaa`] is specified by [RFC 3596, section 2].  It works identically to
/// the [`A`] record.
///
/// [`A`]: crate::new::rdata::A
/// [RFC 3596, section 2]: https://datatracker.ietf.org/doc/html/rfc3596#section-2
///
/// ## Wire Format
///
/// The wire format of a [`Aaaa`] record is the 16 bytes of its IPv6 address,
/// in conventional order (from most to least significant).  For example,
/// `2001::db8::` would be serialized as `20 01 0D B8 00 00 00 00 00 00 00 00
/// 00 00 00 00`.
///
/// The memory layout of the [`Aaaa`] type is identical to its serialization
/// in the wire format.  This means it can be parsed from the wire format in a
/// zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`Aaaa`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// There's a few ways to build an [`Aaaa`]:
///
/// ```
/// # use domain::new::base::wire::{ParseBytes, ParseBytesZC};
/// # use domain::new::rdata::Aaaa;
/// #
/// use core::net::Ipv6Addr;
///
/// // Build a 'Aaaa' from the raw bytes.
/// let from_raw = Aaaa {
///     octets: [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
/// };
///
/// // Convert an 'Ipv6Addr' into a 'Aaaa'.
/// let from_addr: Aaaa = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 0).into();
/// # assert_eq!(from_raw, from_addr);
///
/// // Parse a 'Aaaa' from a string.
/// let from_str: Aaaa = "2001:db8::".parse().unwrap();
/// # assert_eq!(from_raw, from_str);
///
/// // Parse a 'Aaaaa' from the DNS wire format.
/// let bytes = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let from_wire: Aaaa = Aaaa::parse_bytes(&bytes).unwrap();
/// # assert_eq!(from_raw, from_wire);
///
/// // ... even by reference (this is zero-copy).
/// let ref_from_wire: &Aaaa = Aaaa::parse_bytes_by_ref(&bytes).unwrap();
/// // It is also possible to use '<&Aaaa>::parse_bytes()'.
/// # assert_eq!(from_raw, *ref_from_wire);
/// ```
///
/// Since [`Aaaa`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.
///
/// For debugging and logging, [`Aaaa`] can be formatted using [`fmt::Debug`]
/// and [`fmt::Display`].
///
/// To serialize a [`Aaaa`] in the wire format, use [`BuildBytes`] (which
/// will serialize it to a given buffer) or [`AsBytes`] (which will
/// cast the [`Aaaa`] into a byte sequence in place).  It also supports
/// [`BuildInMessage`].
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct Aaaa {
    /// The IPv6 address octets.
    pub octets: [u8; 16],
}

//--- Converting to and from 'Ipv6Addr'

impl From<Ipv6Addr> for Aaaa {
    fn from(value: Ipv6Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<Aaaa> for Ipv6Addr {
    fn from(value: Aaaa) -> Self {
        Self::from(value.octets)
    }
}

//--- Canonical operations

impl CanonicalRecordData for Aaaa {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.octets.cmp(&other.octets)
    }
}

//--- Parsing from a string

impl FromStr for Aaaa {
    type Err = <Ipv6Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::from)
    }
}

//--- Formatting

impl fmt::Debug for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aaaa({self})")
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv6Addr::from(*self).fmt(f)
    }
}

//--- Parsing from DNS messages

impl ParseMessageBytes<'_> for Aaaa {
    fn parse_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        contents
            .get(start..)
            .ok_or(ParseError)
            .and_then(Self::parse_bytes)
    }
}

//--- Building into DNS messages

impl BuildInMessage for Aaaa {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let end = start + self.octets.len();
        let bytes = contents.get_mut(start..end).ok_or(TruncationError)?;
        bytes.copy_from_slice(&self.octets);
        Ok(end)
    }
}

//--- Parsing record data

impl ParseRecordData<'_> for Aaaa {}

impl ParseRecordDataBytes<'_> for Aaaa {
    fn parse_record_data_bytes(
        bytes: &'_ [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::AAAA => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}

impl<'a> ParseRecordData<'a> for &'a Aaaa {}

impl<'a> ParseRecordDataBytes<'a> for &'a Aaaa {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::AAAA => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
