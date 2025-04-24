//! The A record data type.

use core::cmp::Ordering;
use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;

use crate::new_base::build::{self, BuildIntoMessage};
use crate::new_base::parse::ParseMessageBytes;
use crate::new_base::wire::*;
use crate::new_base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- A --------------------------------------------------------------

/// The IPv4 address of a host responsible for this domain.
///
/// An [`A`] record indicates that a domain name is backed by a server that
/// can be reached over the Internet at the specified IPv4 address.  It does
/// not specify the server's capabilities (e.g. what protocols it supports);
/// those have to be communicated elsewhere.
///
/// [`A`] is specified by [RFC 1035, section 3.4.1].
///
/// [RFC 1035, section 3.4.1]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1
///
/// ## Wire Format
///
/// The wire format of an [`A`] record is the 4 bytes of its IPv4 address, in
/// conventional order (from most to least significant).  For example,
/// `127.0.0.1` would be serialized as `7F 00 00 01`.
///
/// The memory layout of the [`A`] type is identical to its serialization in
/// the wire format.  This means it can be parsed from the wire format in a
/// zero-copy fashion, which is more efficient.
///
/// ## Usage
///
/// Because [`A`] is a record data type, it is usually handled within an enum
/// like [`RecordData`].  This section describes how to use it independently
/// (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new_rdata::RecordData
///
/// There's a few ways to build an [`A`]:
///
/// ```
/// # use domain::new_base::wire::{ParseBytes, ParseBytesZC};
/// # use domain::new_rdata::A;
/// #
/// use core::net::Ipv4Addr;
///
/// // From the raw bytes.
/// let from_raw = A { octets: [127, 0, 0, 1] };
///
/// // Convert an 'Ipv4Addr' into an 'A'.
/// let from_addr: A = Ipv4Addr::new(127, 0, 0, 1).into();
/// # assert_eq!(from_raw, from_addr);
///
/// // Parse an 'A' from a string.
/// let from_str: A = "127.0.0.1".parse().unwrap();
/// # assert_eq!(from_raw, from_str);
///
/// // Parse an 'A' from the DNS wire format.
/// let from_wire: A = A::parse_bytes(&[127, 0, 0, 1]).unwrap();
/// # assert_eq!(from_raw, from_wire);
///
/// // Even by reference (this is zero-copy).
/// let ref_from_wire: &A = A::parse_bytes_by_ref(&[127, 0, 0, 1]).unwrap();
/// // It is also possible to use '<&A>::parse_bytes()'.
/// # assert_eq!(from_raw, *ref_from_wire);
/// ```
///
/// Since [`A`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.
///
/// For debugging and logging, [`A`] can be formatted using [`fmt::Debug`]
/// and [`fmt::Display`].
///
/// To serialize an [`A`] in the wire format, use [`BuildBytes`] (which will
/// serialize it to a given buffer) or [`AsBytes`] (which will cast the [`A`]
/// into a byte sequence in place).  It also supports [`BuildIntoMessage`].
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
pub struct A {
    /// The IPv4 address octets.
    pub octets: [u8; 4],
}

//--- Converting to and from 'Ipv4Addr'

impl From<Ipv4Addr> for A {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<A> for Ipv4Addr {
    fn from(value: A) -> Self {
        Self::from(value.octets)
    }
}

//--- Canonical operations

impl CanonicalRecordData for A {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.octets.cmp(&other.octets)
    }
}

//--- Parsing from a string

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::from)
    }
}

//--- Formatting

impl fmt::Debug for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "A({self})")
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv4Addr::from(*self).fmt(f)
    }
}

//--- Parsing from DNS messages

impl ParseMessageBytes<'_> for A {
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

impl BuildIntoMessage for A {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> build::BuildResult {
        builder.append_built_bytes(self)?;
        Ok(builder.commit())
    }
}

//--- Parsing record data

impl ParseRecordData<'_> for A {}

impl ParseRecordDataBytes<'_> for A {
    fn parse_record_data_bytes(
        bytes: &'_ [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}

impl<'a> ParseRecordData<'a> for &'a A {}

impl<'a> ParseRecordDataBytes<'a> for &'a A {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
