//! Support for Extended DNS (RFC 6891).
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use core::{fmt, ops::Range};

use domain_macros::{ParseBytesByRef, SplitBytesByRef};
use zerocopy::{network_endian::U16, FromBytes, IntoBytes};
use zerocopy_derive::*;

use crate::{
    new_base::{
        parse::{
            ParseError, ParseFrom, ParseFromMessage, SplitFrom,
            SplitFromMessage,
        },
        Message,
    },
    new_rdata::Opt,
};

//----------- EdnsRecord -----------------------------------------------------

/// An Extended DNS record.
#[derive(Clone)]
pub struct EdnsRecord<'a> {
    /// The largest UDP payload the DNS client supports, in bytes.
    pub max_udp_payload: U16,

    /// An extension to the response code of the DNS message.
    pub ext_rcode: u8,

    /// The Extended DNS version used by this message.
    pub version: u8,

    /// Flags describing the message.
    pub flags: EdnsFlags,

    /// Extended DNS options.
    pub options: &'a Opt,
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for EdnsRecord<'a> {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = message.as_bytes().get(start..).ok_or(ParseError)?;
        let (this, rest) = Self::split_from(bytes)?;
        Ok((this, message.as_bytes().len() - rest.len()))
    }
}

impl<'a> ParseFromMessage<'a> for EdnsRecord<'a> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        message
            .as_bytes()
            .get(range)
            .ok_or(ParseError)
            .and_then(Self::parse_from)
    }
}

//--- Parsing from bytes

impl<'a> SplitFrom<'a> for EdnsRecord<'a> {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // Strip the record name (root) and the record type.
        let rest = bytes.strip_prefix(&[0, 0, 41]).ok_or(ParseError)?;

        let (&max_udp_payload, rest) = <&U16>::split_from(rest)?;
        let (&ext_rcode, rest) = <&u8>::split_from(rest)?;
        let (&version, rest) = <&u8>::split_from(rest)?;
        let (&flags, rest) = <&EdnsFlags>::split_from(rest)?;

        // Split the record size and data.
        let (&size, rest) = <&U16>::split_from(rest)?;
        let size: usize = size.get().into();
        let (options, rest) = Opt::ref_from_prefix_with_elems(rest, size)?;

        Ok((
            Self {
                max_udp_payload,
                ext_rcode,
                version,
                flags,
                options,
            },
            rest,
        ))
    }
}

impl<'a> ParseFrom<'a> for EdnsRecord<'a> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // Strip the record name (root) and the record type.
        let rest = bytes.strip_prefix(&[0, 0, 41]).ok_or(ParseError)?;

        let (&max_udp_payload, rest) = <&U16>::split_from(rest)?;
        let (&ext_rcode, rest) = <&u8>::split_from(rest)?;
        let (&version, rest) = <&u8>::split_from(rest)?;
        let (&flags, rest) = <&EdnsFlags>::split_from(rest)?;

        // Split the record size and data.
        let (&size, rest) = <&U16>::split_from(rest)?;
        let size: usize = size.get().into();
        let options = Opt::ref_from_bytes_with_elems(rest, size)?;

        Ok(Self {
            max_udp_payload,
            ext_rcode,
            version,
            flags,
            options,
        })
    }
}

//----------- EdnsFlags ------------------------------------------------------

/// Extended DNS flags describing a message.
#[derive(
    Copy,
    Clone,
    Default,
    Hash,
    IntoBytes,
    Immutable,
    ParseBytesByRef,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct EdnsFlags {
    inner: U16,
}

//--- Interaction

impl EdnsFlags {
    /// Get the specified flag bit.
    fn get_flag(&self, pos: u32) -> bool {
        self.inner.get() & (1 << pos) != 0
    }

    /// Set the specified flag bit.
    fn set_flag(mut self, pos: u32, value: bool) -> Self {
        self.inner &= !(1 << pos);
        self.inner |= (value as u16) << pos;
        self
    }

    /// The raw flags bits.
    pub fn bits(&self) -> u16 {
        self.inner.get()
    }

    /// Whether the client supports DNSSEC.
    ///
    /// See [RFC 3225](https://datatracker.ietf.org/doc/html/rfc3225).
    pub fn is_dnssec_ok(&self) -> bool {
        self.get_flag(15)
    }

    /// Indicate support for DNSSEC to the server.
    ///
    /// See [RFC 3225](https://datatracker.ietf.org/doc/html/rfc3225).
    pub fn set_dnssec_ok(self, value: bool) -> Self {
        self.set_flag(15, value)
    }
}

//--- Formatting

impl fmt::Debug for EdnsFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdnsFlags")
            .field("dnssec_ok (do)", &self.is_dnssec_ok())
            .field("bits", &self.bits())
            .finish()
    }
}

//----------- EdnsOption -----------------------------------------------------

/// An Extended DNS option.
#[derive(Debug)]
#[non_exhaustive]
pub enum EdnsOption<'b> {
    /// An unknown option.
    Unknown(OptionCode, &'b UnknownOption),
}

//----------- OptionCode -----------------------------------------------------

/// An Extended DNS option code.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    IntoBytes,
    Immutable,
    ParseBytesByRef,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct OptionCode {
    /// The option code.
    pub code: U16,
}

//----------- UnknownOption --------------------------------------------------

/// Data for an unknown Extended DNS option.
#[derive(Debug, IntoBytes, Immutable, ParseBytesByRef)]
#[repr(C)]
pub struct UnknownOption {
    /// The unparsed option data.
    pub octets: [u8],
}
