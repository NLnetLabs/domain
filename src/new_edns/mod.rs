//! Support for Extended DNS (RFC 6891).
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use core::fmt;

use domain_macros::*;

use crate::{
    new_base::{
        parse::{ParseFromMessage, SplitFromMessage},
        wire::{
            AsBytes, BuildBytes, ParseBytes, ParseBytesByRef, ParseError,
            SizePrefixed, SplitBytes, TruncationError, U16,
        },
        Message,
    },
    new_rdata::Opt,
};

//----------- EDNS option modules --------------------------------------------

mod cookie;
pub use cookie::{ClientCookie, Cookie};

mod ext_err;
pub use ext_err::{ExtError, ExtErrorCode};

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
    pub options: SizePrefixed<&'a Opt>,
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for EdnsRecord<'a> {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = message.contents.get(start..).ok_or(ParseError)?;
        let (this, rest) = Self::split_bytes(bytes)?;
        Ok((this, message.contents.len() - rest.len()))
    }
}

impl<'a> ParseFromMessage<'a> for EdnsRecord<'a> {
    fn parse_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<Self, ParseError> {
        message
            .contents
            .get(start..)
            .ok_or(ParseError)
            .and_then(Self::parse_bytes)
    }
}

//--- Parsing from bytes

impl<'a> SplitBytes<'a> for EdnsRecord<'a> {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // Strip the record name (root) and the record type.
        let rest = bytes.strip_prefix(&[0, 0, 41]).ok_or(ParseError)?;

        let (&max_udp_payload, rest) = <&U16>::split_bytes(rest)?;
        let (&ext_rcode, rest) = <&u8>::split_bytes(rest)?;
        let (&version, rest) = <&u8>::split_bytes(rest)?;
        let (&flags, rest) = <&EdnsFlags>::split_bytes(rest)?;
        let (options, rest) = <SizePrefixed<&Opt>>::split_bytes(rest)?;

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

impl<'a> ParseBytes<'a> for EdnsRecord<'a> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // Strip the record name (root) and the record type.
        let rest = bytes.strip_prefix(&[0, 0, 41]).ok_or(ParseError)?;

        let (&max_udp_payload, rest) = <&U16>::split_bytes(rest)?;
        let (&ext_rcode, rest) = <&u8>::split_bytes(rest)?;
        let (&version, rest) = <&u8>::split_bytes(rest)?;
        let (&flags, rest) = <&EdnsFlags>::split_bytes(rest)?;
        let options = <SizePrefixed<&Opt>>::parse_bytes(rest)?;

        Ok(Self {
            max_udp_payload,
            ext_rcode,
            version,
            flags,
            options,
        })
    }
}

//--- Building into bytes

impl BuildBytes for EdnsRecord<'_> {
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        // Add the record name (root) and the record type.
        bytes = [0, 0, 41].as_slice().build_bytes(bytes)?;

        bytes = self.max_udp_payload.build_bytes(bytes)?;
        bytes = self.ext_rcode.build_bytes(bytes)?;
        bytes = self.version.build_bytes(bytes)?;
        bytes = self.flags.build_bytes(bytes)?;
        bytes = self.options.build_bytes(bytes)?;

        Ok(bytes)
    }
}

//----------- EdnsFlags ------------------------------------------------------

/// Extended DNS flags describing a message.
#[derive(
    Copy,
    Clone,
    Default,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
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
    /// A client's request for a DNS cookie.
    ClientCookie(&'b ClientCookie),

    /// A server-provided DNS cookie.
    Cookie(&'b Cookie),

    /// An extended DNS error.
    ExtError(&'b ExtError),

    /// An unknown option.
    Unknown(OptionCode, &'b UnknownOption),
}

//--- Inspection

impl EdnsOption<'_> {
    /// The code for this option.
    pub fn code(&self) -> OptionCode {
        match self {
            Self::ClientCookie(_) => OptionCode::COOKIE,
            Self::Cookie(_) => OptionCode::COOKIE,
            Self::ExtError(_) => OptionCode::EXT_ERROR,
            Self::Unknown(code, _) => *code,
        }
    }
}

//--- Parsing from bytes

impl<'b> ParseBytes<'b> for EdnsOption<'b> {
    fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
        let (code, rest) = OptionCode::split_bytes(bytes)?;
        let data = <&SizePrefixed<[u8]>>::parse_bytes(rest)?;

        match code {
            OptionCode::COOKIE => match data.len() {
                8 => ClientCookie::parse_bytes_by_ref(data)
                    .map(Self::ClientCookie),
                16..=40 => Cookie::parse_bytes_by_ref(data).map(Self::Cookie),
                _ => Err(ParseError),
            },

            OptionCode::EXT_ERROR => {
                ExtError::parse_bytes_by_ref(data).map(Self::ExtError)
            }

            _ => {
                let data = UnknownOption::parse_bytes_by_ref(data)?;
                Ok(Self::Unknown(code, data))
            }
        }
    }
}

impl<'b> SplitBytes<'b> for EdnsOption<'b> {
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (code, rest) = OptionCode::split_bytes(bytes)?;
        let (data, rest) = <&SizePrefixed<[u8]>>::split_bytes(rest)?;

        let this = match code {
            OptionCode::COOKIE => match data.len() {
                8 => <&ClientCookie>::parse_bytes(data)
                    .map(Self::ClientCookie)?,
                16..=40 => <&Cookie>::parse_bytes(data).map(Self::Cookie)?,
                _ => return Err(ParseError),
            },

            OptionCode::EXT_ERROR => {
                <&ExtError>::parse_bytes(data).map(Self::ExtError)?
            }

            _ => <&UnknownOption>::parse_bytes(data)
                .map(|data| Self::Unknown(code, data))?,
        };

        Ok((this, rest))
    }
}

//--- Building byte strings

impl BuildBytes for EdnsOption<'_> {
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.code().build_bytes(bytes)?;

        let data = match self {
            Self::ClientCookie(this) => this.as_bytes(),
            Self::Cookie(this) => this.as_bytes(),
            Self::ExtError(this) => this.as_bytes(),
            Self::Unknown(_, this) => this.as_bytes(),
        };
        bytes = SizePrefixed::new(data).build_bytes(bytes)?;

        Ok(bytes)
    }
}

//----------- OptionCode -----------------------------------------------------

/// An Extended DNS option code.
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
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct OptionCode {
    /// The option code.
    pub code: U16,
}

//--- Associated Constants

impl OptionCode {
    const fn new(code: u16) -> Self {
        Self {
            code: U16::new(code),
        }
    }

    /// A DNS cookie (request).
    pub const COOKIE: Self = Self::new(10);

    /// An extended DNS error.
    pub const EXT_ERROR: Self = Self::new(15);
}

//--- Formatting

impl fmt::Debug for OptionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::COOKIE => "OptionCode::COOKIE",
            Self::EXT_ERROR => "OptionCode::EXT_ERROR",
            _ => {
                return f
                    .debug_tuple("OptionCode")
                    .field(&self.code.get())
                    .finish();
            }
        })
    }
}

//----------- UnknownOption --------------------------------------------------

/// Data for an unknown Extended DNS option.
#[derive(Debug, AsBytes, BuildBytes, ParseBytesByRef)]
#[repr(transparent)]
pub struct UnknownOption {
    /// The unparsed option data.
    pub octets: [u8],
}
