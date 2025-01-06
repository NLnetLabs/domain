//! Support for Extended DNS (RFC 6891).
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use core::{fmt, ops::Range};

use zerocopy::{network_endian::U16, IntoBytes};

use domain_macros::*;

use crate::{
    new_base::{
        build::{AsBytes, BuildBytes, TruncationError},
        parse::{
            ParseBytes, ParseBytesByRef, ParseError, ParseFromMessage,
            SplitBytes, SplitFromMessage,
        },
        Message,
    },
    new_rdata::Opt,
};

//----------- EDNS option modules --------------------------------------------

mod cookie;
pub use cookie::{Cookie, CookieRequest};

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
    pub options: &'a Opt,
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for EdnsRecord<'a> {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = message.as_bytes().get(start..).ok_or(ParseError)?;
        let (this, rest) = Self::split_bytes(bytes)?;
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

        // Split the record size and data.
        let (&size, rest) = <&U16>::split_bytes(rest)?;
        let size: usize = size.get().into();
        if rest.len() < size {
            return Err(ParseError);
        }
        let (options, rest) = rest.split_at(size);
        let options = Opt::parse_bytes_by_ref(options)?;

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

        // Split the record size and data.
        let (&size, rest) = <&U16>::split_bytes(rest)?;
        let size: usize = size.get().into();
        if rest.len() != size {
            return Err(ParseError);
        }
        let options = Opt::parse_bytes_by_ref(rest)?;

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
    /// A request for a DNS cookie.
    CookieRequest(&'b CookieRequest),

    /// A DNS cookie.
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
            Self::CookieRequest(_) => OptionCode::COOKIE,
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
        let (size, rest) = U16::split_bytes(rest)?;
        if rest.len() != size.get() as usize {
            return Err(ParseError);
        }

        match code {
            OptionCode::COOKIE => match size.get() {
                8 => CookieRequest::parse_bytes_by_ref(rest)
                    .map(Self::CookieRequest),
                16..=40 => Cookie::parse_bytes_by_ref(rest).map(Self::Cookie),
                _ => Err(ParseError),
            },

            OptionCode::EXT_ERROR => {
                ExtError::parse_bytes_by_ref(rest).map(Self::ExtError)
            }

            _ => {
                let data = UnknownOption::parse_bytes_by_ref(rest)?;
                Ok(Self::Unknown(code, data))
            }
        }
    }
}

impl<'b> SplitBytes<'b> for EdnsOption<'b> {
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (code, rest) = OptionCode::split_bytes(bytes)?;
        let (size, rest) = U16::split_bytes(rest)?;
        if rest.len() < size.get() as usize {
            return Err(ParseError);
        }
        let (bytes, rest) = rest.split_at(size.get() as usize);

        match code {
            OptionCode::COOKIE => match size.get() {
                8 => CookieRequest::parse_bytes_by_ref(bytes)
                    .map(Self::CookieRequest),
                16..=40 => {
                    Cookie::parse_bytes_by_ref(bytes).map(Self::Cookie)
                }
                _ => Err(ParseError),
            },

            OptionCode::EXT_ERROR => {
                ExtError::parse_bytes_by_ref(bytes).map(Self::ExtError)
            }

            _ => {
                let data = UnknownOption::parse_bytes_by_ref(bytes)?;
                Ok(Self::Unknown(code, data))
            }
        }
        .map(|this| (this, rest))
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
            Self::CookieRequest(this) => this.as_bytes(),
            Self::Cookie(this) => this.as_bytes(),
            Self::ExtError(this) => this.as_bytes(),
            Self::Unknown(_, this) => this.as_bytes(),
        };

        bytes = U16::new(data.len() as u16).build_bytes(bytes)?;
        bytes = data.build_bytes(bytes)?;
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
