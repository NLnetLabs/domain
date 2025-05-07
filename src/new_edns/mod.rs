//! Support for Extended DNS (RFC 6891).
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use core::fmt;

use crate::new_base::build::{BuildInMessage, NameCompressor};
use crate::new_base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new_base::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError, SizePrefixed,
    SplitBytes, SplitBytesZC, TruncationError, U16,
};
use crate::new_base::{RClass, RType, Record};
use crate::new_rdata::{Opt, RecordData};
use crate::utils::dst::UnsizedCopy;

//----------- EDNS option modules --------------------------------------------

mod cookie;
pub use cookie::{ClientCookie, Cookie};

mod ext_err;
pub use ext_err::{ExtError, ExtErrorCode};

//----------- EdnsRecord -----------------------------------------------------

/// An Extended DNS record.
///
/// This is generic over the record data type.  It will often be [`&Opt`], but
/// it can also be [`Box<Opt>`] or an array/slice of [`EdnsOption`]s.  While
/// [`&Opt`] can be used for parsing, all of them can be used for serializing
/// into the wire format.
///
/// [`&Opt`]: Opt
/// [`Box<Opt>`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
#[derive(Clone, Debug)]
pub struct EdnsRecord<D: ?Sized> {
    /// The largest UDP payload the DNS client supports, in bytes.
    pub max_udp_payload: U16,

    /// An extension to the response code of the DNS message.
    pub ext_rcode: u8,

    /// The Extended DNS version used by this message.
    pub version: u8,

    /// Flags describing the message.
    pub flags: EdnsFlags,

    /// The record data, containing EDNS options.
    pub data: SizePrefixed<U16, D>,
}

//--- Transformation

impl<D> EdnsRecord<D> {
    /// Transform this type's generic parameters.
    pub fn transform<ND>(
        self,
        data_map: impl FnOnce(D) -> ND,
    ) -> EdnsRecord<ND> {
        EdnsRecord {
            max_udp_payload: self.max_udp_payload,
            ext_rcode: self.ext_rcode,
            version: self.version,
            flags: self.flags,
            data: SizePrefixed::new((data_map)(self.data.into_data())),
        }
    }
}

impl<D: ?Sized> EdnsRecord<D> {
    /// Transform this type's generic parameters by reference.
    pub fn transform_ref<'a, ND>(
        &'a self,
        data_map: impl FnOnce(&'a D) -> ND,
    ) -> EdnsRecord<ND> {
        EdnsRecord {
            max_udp_payload: self.max_udp_payload,
            ext_rcode: self.ext_rcode,
            version: self.version,
            flags: self.flags,
            data: SizePrefixed::new((data_map)(&*self.data)),
        }
    }
}

//--- Parsing from DNS messages

impl<'a, D: ParseBytes<'a>> SplitMessageBytes<'a> for EdnsRecord<D> {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(contents.get(start..).ok_or(ParseError)?)
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

impl<'a, D: ParseBytes<'a>> ParseMessageBytes<'a> for EdnsRecord<D> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(contents.get(start..).ok_or(ParseError)?)
    }
}

//--- Building into DNS messages

impl<D: ?Sized + BuildBytes> BuildInMessage for EdnsRecord<D> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = contents.get_mut(start..).ok_or(TruncationError)?;
        let rest_len = self.build_bytes(bytes)?.len();
        Ok(contents.len() - rest_len)
    }
}

//--- Equality

impl<LD: ?Sized, RD: ?Sized> PartialEq<EdnsRecord<RD>> for EdnsRecord<LD>
where
    LD: PartialEq<RD>,
{
    fn eq(&self, other: &EdnsRecord<RD>) -> bool {
        self.max_udp_payload == other.max_udp_payload
            && self.ext_rcode == other.ext_rcode
            && self.version == other.version
            && self.flags == other.flags
            && *self.data == *other.data
    }
}

impl<D: ?Sized + Eq> Eq for EdnsRecord<D> {}

//--- Parsing from bytes

impl<'a, D: ParseBytes<'a>> SplitBytes<'a> for EdnsRecord<D> {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // Strip the record name (root) and the record type.
        let rest = bytes.strip_prefix(&[0, 0, 41]).ok_or(ParseError)?;

        let (&max_udp_payload, rest) = <&U16>::split_bytes(rest)?;
        let (&ext_rcode, rest) = <&u8>::split_bytes(rest)?;
        let (&version, rest) = <&u8>::split_bytes(rest)?;
        let (&flags, rest) = <&EdnsFlags>::split_bytes(rest)?;
        let (data, rest) = <SizePrefixed<U16, D>>::split_bytes(rest)?;

        Ok((
            Self {
                max_udp_payload,
                ext_rcode,
                version,
                flags,
                data,
            },
            rest,
        ))
    }
}

impl<'a, D: ParseBytes<'a>> ParseBytes<'a> for EdnsRecord<D> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

//--- Building into bytes

impl<D: ?Sized + BuildBytes> BuildBytes for EdnsRecord<D> {
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
        bytes = self.data.build_bytes(bytes)?;

        Ok(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        9 + self.data.built_bytes_size()
    }
}

//--- Converting to and from an ordinary 'Record'

impl<'a, N: ParseBytes<'static>, DN> From<EdnsRecord<&'a Opt>>
    for Record<N, RecordData<'a, DN>>
{
    fn from(value: EdnsRecord<&'a Opt>) -> Self {
        let root =
            N::parse_bytes(&[0u8]).expect("The root name is always valid");

        let [flags_hi, flags_lo] = value.flags.inner.get().to_be_bytes();
        let ttl = u32::from_be_bytes([
            value.ext_rcode,
            value.version,
            flags_hi,
            flags_lo,
        ]);

        Self {
            rname: root,
            rtype: RType::OPT,
            rclass: RClass {
                code: value.max_udp_payload,
            },
            ttl: ttl.into(),
            rdata: RecordData::Opt(*value.data),
        }
    }
}

impl<'a, N: BuildBytes, DN> TryFrom<Record<N, RecordData<'a, DN>>>
    for EdnsRecord<&'a Opt>
{
    type Error = ParseError;

    fn try_from(
        value: Record<N, RecordData<'a, DN>>,
    ) -> Result<Self, Self::Error> {
        // Make sure the record name is the root.
        let mut root = [0u8];
        if value.rname.build_bytes(&mut root) != Ok(&mut []) {
            // The name was too long or (impossibly) too short.
            return Err(ParseError);
        } else if root != [0] {
            // The name was incorrectly encoded.
            return Err(ParseError);
        }

        // Make sure the record type is OPT.
        if value.rtype != RType::OPT {
            return Err(ParseError);
        }

        // Decode the record data.
        let data = match value.rdata {
            RecordData::Opt(data) => data,
            RecordData::Unknown(RType::OPT, data) => {
                Opt::parse_bytes_by_ref(&data.octets)?
            }

            // The record data did not correspond to an OPT record.
            _ => return Err(ParseError),
        };

        let [ext_rcode, version, flags_hi, flags_lo] =
            value.ttl.value.get().to_be_bytes();
        let flags = u16::from_be_bytes([flags_hi, flags_lo]);

        Ok(Self {
            max_udp_payload: value.rclass.code,
            ext_rcode,
            version,
            flags: EdnsFlags {
                inner: U16::new(flags),
            },
            data: SizePrefixed::new(data),
        })
    }
}

//----------- EdnsFlags ------------------------------------------------------

/// Extended DNS flags describing a message.
#[derive(
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
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
pub struct EdnsFlags {
    /// The raw flag bits.
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
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EdnsOption<'b> {
    /// A client's request for a DNS cookie.
    ClientCookie(ClientCookie),

    /// A server-provided DNS cookie.
    Cookie(&'b Cookie),

    /// An extended DNS error.
    ExtError(&'b ExtError),

    /// An unknown option.
    Unknown(OptionCode, &'b UnknownOptionData),
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

    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(
        &self,
        bump: &'r bumpalo::Bump,
    ) -> EdnsOption<'r> {
        use crate::utils::dst::copy_to_bump;

        match *self {
            EdnsOption::ClientCookie(client_cookie) => {
                EdnsOption::ClientCookie(client_cookie)
            }
            EdnsOption::Cookie(cookie) => {
                EdnsOption::Cookie(copy_to_bump(cookie, bump))
            }
            EdnsOption::ExtError(ext_error) => {
                EdnsOption::ExtError(copy_to_bump(ext_error, bump))
            }
            EdnsOption::Unknown(option_code, unknown_option) => {
                EdnsOption::Unknown(
                    option_code,
                    copy_to_bump(unknown_option, bump),
                )
            }
        }
    }
}

//--- Parsing from bytes

impl<'b> ParseBytes<'b> for EdnsOption<'b> {
    fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
        UnparsedEdnsOption::parse_bytes_by_ref(bytes)?.try_into()
    }
}

impl<'b> SplitBytes<'b> for EdnsOption<'b> {
    fn split_bytes(bytes: &'b [u8]) -> Result<(Self, &'b [u8]), ParseError> {
        let (this, rest) = UnparsedEdnsOption::split_bytes_by_ref(bytes)?;
        Ok((this.try_into()?, rest))
    }
}

//--- Parsing from an 'UnparsedEdnsOption'

impl<'b> TryFrom<&'b UnparsedEdnsOption> for EdnsOption<'b> {
    type Error = ParseError;

    fn try_from(value: &'b UnparsedEdnsOption) -> Result<Self, Self::Error> {
        let UnparsedEdnsOption { code, data } = value;
        match *code {
            OptionCode::COOKIE => match data.len() {
                8 => ClientCookie::parse_bytes(data).map(Self::ClientCookie),
                16..=40 => <&Cookie>::parse_bytes(data).map(Self::Cookie),
                _ => Err(ParseError),
            },

            OptionCode::EXT_ERROR => {
                <&ExtError>::parse_bytes(data).map(Self::ExtError)
            }

            _ => <&UnknownOptionData>::parse_bytes(data)
                .map(|data| Self::Unknown(*code, data)),
        }
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
        bytes = SizePrefixed::<U16, _>::new(data).build_bytes(bytes)?;

        Ok(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        4 + match self {
            Self::ClientCookie(this) => this.built_bytes_size(),
            Self::Cookie(this) => this.built_bytes_size(),
            Self::ExtError(this) => this.built_bytes_size(),
            Self::Unknown(_, this) => this.built_bytes_size(),
        }
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
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct OptionCode {
    /// The option code.
    pub code: U16,
}

//--- Associated Constants

impl OptionCode {
    /// Create a new [`OptionCode`].
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

//----------- UnknownOptionData ----------------------------------------------

/// Data for an unknown EDNS option.
#[derive(
    Debug, PartialEq, Eq, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy,
)]
#[repr(transparent)]
pub struct UnknownOptionData {
    /// The unparsed option data.
    pub octets: [u8],
}

//----------- UnparsedEdnsOption ---------------------------------------------

/// An unparsed EDNS option.
#[derive(
    Debug,
    PartialEq,
    Eq,
    AsBytes,
    BuildBytes,
    ParseBytesZC,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(C)]
pub struct UnparsedEdnsOption {
    /// The option code.
    pub code: OptionCode,

    /// The option data.
    pub data: SizePrefixed<U16, [u8]>,
}
