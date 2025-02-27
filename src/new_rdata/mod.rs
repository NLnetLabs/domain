//! Record data types.

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError},
    ParseRecordData, RType,
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Concrete record data types -------------------------------------

mod basic;
pub use basic::{CName, HInfo, Mx, Ns, Ptr, Soa, Txt, Wks, A};

mod ipv6;
pub use ipv6::Aaaa;

mod edns;
pub use edns::{EdnsOptionsIter, Opt};

//----------- RecordData -----------------------------------------------------

/// DNS record data.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RecordData<'a, N> {
    /// The IPv4 address of a host responsible for this domain.
    A(&'a A),

    /// The authoritative name server for this domain.
    Ns(Ns<N>),

    /// The canonical name for this domain.
    CName(CName<N>),

    /// The start of a zone of authority.
    Soa(Soa<N>),

    /// Well-known services supported on this domain.
    Wks(&'a Wks),

    /// A pointer to another domain name.
    Ptr(Ptr<N>),

    /// Information about the host computer.
    HInfo(HInfo<'a>),

    /// A host that can exchange mail for this domain.
    Mx(Mx<N>),

    /// Free-form text strings about this domain.
    Txt(&'a Txt),

    /// The IPv6 address of a host responsible for this domain.
    Aaaa(&'a Aaaa),

    /// Extended DNS options.
    Opt(&'a Opt),

    /// Data for an unknown DNS record type.
    Unknown(RType, &'a UnknownRecordData),
}

//--- Parsing record data

impl<'a, N> ParseRecordData<'a> for RecordData<'a, N>
where
    N: SplitBytes<'a> + SplitMessageBytes<'a>,
{
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => {
                <&A>::parse_message_bytes(contents, start).map(Self::A)
            }
            RType::NS => {
                Ns::parse_message_bytes(contents, start).map(Self::Ns)
            }
            RType::CNAME => {
                CName::parse_message_bytes(contents, start).map(Self::CName)
            }
            RType::SOA => {
                Soa::parse_message_bytes(contents, start).map(Self::Soa)
            }
            RType::WKS => {
                <&Wks>::parse_message_bytes(contents, start).map(Self::Wks)
            }
            RType::PTR => {
                Ptr::parse_message_bytes(contents, start).map(Self::Ptr)
            }
            RType::HINFO => {
                HInfo::parse_message_bytes(contents, start).map(Self::HInfo)
            }
            RType::MX => {
                Mx::parse_message_bytes(contents, start).map(Self::Mx)
            }
            RType::TXT => {
                <&Txt>::parse_message_bytes(contents, start).map(Self::Txt)
            }
            RType::AAAA => {
                <&Aaaa>::parse_message_bytes(contents, start).map(Self::Aaaa)
            }
            RType::OPT => {
                <&Opt>::parse_message_bytes(contents, start).map(Self::Opt)
            }
            _ => <&UnknownRecordData>::parse_message_bytes(contents, start)
                .map(|data| Self::Unknown(rtype, data)),
        }
    }

    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => <&A>::parse_bytes(bytes).map(Self::A),
            RType::NS => Ns::parse_bytes(bytes).map(Self::Ns),
            RType::CNAME => CName::parse_bytes(bytes).map(Self::CName),
            RType::SOA => Soa::parse_bytes(bytes).map(Self::Soa),
            RType::WKS => <&Wks>::parse_bytes(bytes).map(Self::Wks),
            RType::PTR => Ptr::parse_bytes(bytes).map(Self::Ptr),
            RType::HINFO => HInfo::parse_bytes(bytes).map(Self::HInfo),
            RType::MX => Mx::parse_bytes(bytes).map(Self::Mx),
            RType::TXT => <&Txt>::parse_bytes(bytes).map(Self::Txt),
            RType::AAAA => <&Aaaa>::parse_bytes(bytes).map(Self::Aaaa),
            RType::OPT => <&Opt>::parse_bytes(bytes).map(Self::Opt),
            _ => <&UnknownRecordData>::parse_bytes(bytes)
                .map(|data| Self::Unknown(rtype, data)),
        }
    }
}

//--- Building record data

impl<N: BuildIntoMessage> BuildIntoMessage for RecordData<'_, N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        match self {
            Self::A(r) => r.build_into_message(builder),
            Self::Ns(r) => r.build_into_message(builder),
            Self::CName(r) => r.build_into_message(builder),
            Self::Soa(r) => r.build_into_message(builder),
            Self::Wks(r) => r.build_into_message(builder),
            Self::Ptr(r) => r.build_into_message(builder),
            Self::HInfo(r) => r.build_into_message(builder),
            Self::Mx(r) => r.build_into_message(builder),
            Self::Txt(r) => r.build_into_message(builder),
            Self::Aaaa(r) => r.build_into_message(builder),
            Self::Opt(r) => r.build_into_message(builder),
            Self::Unknown(_, r) => r.octets.build_into_message(builder),
        }
    }
}

impl<N: BuildBytes> BuildBytes for RecordData<'_, N> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        match self {
            Self::A(r) => r.build_bytes(bytes),
            Self::Ns(r) => r.build_bytes(bytes),
            Self::CName(r) => r.build_bytes(bytes),
            Self::Soa(r) => r.build_bytes(bytes),
            Self::Wks(r) => r.build_bytes(bytes),
            Self::Ptr(r) => r.build_bytes(bytes),
            Self::HInfo(r) => r.build_bytes(bytes),
            Self::Mx(r) => r.build_bytes(bytes),
            Self::Txt(r) => r.build_bytes(bytes),
            Self::Aaaa(r) => r.build_bytes(bytes),
            Self::Opt(r) => r.build_bytes(bytes),
            Self::Unknown(_, r) => r.build_bytes(bytes),
        }
    }
}

//----------- UnknownRecordData ----------------------------------------------

/// Data for an unknown DNS record type.
#[derive(Debug, AsBytes, BuildBytes, ParseBytesByRef)]
#[repr(transparent)]
pub struct UnknownRecordData {
    /// The unparsed option data.
    pub octets: [u8],
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a UnknownRecordData {
    /// Scan record data from the generic format.
    ///
    /// Parses the `unknown-data` syntax from [the specification].
    ///
    /// [the specification]: crate::new_zonefile#specification
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        // Allow the buffer to have previous content.
        let start = buffer.len();

        // Parse the special unknown data marker.
        if !scanner
            .remaining()
            .strip_prefix(b"\\#")
            .is_some_and(|r| r.first().map_or(true, u8::is_ascii_whitespace))
        {
            return Err(ScanError::Custom(
                "missing marker for the unknown record data format",
            ));
        }
        scanner.consume(2);

        if !scanner.skip_ws() {
            return Err(ScanError::Custom("missing data size field"));
        }

        // Parse the record data size.
        let size: usize = scanner
            .scan_plain_token()?
            .parse::<u16>()
            .map_err(|_| ScanError::Custom("invalid data size field"))?
            .into();

        // NOTE: We explicitly choose not to preallocate the expected size of
        // the record, in case it's wrong and we end up over-allocating.

        // Fill the buffer with the record data in bytes.
        while buffer.len() < start + size {
            if !scanner.skip_ws() {
                return Err(ScanError::Custom("missing record data bytes"));
            }

            let token = scanner.scan_plain_token()?;

            if buffer.len() > start + size + token.len() / 2 {
                return Err(ScanError::Custom(
                    "overlong unknown record data bytes",
                ));
            }

            for chunk in token.as_bytes().chunks(2) {
                let &[hi, lo] = chunk else {
                    return Err(ScanError::Custom(
                        "partial byte in unknown record data",
                    ));
                };

                fn decode_hex(c: u8) -> Result<u8, ScanError> {
                    match c {
                        b'0'..=b'9' => Ok(c - b'0'),
                        b'A'..=b'F' => Ok(c - b'A' + 10),
                        b'a'..=b'f' => Ok(c - b'a' + 10),
                        _ => Err(ScanError::Custom("unknown record data contained a non-hexadecimal value")),
                    }
                }

                buffer.push((decode_hex(hi)? << 4) | decode_hex(lo)?);
            }
        }

        debug_assert_eq!(buffer.len(), start + size);
        let bytes = alloc.alloc_slice_copy(&buffer[start..]);
        Ok(Self::parse_bytes(bytes)
            .expect("Up to 64K of arbitrary bytes is always valid 'UnknownRecordData'"))
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::UnknownRecordData;

    #[cfg(feature = "zonefile")]
    #[test]
    fn scan_unknown() {
        use crate::{
            new_base::wire::AsBytes,
            new_zonefile::scanner::{Scan, ScanError, Scanner},
        };

        let cases = [
            (b"\\# 0" as &[u8], Ok(&[] as &[u8])),
            (b"\\# 1 5A", Ok(&[0x5A])),
            (b"\\# 4 41 52 5a 4B", Ok(&[0x41, 0x52, 0x5a, 0x4B])),
            (b"\\# 4 4152 5a4B", Ok(&[0x41, 0x52, 0x5a, 0x4B])),
            (
                b"\\# 4 415 25 a4B",
                Err(ScanError::Custom("partial byte in unknown record data")),
            ),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            assert_eq!(
                <&UnknownRecordData>::scan(&mut scanner, &alloc, &mut buffer)
                    .map(|d| d.as_bytes()),
                expected
            );
        }
    }
}
