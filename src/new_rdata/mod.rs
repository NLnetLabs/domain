//! Record data types.

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{
        AsBytes, BuildBytes, ParseBytes, ParseError, SplitBytes,
        TruncationError,
    },
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

mod dnssec;
pub use dnssec::{
    DNSKey, DNSKeyFlags, DigestType, Ds, NSec, NSec3, NSec3Flags,
    NSec3HashAlg, NSec3Param, RRSig, SecAlg,
};

//----------- RecordData -----------------------------------------------------

/// DNS record data.
#[derive(Clone, Debug, PartialEq, Eq)]
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

    /// The signing key of a delegated zone.
    Ds(&'a Ds),

    /// A cryptographic signature on a DNS record set.
    RRSig(RRSig<'a>),

    /// An indication of the non-existence of a set of DNS records (version 1).
    NSec(NSec<'a>),

    /// A cryptographic key for DNS security.
    DNSKey(&'a DNSKey),

    /// An indication of the non-existence of a set of DNS records (version 3).
    NSec3(NSec3<'a>),

    /// Parameters for computing [`NSec3`] records.
    NSec3Param(&'a NSec3Param),

    /// Data for an unknown DNS record type.
    Unknown(RType, &'a UnknownRecordData),
}

//--- Inspection

impl<N> RecordData<'_, N> {
    /// The type of this record data.
    pub const fn rtype(&self) -> RType {
        match self {
            Self::A(..) => RType::A,
            Self::Ns(..) => RType::NS,
            Self::CName(..) => RType::CNAME,
            Self::Soa(..) => RType::SOA,
            Self::Wks(..) => RType::WKS,
            Self::Ptr(..) => RType::PTR,
            Self::HInfo(..) => RType::HINFO,
            Self::Mx(..) => RType::MX,
            Self::Txt(..) => RType::TXT,
            Self::Aaaa(..) => RType::AAAA,
            Self::Opt(..) => RType::OPT,
            Self::Ds(..) => RType::DS,
            Self::RRSig(..) => RType::RRSIG,
            Self::NSec(..) => RType::NSEC,
            Self::DNSKey(..) => RType::DNSKEY,
            Self::NSec3(..) => RType::NSEC3,
            Self::NSec3Param(..) => RType::NSEC3PARAM,
            Self::Unknown(rtype, _) => *rtype,
        }
    }
}

//--- Interaction

impl<'a, N> RecordData<'a, N> {
    /// Map the domain names within to another type.
    pub fn map_names<R, F: FnMut(N) -> R>(self, f: F) -> RecordData<'a, R> {
        match self {
            Self::A(r) => RecordData::A(r),
            Self::Ns(r) => RecordData::Ns(r.map_name(f)),
            Self::CName(r) => RecordData::CName(r.map_name(f)),
            Self::Soa(r) => RecordData::Soa(r.map_names(f)),
            Self::Wks(r) => RecordData::Wks(r),
            Self::Ptr(r) => RecordData::Ptr(r.map_name(f)),
            Self::HInfo(r) => RecordData::HInfo(r),
            Self::Mx(r) => RecordData::Mx(r.map_name(f)),
            Self::Txt(r) => RecordData::Txt(r),
            Self::Aaaa(r) => RecordData::Aaaa(r),
            Self::Opt(r) => RecordData::Opt(r),
            Self::Ds(r) => RecordData::Ds(r),
            Self::RRSig(r) => RecordData::RRSig(r),
            Self::NSec(r) => RecordData::NSec(r),
            Self::DNSKey(r) => RecordData::DNSKey(r),
            Self::NSec3(r) => RecordData::NSec3(r),
            Self::NSec3Param(r) => RecordData::NSec3Param(r),
            Self::Unknown(rt, rd) => RecordData::Unknown(rt, rd),
        }
    }

    /// Map references to the domain names within to another type.
    pub fn map_names_by_ref<'r, R, F: FnMut(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> RecordData<'r, R> {
        match self {
            Self::A(r) => RecordData::A(r),
            Self::Ns(r) => RecordData::Ns(r.map_name_by_ref(f)),
            Self::CName(r) => RecordData::CName(r.map_name_by_ref(f)),
            Self::Soa(r) => RecordData::Soa(r.map_names_by_ref(f)),
            Self::Wks(r) => RecordData::Wks(r),
            Self::Ptr(r) => RecordData::Ptr(r.map_name_by_ref(f)),
            Self::HInfo(r) => RecordData::HInfo(r.clone()),
            Self::Mx(r) => RecordData::Mx(r.map_name_by_ref(f)),
            Self::Txt(r) => RecordData::Txt(r),
            Self::Aaaa(r) => RecordData::Aaaa(r),
            Self::Opt(r) => RecordData::Opt(r),
            Self::Ds(r) => RecordData::Ds(r),
            Self::RRSig(r) => RecordData::RRSig(r.clone()),
            Self::NSec(r) => RecordData::NSec(r.clone()),
            Self::DNSKey(r) => RecordData::DNSKey(r),
            Self::NSec3(r) => RecordData::NSec3(r.clone()),
            Self::NSec3Param(r) => RecordData::NSec3Param(r),
            Self::Unknown(rt, rd) => RecordData::Unknown(*rt, rd),
        }
    }
}

//--- Parsing record data

impl<'a, N> ParseRecordData<'a> for RecordData<'a, N>
where
    // TODO: Remove 'SplitMessageBytes' bound when parsing from bytes.
    N: SplitBytes<'a> + SplitMessageBytes<'a>,
{
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => <&A>::parse_bytes(&contents[start..]).map(Self::A),
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
                <&Wks>::parse_bytes(&contents[start..]).map(Self::Wks)
            }
            RType::PTR => {
                Ptr::parse_message_bytes(contents, start).map(Self::Ptr)
            }
            RType::HINFO => {
                HInfo::parse_bytes(&contents[start..]).map(Self::HInfo)
            }
            RType::MX => {
                Mx::parse_message_bytes(contents, start).map(Self::Mx)
            }
            RType::TXT => {
                <&Txt>::parse_bytes(&contents[start..]).map(Self::Txt)
            }
            RType::AAAA => {
                <&Aaaa>::parse_bytes(&contents[start..]).map(Self::Aaaa)
            }
            RType::OPT => {
                <&Opt>::parse_bytes(&contents[start..]).map(Self::Opt)
            }
            RType::DS => <&Ds>::parse_bytes(&contents[start..]).map(Self::Ds),
            RType::RRSIG => {
                RRSig::parse_bytes(&contents[start..]).map(Self::RRSig)
            }
            RType::NSEC => {
                NSec::parse_bytes(&contents[start..]).map(Self::NSec)
            }
            RType::DNSKEY => {
                <&DNSKey>::parse_bytes(&contents[start..]).map(Self::DNSKey)
            }
            RType::NSEC3 => {
                NSec3::parse_bytes(&contents[start..]).map(Self::NSec3)
            }
            RType::NSEC3PARAM => {
                <&NSec3Param>::parse_bytes(&contents[start..])
                    .map(Self::NSec3Param)
            }
            _ => <&UnknownRecordData>::parse_bytes(&contents[start..])
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
            RType::DS => <&Ds>::parse_bytes(bytes).map(Self::Ds),
            RType::RRSIG => RRSig::parse_bytes(bytes).map(Self::RRSig),
            RType::NSEC => NSec::parse_bytes(bytes).map(Self::NSec),
            RType::DNSKEY => <&DNSKey>::parse_bytes(bytes).map(Self::DNSKey),
            RType::NSEC3 => NSec3::parse_bytes(bytes).map(Self::NSec3),
            RType::NSEC3PARAM => {
                <&NSec3Param>::parse_bytes(bytes).map(Self::NSec3Param)
            }
            _ => <&UnknownRecordData>::parse_bytes(bytes)
                .map(|data| Self::Unknown(rtype, data)),
        }
    }
}

//--- Building record data

impl<N: BuildIntoMessage> BuildIntoMessage for RecordData<'_, N> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        match self {
            Self::A(r) => builder.append_bytes(r.as_bytes())?,
            Self::Ns(r) => return r.build_into_message(builder),
            Self::CName(r) => return r.build_into_message(builder),
            Self::Soa(r) => return r.build_into_message(builder),
            Self::Wks(r) => builder.append_bytes(r.as_bytes())?,
            Self::Ptr(r) => return r.build_into_message(builder),
            Self::HInfo(r) => builder.append_built_bytes(r)?,
            Self::Mx(r) => return r.build_into_message(builder),
            Self::Txt(r) => builder.append_bytes(r.as_bytes())?,
            Self::Aaaa(r) => builder.append_bytes(r.as_bytes())?,
            Self::Opt(r) => builder.append_bytes(r.as_bytes())?,
            Self::Ds(r) => builder.append_bytes(r.as_bytes())?,
            Self::RRSig(r) => builder.append_built_bytes(r)?,
            Self::NSec(r) => builder.append_built_bytes(r)?,
            Self::DNSKey(r) => builder.append_bytes(r.as_bytes())?,
            Self::NSec3(r) => builder.append_built_bytes(r)?,
            Self::NSec3Param(r) => builder.append_bytes(r.as_bytes())?,
            Self::Unknown(_, r) => builder.append_bytes(r.as_bytes())?,
        }

        Ok(builder.commit())
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
            Self::Ds(r) => r.build_bytes(bytes),
            Self::RRSig(r) => r.build_bytes(bytes),
            Self::NSec(r) => r.build_bytes(bytes),
            Self::DNSKey(r) => r.build_bytes(bytes),
            Self::NSec3(r) => r.build_bytes(bytes),
            Self::NSec3Param(r) => r.build_bytes(bytes),
            Self::Unknown(_, r) => r.build_bytes(bytes),
        }
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N> Scan<'a> for RecordData<'a, N>
where
    N: Scan<'a> + SplitBytes<'a> + SplitMessageBytes<'a>,
{
    /// Scan record data.
    ///
    /// Parses the `data` syntax from [the specification].
    ///
    /// [the specification]: crate::new_zonefile#specification
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let rtype = RType::scan(scanner, alloc, buffer)?;

        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        if scanner.remaining().starts_with(b"\\#") {
            // Parse from the unknown record data format.
            let data = <&'a UnknownRecordData>::scan(scanner, alloc, buffer)?;
            return Self::parse_record_data_bytes(&data.octets, rtype)
                .map_err(|_| ScanError::Custom("Invalid unknown-data content for a known record data type"));
        }

        // Try all concrete parsers.
        match rtype {
            RType::A => {
                Scan::scan(scanner, alloc, buffer)
                    .map(|data| Self::A(alloc.alloc(data)))
            }

            RType::NS => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Ns)
            }

            RType::CNAME => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::CName)
            }

            RType::SOA => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Soa)
            }

            RType::PTR => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Ptr)
            }

            RType::HINFO => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::HInfo)
            }

            RType::MX => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Mx)
            }

            RType::TXT => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Txt)
            }

            RType::DS => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::Ds)
            }

            RType::RRSIG => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::RRSig)
            }

            RType::NSEC => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::NSec)
            }

            RType::DNSKEY => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::DNSKey)
            }

            RType::NSEC3 => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::NSec3)
            }

            RType::NSEC3PARAM => {
                Scan::scan(scanner, alloc, buffer)
                    .map(Self::NSec3Param)
            }

            _ => Err(ScanError::Custom("The concrete format for this record type is currently unsupported")),
        }
    }
}

//----------- UnknownRecordData ----------------------------------------------

/// Data for an unknown DNS record type.
#[derive(Debug, AsBytes, BuildBytes, ParseBytesByRef, PartialEq, Eq)]
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
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan_unknown() {
        use crate::{
            new_base::wire::AsBytes,
            new_zonefile::scanner::{Scan, ScanError, Scanner},
        };

        use super::UnknownRecordData;

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
