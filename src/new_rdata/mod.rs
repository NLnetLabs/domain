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

//----------- Concrete record data types -------------------------------------

mod basic;
pub use basic::{CName, HInfo, Mx, Ns, Ptr, Soa, Txt, Wks, A};

mod ipv6;
pub use ipv6::Aaaa;

mod edns;
pub use edns::{EdnsOptionsIter, Opt};

mod dnssec;
pub use dnssec::{
    DNSKey, DigestType, Ds, NSec, NSec3, NSec3Flags, NSec3HashAlg, RRSig,
    SecAlg,
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
            Self::Unknown(rt, rd) => RecordData::Unknown(*rt, rd),
        }
    }
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
            Self::Unknown(_, r) => r.build_bytes(bytes),
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
