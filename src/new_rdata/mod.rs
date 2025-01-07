//! Record data types.

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage},
    parse::{ParseFromMessage, SplitFromMessage},
    wire::{BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError},
    Message, ParseRecordData, RType,
};

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
    N: SplitBytes<'a> + SplitFromMessage<'a>,
{
    fn parse_record_data(
        message: &'a Message,
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => <&A>::parse_from_message(message, start).map(Self::A),
            RType::NS => Ns::parse_from_message(message, start).map(Self::Ns),
            RType::CNAME => {
                CName::parse_from_message(message, start).map(Self::CName)
            }
            RType::SOA => {
                Soa::parse_from_message(message, start).map(Self::Soa)
            }
            RType::WKS => {
                <&Wks>::parse_from_message(message, start).map(Self::Wks)
            }
            RType::PTR => {
                Ptr::parse_from_message(message, start).map(Self::Ptr)
            }
            RType::HINFO => {
                HInfo::parse_from_message(message, start).map(Self::HInfo)
            }
            RType::MX => Mx::parse_from_message(message, start).map(Self::Mx),
            RType::TXT => {
                <&Txt>::parse_from_message(message, start).map(Self::Txt)
            }
            RType::AAAA => {
                <&Aaaa>::parse_from_message(message, start).map(Self::Aaaa)
            }
            RType::OPT => {
                <&Opt>::parse_from_message(message, start).map(Self::Opt)
            }
            _ => <&UnknownRecordData>::parse_from_message(message, start)
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
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
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
