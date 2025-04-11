//! Record data types.

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    name::CanonicalName,
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{
        AsBytes, BuildBytes, ParseBytes, ParseError, SplitBytes,
        TruncationError,
    },
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
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
    DNSKey, DNSKeyFlags, DigestType, Ds, NSec, NSec3, NSec3Flags,
    NSec3HashAlg, NSec3Param, RRSig, SecAlg, TypeBitmaps,
};

//----------- RecordData -----------------------------------------------------

/// DNS record data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordData<'a, N> {
    /// The IPv4 address of a host responsible for this domain.
    A(A),

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
    Aaaa(Aaaa),

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
        match *self {
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
            Self::Unknown(rtype, _) => rtype,
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
            Self::A(r) => RecordData::A(*r),
            Self::Ns(r) => RecordData::Ns(r.map_name_by_ref(f)),
            Self::CName(r) => RecordData::CName(r.map_name_by_ref(f)),
            Self::Soa(r) => RecordData::Soa(r.map_names_by_ref(f)),
            Self::Wks(r) => RecordData::Wks(r),
            Self::Ptr(r) => RecordData::Ptr(r.map_name_by_ref(f)),
            Self::HInfo(r) => RecordData::HInfo(r.clone()),
            Self::Mx(r) => RecordData::Mx(r.map_name_by_ref(f)),
            Self::Txt(r) => RecordData::Txt(r),
            Self::Aaaa(r) => RecordData::Aaaa(*r),
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

    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(
        &self,
        bump: &'r bumpalo::Bump,
    ) -> RecordData<'r, N>
    where
        N: Clone,
    {
        use crate::utils::clone_to_bump;

        match self {
            Self::A(r) => RecordData::A(*r),
            Self::Ns(r) => RecordData::Ns(r.clone()),
            Self::CName(r) => RecordData::CName(r.clone()),
            Self::Soa(r) => RecordData::Soa(r.clone()),
            Self::Wks(r) => RecordData::Wks(clone_to_bump(*r, bump)),
            Self::Ptr(r) => RecordData::Ptr(r.clone()),
            Self::HInfo(r) => RecordData::HInfo(r.clone_to_bump(bump)),
            Self::Mx(r) => RecordData::Mx(r.clone()),
            Self::Txt(r) => RecordData::Txt(clone_to_bump(*r, bump)),
            Self::Aaaa(r) => RecordData::Aaaa(*r),
            Self::Opt(r) => RecordData::Opt(clone_to_bump(*r, bump)),
            Self::Ds(r) => RecordData::Ds(clone_to_bump(*r, bump)),
            Self::RRSig(r) => RecordData::RRSig(r.clone_to_bump(bump)),
            Self::NSec(r) => RecordData::NSec(r.clone_to_bump(bump)),
            Self::DNSKey(r) => RecordData::DNSKey(clone_to_bump(*r, bump)),
            Self::NSec3(r) => RecordData::NSec3(r.clone_to_bump(bump)),
            Self::NSec3Param(r) => {
                RecordData::NSec3Param(clone_to_bump(*r, bump))
            }
            Self::Unknown(rt, rd) => {
                RecordData::Unknown(*rt, rd.clone_to_bump(bump))
            }
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for RecordData<'_, N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        match self {
            Self::A(r) => r.build_canonical_bytes(bytes),
            Self::Ns(r) => r.build_canonical_bytes(bytes),
            Self::CName(r) => r.build_canonical_bytes(bytes),
            Self::Soa(r) => r.build_canonical_bytes(bytes),
            Self::Wks(r) => r.build_canonical_bytes(bytes),
            Self::Ptr(r) => r.build_canonical_bytes(bytes),
            Self::HInfo(r) => r.build_canonical_bytes(bytes),
            Self::Mx(r) => r.build_canonical_bytes(bytes),
            Self::Txt(r) => r.build_canonical_bytes(bytes),
            Self::Aaaa(r) => r.build_canonical_bytes(bytes),
            Self::Opt(r) => r.build_canonical_bytes(bytes),
            Self::Ds(r) => r.build_canonical_bytes(bytes),
            Self::RRSig(r) => r.build_canonical_bytes(bytes),
            Self::NSec(r) => r.build_canonical_bytes(bytes),
            Self::DNSKey(r) => r.build_canonical_bytes(bytes),
            Self::NSec3(r) => r.build_canonical_bytes(bytes),
            Self::NSec3Param(r) => r.build_canonical_bytes(bytes),
            Self::Unknown(_, rd) => rd.build_canonical_bytes(bytes),
        }
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.rtype()
            .cmp(&other.rtype())
            .then_with(|| match (self, other) {
                (Self::A(l), Self::A(r)) => l.cmp_canonical(r),
                (Self::Ns(l), Self::Ns(r)) => l.cmp_canonical(r),
                (Self::CName(l), Self::CName(r)) => l.cmp_canonical(r),
                (Self::Soa(l), Self::Soa(r)) => l.cmp_canonical(r),
                (Self::Wks(l), Self::Wks(r)) => l.cmp_canonical(r),
                (Self::Ptr(l), Self::Ptr(r)) => l.cmp_canonical(r),
                (Self::HInfo(l), Self::HInfo(r)) => l.cmp_canonical(r),
                (Self::Mx(l), Self::Mx(r)) => l.cmp_canonical(r),
                (Self::Txt(l), Self::Txt(r)) => l.cmp_canonical(r),
                (Self::Aaaa(l), Self::Aaaa(r)) => l.cmp_canonical(r),
                (Self::Opt(l), Self::Opt(r)) => l.cmp_canonical(r),
                (Self::Ds(l), Self::Ds(r)) => l.cmp_canonical(r),
                (Self::RRSig(l), Self::RRSig(r)) => l.cmp_canonical(r),
                (Self::NSec(l), Self::NSec(r)) => l.cmp_canonical(r),
                (Self::DNSKey(l), Self::DNSKey(r)) => l.cmp_canonical(r),
                (Self::NSec3(l), Self::NSec3(r)) => l.cmp_canonical(r),
                (Self::NSec3Param(l), Self::NSec3Param(r)) => {
                    l.cmp_canonical(r)
                }
                (Self::Unknown(_, l), Self::Unknown(_, r)) => {
                    l.cmp_canonical(r)
                }
                _ => unreachable!("'self' and 'other' had the same rtype but were different enum variants"),
            })
    }
}

//--- Parsing record data

impl<'a, N: SplitMessageBytes<'a>> ParseRecordData<'a> for RecordData<'a, N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => A::parse_bytes(&contents[start..]).map(Self::A),
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
                Aaaa::parse_bytes(&contents[start..]).map(Self::Aaaa)
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
}

impl<'a, N: SplitBytes<'a>> ParseRecordDataBytes<'a> for RecordData<'a, N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::A => A::parse_bytes(bytes).map(Self::A),
            RType::NS => Ns::parse_bytes(bytes).map(Self::Ns),
            RType::CNAME => CName::parse_bytes(bytes).map(Self::CName),
            RType::SOA => Soa::parse_bytes(bytes).map(Self::Soa),
            RType::WKS => <&Wks>::parse_bytes(bytes).map(Self::Wks),
            RType::PTR => Ptr::parse_bytes(bytes).map(Self::Ptr),
            RType::HINFO => HInfo::parse_bytes(bytes).map(Self::HInfo),
            RType::MX => Mx::parse_bytes(bytes).map(Self::Mx),
            RType::TXT => <&Txt>::parse_bytes(bytes).map(Self::Txt),
            RType::AAAA => Aaaa::parse_bytes(bytes).map(Self::Aaaa),
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

//----------- UnknownRecordData ----------------------------------------------

/// Data for an unknown DNS record type.
#[derive(Debug, AsBytes, BuildBytes, ParseBytesByRef, PartialEq, Eq)]
#[repr(transparent)]
pub struct UnknownRecordData {
    /// The unparsed option data.
    pub octets: [u8],
}

//--- Interaction

impl UnknownRecordData {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    #[allow(clippy::mut_from_ref)] // using a memory allocator
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> &'r mut Self {
        use crate::new_base::wire::{AsBytes, ParseBytesByRef};

        let bytes = bump.alloc_slice_copy(self.as_bytes());
        // SAFETY: 'ParseBytesByRef' and 'AsBytes' are inverses.
        unsafe { Self::parse_bytes_by_mut(bytes).unwrap_unchecked() }
    }
}

//--- Canonical operations

impl CanonicalRecordData for UnknownRecordData {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        // Since this is not a well-known record data type, embedded domain
        // names do not need to be lowercased.
        self.octets.cmp(&other.octets)
    }
}
