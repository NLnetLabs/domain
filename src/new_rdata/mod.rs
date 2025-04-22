//! Record data types.
//!
//! ## Containers for record data
//!
//! When you need data for a particular record type, you can use the matching
//! concrete type for it.  Otherwise, the record data can be held in one of
//! the following types:
//!
//! - [`RecordData`] is useful for short-term usage, e.g. when manipulating a
//!   DNS message or parsing into a custom representation.  It can be parsed
//!   from the wire format very efficiently.
//!
//! - [`BoxedRecordData`] is useful for long-term storage.  For long-term
//!   storage of a whole DNS zone, it's more advisable to use the "zone tree"
//!   types provided by this crate.
//!
//! - [`UnparsedRecordData`](crate::new_base::UnparsedRecordData) is a niche
//!   type, useful for low-level manipulation of the DNS wire format.  Beware
//!   that it can contain unresolved name compression pointers.
//!
//! ## Supported data types
//!
//! The following record data types are supported.  They are enumerated by
//! [`RecordData`], which can store any one of them at a time.
//!
//! Basic record types (RFC 1035):
//! - [`A`]
//! - [`Ns`]
//! - [`CName`]
//! - [`Soa`]
//! - [`Wks`]
//! - [`Ptr`]
//! - [`HInfo`]
//! - [`Mx`]
//! - [`Txt`]
//!
//! IPv6 support (RFC 3596):
//! - [`Aaaa`]
//!
//! EDNS support (RFC 6891):
//! - [`Opt`]
//!
//! DNSSEC support (RFC 4034, RFC 5155):
//! - [`DNSKey`]
//! - [`RRSig`]
//! - [`NSec`]
//! - [`NSec3`]
//! - [`Ds`]

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]

use core::cmp::Ordering;

#[cfg(feature = "std")]
use core::fmt;

#[cfg(feature = "std")]
use std::boxed::Box;

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

#[cfg(feature = "std")]
use crate::new_base::name::{Name, NameBuf};

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
        use crate::utils::dst::copy_to_bump;

        match self {
            Self::A(r) => RecordData::A(*r),
            Self::Ns(r) => RecordData::Ns(r.clone()),
            Self::CName(r) => RecordData::CName(r.clone()),
            Self::Soa(r) => RecordData::Soa(r.clone()),
            Self::Wks(r) => RecordData::Wks(copy_to_bump(*r, bump)),
            Self::Ptr(r) => RecordData::Ptr(r.clone()),
            Self::HInfo(r) => RecordData::HInfo(r.clone_to_bump(bump)),
            Self::Mx(r) => RecordData::Mx(r.clone()),
            Self::Txt(r) => RecordData::Txt(copy_to_bump(*r, bump)),
            Self::Aaaa(r) => RecordData::Aaaa(*r),
            Self::Opt(r) => RecordData::Opt(copy_to_bump(*r, bump)),
            Self::Ds(r) => RecordData::Ds(copy_to_bump(*r, bump)),
            Self::RRSig(r) => RecordData::RRSig(r.clone_to_bump(bump)),
            Self::NSec(r) => RecordData::NSec(r.clone_to_bump(bump)),
            Self::DNSKey(r) => RecordData::DNSKey(copy_to_bump(*r, bump)),
            Self::NSec3(r) => RecordData::NSec3(r.clone_to_bump(bump)),
            Self::NSec3Param(r) => {
                RecordData::NSec3Param(copy_to_bump(*r, bump))
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

//----------- BoxedRecordData ------------------------------------------------

/// A heap-allocated container for [`RecordData`].
///
/// This is an efficient heap-allocated container for DNS record data.  While
/// it does not directly provide much functionality, it has getters to access
/// the [`RecordData`] within.
///
/// ## Performance
///
/// On 64-bit machines, [`BoxedRecordData`] has a size of 16 bytes.  This is
/// significantly better than [`RecordData`], which is usually 64 bytes in
/// size.  Since [`BoxedRecordData`] is intended for long-term storage and
/// use, it trades off ergonomics for lower memory usage.
#[cfg(feature = "std")]
pub struct BoxedRecordData {
    /// A pointer to the record data.
    ///
    /// This is the raw pointer backing a `Box<[u8]>` (its size is stored in
    /// the `size` field).  It is owned by this type.
    data: *mut u8,

    /// The record data type.
    ///
    /// The stored bytes represent a valid instance of this record data type,
    /// at least for all known record data types.
    rtype: RType,

    /// The size of the record data.
    size: u16,
}

//--- Inspection

#[cfg(feature = "std")]
impl BoxedRecordData {
    /// The record data type.
    pub const fn rtype(&self) -> RType {
        self.rtype
    }

    /// The wire format of the record data.
    pub const fn bytes(&self) -> &[u8] {
        // SAFETY:
        //
        // As documented on 'BoxedRecordData', 'data' and 'size' form the
        // pointer and length of a 'Box<[u8]>'.  This pointer is identical to
        // the pointer returned by 'Box::deref()', so we use it directly.
        //
        // The lifetime of the returned slice is within the lifetime of 'self'
        // which is a shared borrow of the 'BoxedRecordData'.  As such, the
        // underlying 'Box<[u8]>' outlives the returned slice.
        unsafe { core::slice::from_raw_parts(self.data, self.size as usize) }
    }

    /// Access the [`RecordData`] within.
    pub fn get(&self) -> RecordData<'_, &'_ Name> {
        let (rtype, bytes) = (self.rtype, self.bytes());
        // SAFETY: As documented on 'BoxedRecordData', the referenced bytes
        // are known to be a valid instance of the record data type (for all
        // known record data types).  As such, this function will succeed.
        unsafe {
            RecordData::parse_record_data_bytes(bytes, rtype)
                .unwrap_unchecked()
        }
    }
}

//--- Formatting

#[cfg(feature = "std")]
impl fmt::Debug for BoxedRecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // This should concatenate to form 'BoxedRecordData'.
        f.write_str("Boxed")?;
        self.get().fmt(f)
    }
}

//--- Equality

#[cfg(feature = "std")]
impl PartialEq for BoxedRecordData {
    fn eq(&self, other: &Self) -> bool {
        self.get().eq(&other.get())
    }
}

#[cfg(feature = "std")]
impl Eq for BoxedRecordData {}

//--- Clone

#[cfg(feature = "std")]
impl Clone for BoxedRecordData {
    fn clone(&self) -> Self {
        let bytes: Box<[u8]> = self.bytes().into();
        let data = Box::into_raw(bytes).cast::<u8>();
        let (rtype, size) = (self.rtype, self.size);
        Self { data, rtype, size }
    }
}

//--- Drop

#[cfg(feature = "std")]
impl Drop for BoxedRecordData {
    fn drop(&mut self) {
        // Reconstruct the 'Box' and drop it.
        let slice = core::ptr::slice_from_raw_parts_mut(
            self.data,
            self.size as usize,
        );

        // SAFETY: As documented on 'BoxedRecordData', 'data' and 'size' form
        // the pointer and length of a 'Box<[u8]>'.  Reconstructing the 'Box'
        // moves out of 'self', but this is sound because 'self' is dropped.
        let _ = unsafe { Box::from_raw(slice) };
    }
}

//--- Send and Sync

// SAFETY: 'BoxedRecordData' is equivalent to '(RType, Box<[u8]>)' with a
// custom representation.  It cannot cause data races.
#[cfg(feature = "std")]
unsafe impl Send for BoxedRecordData {}

// SAFETY: 'BoxedRecordData' is equivalent to '(RType, Box<[u8]>)' with a
// custom representation.  It cannot cause data races.
#[cfg(feature = "std")]
unsafe impl Sync for BoxedRecordData {}

//--- Conversion from 'RecordData'

#[cfg(feature = "std")]
impl<N: BuildBytes> From<RecordData<'_, N>> for BoxedRecordData {
    /// Build a [`RecordData`] into a heap allocation.
    ///
    /// # Panics
    ///
    /// Panics if the [`RecordData`] does not fit in a 64KiB buffer, or if the
    /// serialized bytes cannot be parsed back into `RecordData<'_, &Name>`.
    fn from(value: RecordData<'_, N>) -> Self {
        // TODO: Determine the size of the record data upfront, and only
        // allocate that much.  Maybe as a new method on 'BuildBytes'...
        let mut buffer = vec![0u8; 65535];
        let rest_len = value
            .build_bytes(&mut buffer)
            .expect("A 'RecordData' could not be built into a 64KiB buffer")
            .len();
        let len = buffer.len() - rest_len;
        buffer.truncate(len);
        let buffer: Box<[u8]> = buffer.into_boxed_slice();

        // Verify that the built bytes can be parsed correctly.
        let _rdata: RecordData<'_, &Name> =
            RecordData::parse_record_data_bytes(&buffer, value.rtype())
                .expect("A serialized 'RecordData' could not be parsed back");

        // Construct the internal representation.
        let size = buffer.len() as u16;
        let data = Box::into_raw(buffer).cast::<u8>();
        let rtype = value.rtype();
        Self { data, rtype, size }
    }
}

//--- Canonical operations

#[cfg(feature = "std")]
impl CanonicalRecordData for BoxedRecordData {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        if self.rtype.uses_lowercase_canonical_form() {
            // Forward to the semantically correct operation.
            self.get().build_canonical_bytes(bytes)
        } else {
            // The canonical format is the same as the wire format.
            self.bytes().build_bytes(bytes)
        }
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        // Compare record data types.
        if self.rtype != other.rtype {
            return self.rtype.cmp(&other.rtype);
        }

        if self.rtype.uses_lowercase_canonical_form() {
            // Forward to the semantically correct operation.
            self.get().cmp_canonical(&other.get())
        } else {
            // Compare raw byte sequences.
            self.bytes().cmp(other.bytes())
        }
    }
}

//--- Parsing record data

#[cfg(feature = "std")]
impl ParseRecordData<'_> for BoxedRecordData {
    fn parse_record_data(
        contents: &'_ [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        RecordData::<'_, NameBuf>::parse_record_data(contents, start, rtype)
            .map(BoxedRecordData::from)
    }
}

#[cfg(feature = "std")]
impl ParseRecordDataBytes<'_> for BoxedRecordData {
    fn parse_record_data_bytes(
        bytes: &'_ [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        // Ensure the bytes form valid 'RecordData'.
        let _rdata: RecordData<'_, &Name> =
            RecordData::parse_record_data_bytes(bytes, rtype)?;

        // Ensure the data size is valid.
        let size = u16::try_from(bytes.len()).map_err(|_| ParseError)?;

        // Construct the 'BoxedRecordData' manually.
        let bytes: Box<[u8]> = bytes.into();
        let data = Box::into_raw(bytes).cast::<u8>();
        Ok(Self { data, rtype, size })
    }
}

//--- Building record data

// TODO: 'impl BuildIntoMessage for BoxedRecordData' will require implementing
// 'impl BuildIntoMessage for Name', which is difficult because it is hard on
// name compression.

#[cfg(feature = "std")]
impl BuildBytes for BoxedRecordData {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.bytes().build_bytes(bytes)
    }
}

//----------- UnknownRecordData ----------------------------------------------

/// Data for an unknown DNS record type.
///
/// This is a fallback type, used for record types not known to the current
/// implementation.  It must not be used for well-known record types, because
/// some of them have special rules that this type does not follow.
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
