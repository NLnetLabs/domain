//! DNS records.

use core::{borrow::Borrow, cmp::Ordering, fmt, ops::Deref};

use crate::utils::dst::UnsizedCopy;

use super::super::rdata::{BoxedRecordData, RecordData};
use super::build::{BuildInMessage, NameCompressor};
use super::parse::{ParseMessageBytes, SplitMessageBytes};
use super::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError, SizePrefixed,
    SplitBytes, SplitBytesZC, TruncationError, U16, U32,
};

//----------- Marco ----------------------------------------------------------
/// Enum Type implementation
///
/// This Macros is used to write boilerplate `match` functions which turn the
/// Self type into the mnemonic and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - get_mnemonic()
/// - from_mnemonic()
#[macro_export]
macro_rules! enum_type{
    ( $(#[$attr:meta])* =>
      $enumtype:ident;
      $( $(#[$variant_attr:meta])*
    ( $variant:ident => $value:expr, $mnemonic:expr) )* ) => {
        // create constants
        impl $enumtype {
            $(
                $(#[$variant_attr])*
                pub const $variant: $enumtype = $enumtype::new($value);
            )*
        }

        // create conversion functions
        impl $enumtype{
            /// Returns mnemonic representation of this type if defined.
            #[must_use]
            pub fn get_mnemonic(&self) -> Option<&'static str> {
                let mnemonic = match self {
                $(
                    &$enumtype::$variant => Some($mnemonic),
                )*
                    _ => None, // default case if mnemonic is unknown
                };
                return mnemonic;
            }

            /// Returns Self if mnemonic is recognised.
            #[must_use]
            pub fn from_mnemonic(mnemonic: &str) -> Option<Self> {
                let rtype = match mnemonic.to_uppercase().as_str() {
                $(
                     $mnemonic => Some($enumtype::$variant),
                )*
                    _ => None, // default case if mnemonic is unknown
                };
                return rtype;
            }
        }
    }
}

/// From for Enum Type implementation
///
/// This macro implements conversions from the primitive type into the enum
/// type and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - fn from(value: $inttype) -> $enumtype
/// - fn from(value: $enumtype) -> $inttype
#[macro_export]
macro_rules! enum_type_from_and_to_primative {
    ( $(#[$attr:meta])* =>
      $enumtype:ident, $inttype:ident;) => {
        //--- Conversion to and from primative
        impl From<$inttype> for $enumtype {
            fn from(value: $inttype) -> Self {
                Self::new(value)
            }
        }

        impl From<$enumtype> for $inttype {
            fn from(value: $enumtype) -> Self {
                value.code.get()
            }
        }
    };
}

//----------- Record ---------------------------------------------------------

/// A DNS record.
///
/// ```
/// use domain::new::base;
/// use domain::new::rdata;
///
/// // Construct DNS Record with `RevNameBuf` as the `rname` and a `Cname`
/// // record with a `NameBuf`
/// let record: base::Record<
///     base::name::RevNameBuf,
///     rdata::CName<base::name::NameBuf>,
/// > = base::Record {
///     rname: "www.nlnetlabs.nl.".parse().unwrap(),
///     rtype: base::RType::CNAME,
///     rclass: base::RClass::IN,
///     ttl: base::TTL::from(3600),
///     rdata: rdata::CName {
///         name: "nlnetlabs.nl.".parse().unwrap(),
///     },
/// };
///
/// // Convert the `rname` from `RevNameBuf` into `NameBuf` but keep the
/// // `rdata` untouched.
/// let record: base::Record<
///     base::name::NameBuf,
///     rdata::CName<base::name::NameBuf>,
/// > = record.transform(
///     |name: base::name::RevNameBuf| name.into(),
///     |data: rdata::CName<base::name::NameBuf>| data,
/// );
///
/// println!("{:?}", record);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Record<N, D> {
    /// The name of the record.
    pub rname: N,

    /// The type of the record.
    pub rtype: RType,

    /// The class of the record.
    pub rclass: RClass,

    /// How long the record is reliable for.
    pub ttl: TTL,

    /// Unparsed record data.
    pub rdata: D,
}

//--- Construction

impl<N, D> Record<N, D> {
    /// Construct a new [`Record`].
    pub fn new(
        rname: N,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
        rdata: D,
    ) -> Self {
        Self {
            rname,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }
}

//--- Transformation

impl<N, D> Record<N, D> {
    /// Transform this type's generic parameters.
    pub fn transform<NN, ND>(
        self,
        name_map: impl FnOnce(N) -> NN,
        data_map: impl FnOnce(D) -> ND,
    ) -> Record<NN, ND> {
        Record {
            rname: (name_map)(self.rname),
            rtype: self.rtype,
            rclass: self.rclass,
            ttl: self.ttl,
            rdata: (data_map)(self.rdata),
        }
    }

    /// Transform this type's generic parameters by reference.
    pub fn transform_ref<'a, NN, ND>(
        &'a self,
        name_map: impl FnOnce(&'a N) -> NN,
        data_map: impl FnOnce(&'a D) -> ND,
    ) -> Record<NN, ND> {
        Record {
            rname: (name_map)(&self.rname),
            rtype: self.rtype,
            rclass: self.rclass,
            ttl: self.ttl,
            rdata: (data_map)(&self.rdata),
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N, D> SplitMessageBytes<'a> for Record<N, D>
where
    N: SplitMessageBytes<'a>,
    D: ParseRecordData<'a>,
{
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (rname, rest) = N::split_message_bytes(contents, start)?;
        let (&rtype, rest) = <&RType>::split_message_bytes(contents, rest)?;
        let (&rclass, rest) = <&RClass>::split_message_bytes(contents, rest)?;
        let (&ttl, rest) = <&TTL>::split_message_bytes(contents, rest)?;
        let rdata_start = rest;
        let (_, rest) =
            <&SizePrefixed<U16, [u8]>>::split_message_bytes(contents, rest)?;
        let rdata =
            D::parse_record_data(&contents[..rest], rdata_start + 2, rtype)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a, N, D> ParseMessageBytes<'a> for Record<N, D>
where
    N: SplitMessageBytes<'a>,
    D: ParseRecordData<'a>,
{
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        match Self::split_message_bytes(contents, start) {
            Ok((this, rest)) if rest == contents.len() => Ok(this),
            _ => Err(ParseError),
        }
    }
}

//--- Building into DNS messages

impl<N, D> BuildInMessage for Record<N, D>
where
    N: BuildInMessage,
    D: BuildInMessage,
{
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self.rname.build_in_message(contents, start, compressor)?;
        // For more efficiency, copy the bytes manually.
        let end = start + 8;
        let bytes = contents.get_mut(start..end).ok_or(TruncationError)?;
        bytes[0..2].copy_from_slice(self.rtype.as_bytes());
        bytes[2..4].copy_from_slice(self.rclass.as_bytes());
        bytes[4..8].copy_from_slice(self.ttl.as_bytes());
        start = end;
        // Build the record data with a 16-bit size prefix.
        start = SizePrefixed::<U16, _>::new(&self.rdata)
            .build_in_message(contents, start, compressor)?;
        Ok(start)
    }
}

//--- Parsing from bytes

impl<'a, N, D> SplitBytes<'a> for Record<N, D>
where
    N: SplitBytes<'a>,
    D: ParseRecordDataBytes<'a>,
{
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (rname, rest) = N::split_bytes(bytes)?;
        let (rtype, rest) = RType::split_bytes(rest)?;
        let (rclass, rest) = RClass::split_bytes(rest)?;
        let (ttl, rest) = TTL::split_bytes(rest)?;
        let (rdata, rest) = <&SizePrefixed<U16, [u8]>>::split_bytes(rest)?;
        let rdata = D::parse_record_data_bytes(rdata, rtype)?;

        Ok((Self::new(rname, rtype, rclass, ttl, rdata), rest))
    }
}

impl<'a, N, D> ParseBytes<'a> for Record<N, D>
where
    N: SplitBytes<'a>,
    D: ParseRecordDataBytes<'a>,
{
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

//--- Building into byte sequences

impl<N, D> BuildBytes for Record<N, D>
where
    N: BuildBytes,
    D: BuildBytes,
{
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.rname.build_bytes(bytes)?;
        bytes = self.rtype.as_bytes().build_bytes(bytes)?;
        bytes = self.rclass.as_bytes().build_bytes(bytes)?;
        bytes = self.ttl.as_bytes().build_bytes(bytes)?;
        bytes =
            SizePrefixed::<U16, _>::new(&self.rdata).build_bytes(bytes)?;

        Ok(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.rname.built_bytes_size() + 10 + self.rdata.built_bytes_size()
    }
}

//----------- RType ----------------------------------------------------------

/// The type of a record.
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
pub struct RType {
    /// The type code.
    pub code: U16,
}

//--- Associated Constants

impl RType {
    /// Create a new [`RType`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

// [`RType`] implementation using Macro. See macro for implementation details
enum_type! {
    =>
    RType;
    /// The type of an [`A`](crate::new::rdata::A) record.
    (A => 1, "A")

    /// The type of an [`Ns`](crate::new::rdata::Ns) record.
    (NS => 2, "NS")

    /// The type of a [`CName`](crate::new::rdata::CName) record.
    (CNAME => 5, "CNAME")

    /// The type of an [`Soa`](crate::new::rdata::Soa) record.
    (SOA => 6, "SOA")

    /// The type of a [`Ptr`](crate::new::rdata::Ptr) record.
    (PTR => 12, "PTR")

    /// The type of a [`HInfo`](crate::new::rdata::HInfo) record.
    (HINFO => 13, "HINFO")

    /// The type of a [`Mx`](crate::new::rdata::Mx) record.
    (MX => 15, "MX")

    /// The type of a [`Txt`](crate::new::rdata::Txt) record.
    (TXT => 16, "TXT")

    /// The type of an [`Rp`](crate::new::rdata::Rp) record.
    (RP => 17, "RP")

    /// The type of an [`Aaaa`](crate::new::rdata::Aaaa) record.
    (AAAA => 28, "AAAA")

    /// The type of a [`DName`](crate::new::rdata::DName) record.
    (DNAME => 39, "DNAME")

    /// The type of an [`Opt`](crate::new::rdata::Opt) record.
    (OPT => 41, "OPT")

    /// The type of a [`Ds`](crate::new::rdata::Ds) record.
    (DS => 43, "DS")

    /// The type of an [`Rrsig`](crate::new::rdata::Rrsig) record.
    (RRSIG => 46, "RRSIG")

    /// The type of an [`Nsec`](crate::new::rdata::Nsec) record.
    (NSEC => 47, "NSEC")

    /// The type of a [`DNSKey`](crate::new::rdata::DNSKey) record.
    (DNSKEY => 48, "DNSKEY")

    /// The type of an [`Nsec3`](crate::new::rdata::Nsec3) record.
    (NSEC3 => 50, "NSEC3")

    /// The type of an [`Nsec3Param`](crate::new::rdata::Nsec3Param) record.
    (NSEC3PARAM => 51, "NSEC3PARAM")

    /// The type of a `Cds` record.
    (CDS => 59, "CDS")

    /// The type of a `CDNSKey` record.
    (CDNSKEY => 60, "CDNSKEY")

    /// The type of a [`ZoneMD`](crate::new::rdata::ZoneMD) record.
    (ZONEMD => 63, "ZONEMD")

    /// The type of a `TSig` record.
    (TSIG => 250, "TSIG")
}

//--- Interaction

impl RType {
    /// Whether this type uses lowercased domain names in canonical form.
    ///
    /// As specified by [RFC 4034, section 6.2] (and updated by [RFC 6840,
    /// section 5.1]), the canonical form of the record data of any of the
    /// following types will have its domain names lowercased:
    ///
    /// - [`NS`](RType::NS)
    /// - `MD` (obsolete)
    /// - `MF` (obsolete)
    /// - [`CNAME`](RType::CNAME)
    /// - [`SOA`](RType::SOA)
    /// - `MB`
    /// - `MG`
    /// - `MR`
    /// - [`PTR`](RType::PTR)
    /// - `MINFO`
    /// - [`MX`](RType::MX)
    /// - [`RP`](RType::RP)
    /// - `AFSDB`
    /// - `RT`
    /// - `SIG` (obsolete)
    /// - `PX`
    /// - `NXT` (obsolete)
    /// - `NAPTR`
    /// - `KX`
    /// - `SRV`
    /// - [`DNAME`](RType::DNAME)
    /// - `A6` (obsolete)
    /// - [`RRSIG`](RType::RRSIG)
    ///
    /// [RFC 4034, section 6.2]: https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
    /// [RFC 6840, section 5.1]: https://datatracker.ietf.org/doc/html/rfc6840#section-5.1
    pub const fn uses_lowercase_canonical_form(&self) -> bool {
        // TODO: Update this as more types are added.
        matches!(
            *self,
            Self::NS
                | Self::CNAME
                | Self::SOA
                | Self::PTR
                | Self::MX
                | Self::RP
                | Self::DNAME
                | Self::RRSIG
        )
    }
}

//--- Conversion to and from 'u16'

enum_type_from_and_to_primative!(=> RType, u16;);

//--- Formatting

impl fmt::Debug for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "RType::{}", m),
            None => write!(f, "RType({})", self.code),
        }
    }
}

/// Format an [`RType`] in a human-readable way
///
/// Return the mnemonic of [`RType`]. If [`RType`] is unknown, then the
/// returned string contains the type in the unknown format as defined in
/// Section 5 in [RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::RType;
/// // Known RType with mnemonic
/// assert_eq!("A", format!("{}", RType::A));
/// // Unknown RType
/// assert_eq!("TYPE265", format!("{}", RType::from(265)));
/// ```
///
/// [RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
impl fmt::Display for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "{}", m),
            None => write!(f, "TYPE{}", self.code),
        }
    }
}

//----------- RClass ---------------------------------------------------------

/// The class of a record.
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
pub struct RClass {
    /// The class code.
    pub code: U16,
}

//--- Associated Constants

impl RClass {
    /// Create a new [`RType`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

enum_type! {
    =>
    RClass;
    /// The Internet class.
    (IN => 1, "IN")
    /// The CHAOS class.
    (CH => 3, "CH")
}

//--- Conversion to and from 'u16'

enum_type_from_and_to_primative!(=> RClass, u16;);

//--- Formatting

impl fmt::Debug for RClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "RClass::{}", m),
            None => write!(f, "RClass({})", self.code),
        }
    }
}

/// Format an [`RClass`] in a human-readable way
///
/// Return the mnemonic of [`RClass`]. If [`RClass`] is unknown, then the
/// returned string contains the class in the unknown format as defined in
/// Section 5 in [RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::RClass;
/// // Known RClass with mnemonic
/// assert_eq!("IN", format!("{}", RClass::IN));
/// // Unknown RClass
/// assert_eq!("CLASS42", format!("{}", RClass::from(42)));
/// ```
///
/// [RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
impl fmt::Display for RClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "{}", m),
            None => write!(f, "CLASS{}", self.code),
        }
    }
}

//----------- TTL ------------------------------------------------------------

/// How long a record can be cached.
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
pub struct TTL {
    /// The underlying value.
    pub value: U32,
}

//--- Conversion to and from integers

impl From<u32> for TTL {
    fn from(value: u32) -> Self {
        Self {
            value: U32::new(value),
        }
    }
}

impl From<TTL> for u32 {
    fn from(value: TTL) -> Self {
        value.value.get()
    }
}

//--- Formatting

impl fmt::Debug for TTL {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TTL({})", self.value)
    }
}

//--- Compatibility with old base
impl TTL {
    /// Return the TTL value in seconds.
    pub fn as_secs(&self) -> u32 {
        self.value.into()
    }
}

//----------- ParseRecordData ------------------------------------------------

/// Parsing DNS record data.
pub trait ParseRecordData<'a>: ParseRecordDataBytes<'a> {
    /// Parse DNS record data of the given type from a DNS message.
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        Self::parse_record_data_bytes(&contents[start..], rtype)
    }
}

/// Parsing DNS record data without name compression.
pub trait ParseRecordDataBytes<'a>: Sized {
    /// Parse DNS record data of the given type from a byte sequence.
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError>;
}

//----------- CanonicalRecordData --------------------------------------------

/// DNSSEC-conformant operations for resource records.
///
/// As specified by [RFC 4034, section 6], there is a "canonical form" for
/// DNS resource records, used for ordering records and computing signatures.
/// This trait defines operations for working with the canonical form.
///
/// [RFC 4034, section 6]: https://datatracker.ietf.org/doc/html/rfc4034#section-6
pub trait CanonicalRecordData: BuildBytes {
    /// Serialize record data in the canonical form.
    ///
    /// This is subtly different from [`BuildBytes`]: for certain special
    /// record data types, it causes embedded domain names to be lowercased.
    /// By default, it will fall back to [`BuildBytes`].
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.build_bytes(bytes)
    }

    /// Compare record data in the canonical form.
    ///
    /// This is equivalent to serializing both record data instances using
    /// [`Self::build_canonical_bytes()`] and comparing the resulting byte sequences.
    fn cmp_canonical(&self, other: &Self) -> Ordering;
}

/// Implement [`CanonicalRecordData`] for a [`Deref`]-based generic container.
macro_rules! impl_canonical_record_data_for_deref {
    {$(
        $(#[$attr:meta])*
        impl[$($args:tt)*] CanonicalRecordData for $subject:ty;
    )*} => {$(
        $(#[$attr])*
        impl<$($args)*> CanonicalRecordData for $subject {
            fn build_canonical_bytes<'b>(
                &self,
                bytes: &'b mut [u8],
            ) -> Result<&'b mut [u8], TruncationError> {
                (**self).build_canonical_bytes(bytes)
            }

            fn cmp_canonical(&self, other: &Self) -> Ordering {
                (**self).cmp_canonical(&**other)
            }
        }
    )*};
}

impl_canonical_record_data_for_deref! {
    impl[T: ?Sized + CanonicalRecordData] CanonicalRecordData for &T;
    impl[T: ?Sized + CanonicalRecordData] CanonicalRecordData for &mut T;

    #[cfg(feature = "alloc")]
    impl[T: ?Sized + CanonicalRecordData] CanonicalRecordData for alloc::boxed::Box<T>;
    #[cfg(feature = "alloc")]
    impl[T: ?Sized + CanonicalRecordData] CanonicalRecordData for alloc::rc::Rc<T>;
    #[cfg(feature = "alloc")]
    impl[T: ?Sized + CanonicalRecordData] CanonicalRecordData for alloc::sync::Arc<T>;
}

//----------- UnparsedRecordData ---------------------------------------------

/// Unparsed DNS record data.
#[derive(AsBytes, BuildBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct UnparsedRecordData([u8]);

//--- Construction

impl UnparsedRecordData {
    /// Assume a byte sequence is a valid [`UnparsedRecordData`].
    ///
    /// # Safety
    ///
    /// The byte sequence must be 65,535 bytes or shorter.
    pub const unsafe fn new_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'UnparsedRecordData' is 'repr(transparent)' to '[u8]', so
        // casting a '[u8]' into an 'UnparsedRecordData' is sound.
        unsafe { core::mem::transmute(bytes) }
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a UnparsedRecordData {}

impl<'a> ParseRecordDataBytes<'a> for &'a UnparsedRecordData {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        _rtype: RType,
    ) -> Result<Self, ParseError> {
        if bytes.len() > 65535 {
            // Too big to fit in an 'UnparsedRecordData'.
            return Err(ParseError);
        }

        // SAFETY: 'bytes.len()' fits within a 'u16'.
        Ok(unsafe { UnparsedRecordData::new_unchecked(bytes) })
    }
}

//--- Building into DNS messages

impl BuildInMessage for UnparsedRecordData {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let end = start + self.0.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(&self.0);
        Ok(end)
    }
}

//--- Access to the underlying bytes

impl Deref for UnparsedRecordData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<[u8]> for UnparsedRecordData {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl AsRef<[u8]> for UnparsedRecordData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<UnparsedRecordData> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//
// --- Functions to make it easier to transition from old base.
// These functions should be marked as deprecated when most of the initial
// migration to new base has completed.
impl<'a, N> Record<N, RecordData<'a, N>> {
    /// Constructor that is more compatible with old base that takes
    /// RecordData.
    pub fn old_new(
        rname: N,
        rclass: RClass,
        ttl: TTL,
        rdata: RecordData<'a, N>,
    ) -> Self {
        Self::new(rname, rdata.rtype(), rclass, ttl, rdata)
    }
}

impl<N> Record<N, BoxedRecordData> {
    /// Constructor that is more compatible with old base that takes
    /// BoxedRecordData.
    pub fn old_new_box(
        rname: N,
        rclass: RClass,
        ttl: TTL,
        rdata: BoxedRecordData,
    ) -> Self {
        Self::new(rname, rdata.rtype(), rclass, ttl, rdata)
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "alloc")]
    use alloc::format;

    use super::{RClass, RType, Record, TTL, UnparsedRecordData};

    use crate::new::base::{
        name::Name,
        wire::{AsBytes, BuildBytes, ParseBytes, SplitBytes},
    };

    #[test]
    fn parse_build() {
        type Subject<'a> = Record<&'a Name, &'a UnparsedRecordData>;

        let bytes =
            b"\x03com\x00\x00\x01\x00\x01\x00\x00\x00\x2A\x00\x00\x54";
        let (record, rest) = Subject::split_bytes(bytes).unwrap();
        assert_eq!(record.rname.as_bytes(), b"\x03com\x00");
        assert_eq!(record.rtype, RType::A);
        assert_eq!(record.rclass, RClass::IN);
        assert_eq!(record.ttl, TTL::from(42));
        assert_eq!(record.rdata.as_bytes(), b"");
        assert_eq!(rest, b"\x54");

        assert!(Subject::parse_bytes(bytes).is_err());
        assert!(Subject::parse_bytes(&bytes[..15]).is_ok());

        let mut buffer = [0u8; 15];
        assert_eq!(record.build_bytes(&mut buffer), Ok(&mut [] as &mut [u8]));
        assert_eq!(buffer, &bytes[..15]);
    }

    #[test]
    fn test_rclass_from() {
        let rclass: RClass = 1.into();
        assert_eq!(rclass, RClass::IN);

        let number: u16 = rclass.into();
        assert_eq!(number, 1);
    }

    #[test]
    fn test_rtype_from() {
        let rtype: RType = 6.into();
        assert_eq!(rtype, RType::SOA);

        let number: u16 = rtype.into();
        assert_eq!(number, 6);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_rclass_display() {
        assert_eq!("IN", format!("{}", RClass::IN));
        assert_eq!("CH", format!("{}", RClass::CH));
        assert_eq!("CLASS42", format!("{}", RClass::from(42)));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_rtype_display() {
        assert_eq!("A", format!("{}", RType::A));
        assert_eq!("MX", format!("{}", RType::MX));
        assert_eq!("TYPE265", format!("{}", RType::from(265)));
    }
}
