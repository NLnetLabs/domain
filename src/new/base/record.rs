//! DNS records.

use core::{borrow::Borrow, cmp::Ordering, fmt, ops::Deref};

use crate::new::base::parse::split_without_compression;
use crate::utils::dst::UnsizedCopy;

#[cfg(feature = "alloc")]
use super::super::rdata::BoxedRecordData;
use super::super::rdata::RecordData;

use super::build::{BuildInMessage, NameCompressor};
use super::parse::{ParseMessageBytes, SplitMessageBytes};
use super::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError, SizePrefixed,
    SplitBytes, SplitBytesZC, TruncationError, U16, U32,
};

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
        let (&rtype, rest) = split_without_compression(contents, rest)?;
        let (&rclass, rest) = split_without_compression(contents, rest)?;
        let (&ttl, rest) = split_without_compression(contents, rest)?;

        // Parse the rdata length and split the input accordingly.
        let (size, rest) = split_without_compression::<&U16>(contents, rest)?;
        let (rdata_start, rest) = (rest, rest + size.get() as usize);
        let contents = contents.get(..rest).ok_or(ParseError)?;
        let rdata = D::parse_record_data(contents, rdata_start, rtype)?;

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
///
/// IANA maintains [the registry][iana-rtype] of assignments for Record Types.
///
/// [iana-rtype]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
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

impl RType {
    /// Create a new [`RType`].
    pub const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

//--- Associated Constants

// [`RType`] implementation using macro. See macro for implementation details.
known_values_define! (
    RType::(pub TYPES, pub MNEMONICS) = [
        /// The type of an [`A`](crate::new::rdata::A) record.
        "A" as A = Self::new(1),

        /// The type of an [`Ns`](crate::new::rdata::Ns) record.
        "NS" as NS = Self::new(2),

        /// The type of a [`CName`](crate::new::rdata::CName) record.
        "CNAME" as CNAME = Self::new(5),

        /// The type of an [`Soa`](crate::new::rdata::Soa) record.
        "SOA" as SOA = Self::new(6),

        /// The type of a [`Ptr`](crate::new::rdata::Ptr) record.
        "PTR" as PTR = Self::new(12),

        /// The type of a [`HInfo`](crate::new::rdata::HInfo) record.
        "HINFO" as HINFO = Self::new(13),

        /// The type of a [`Mx`](crate::new::rdata::Mx) record.
        "MX" as MX = Self::new(15),

        /// The type of a [`Txt`](crate::new::rdata::Txt) record.
        "TXT" as TXT = Self::new(16),

        /// The type of an [`Rp`](crate::new::rdata::Rp) record.
        "RP" as RP = Self::new(17),

        /// The type of an [`Aaaa`](crate::new::rdata::Aaaa) record.
        "AAAA" as AAAA = Self::new(28),

        /// The type of an [`Srv`](crate::new::rdata::Srv) record.
        "SRV" as SRV = Self::new(33),

        /// The type of a [`DName`](crate::new::rdata::DName) record.
        "DNAME" as DNAME = Self::new(39),

        /// The type of an [`Opt`](crate::new::rdata::Opt) record.
        "OPT" as OPT = Self::new(41),

        /// The type of a [`Ds`](crate::new::rdata::Ds) record.
        "DS" as DS = Self::new(43),

        /// The type of an [`Rrsig`](crate::new::rdata::Rrsig) record.
        "RRSIG" as RRSIG = Self::new(46),

        /// The type of an [`Nsec`](crate::new::rdata::Nsec) record.
        "NSEC" as NSEC = Self::new(47),

        /// The type of a [`DNSKey`](crate::new::rdata::DNSKey) record.
        "DNSKEY" as DNSKEY = Self::new(48),

        /// The type of an [`Nsec3`](crate::new::rdata::Nsec3) record.
        "NSEC3" as NSEC3 = Self::new(50),

        /// The type of an [`Nsec3Param`](crate::new::rdata::Nsec3Param) record.
        "NSEC3PARAM" as NSEC3PARAM = Self::new(51),

        /// The type of a `Cds` record.
        "CDS" as CDS = Self::new(59),

        /// The type of a `CDNSKey` record.
        "CDNSKEY" as CDNSKEY = Self::new(60),

        /// The type of a [`ZoneMD`](crate::new::rdata::ZoneMD) record.
        "ZONEMD" as ZONEMD = Self::new(63),

        /// The type of a `TSig` record.
        "TSIG" as TSIG = Self::new(250),
    ];

);

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
    /// - [`SRV`](RType::SRV)
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
                | Self::SRV
                | Self::DNAME
                | Self::RRSIG
        )
    }
}

//--- Conversion to and from 'u16'

known_values_from_and_to_primitive!(RType, u16);

//--- Formatting

/// Format a [`RType`] for debugging.
///
/// The output displays the mnemonic, if known, and the code associated to the
/// [`RType`].
///
/// ```
/// # use domain::new::base::RType;
/// // Known Record Type.
/// assert_eq!(
///     "RType::A(1)",
///     format!("{:?}", RType::A)
/// );
/// // Unknown Record Type.
/// assert_eq!(
///     "RType(42)",
///     format!("{:?}", RType::from(42))
/// );
/// ```
impl fmt::Debug for RType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "RType::{}({})", m, self.code),
            None => write!(f, "RType({})", self.code),
        }
    }
}

/// Format a [`RType`] in a human-readable way.
///
/// Return the mnemonic of [`RType`]. If [`RType`] is unknown, then the
/// returned string contains the type in the unknown format as defined in
/// [Section 5 of RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::RType;
/// // Known Record Type with mnemonic.
/// assert_eq!("A", format!("{}", RType::A));
/// // Unknown Record Type.
/// assert_eq!("TYPE265", format!("{}", RType::from(265)));
/// ```
///
/// [Section 5 of RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
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
///
/// IANA maintains [the registry][iana-rclass] of assignments for Record
/// Classes.
///
/// [iana-rclass]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
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
    pub const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

known_values_define! (
    RClass::(pub CLASSES, pub MNEMONICS) = [
        /// The Internet class.
        "IN" as IN = Self::new(1),
        /// The CHAOS class.
        "CH" as CH = Self::new(3),
    ];
);

//--- Conversion to and from 'u16'

known_values_from_and_to_primitive!(RClass, u16);

//--- Formatting

/// Format a [`RClass`] for debugging.
///
/// The output displays the mnemonic, if known, and the code associated to the
/// [`RClass`].
///
/// ```
/// # use domain::new::base::RClass;
/// // Known Record Class.
/// assert_eq!(
///     "RClass::IN(1)",
///     format!("{:?}", RClass::IN)
/// );
/// // Unknown Record Class.
/// assert_eq!(
///     "RClass(42)",
///     format!("{:?}", RClass::from(42))
/// );
/// ```
impl fmt::Debug for RClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "RClass::{}({})", m, self.code),
            None => write!(f, "RClass({})", self.code),
        }
    }
}

/// Format a [`RClass`] in a human-readable way.
///
/// Return the mnemonic of [`RClass`]. If [`RClass`] is unknown, then the
/// returned string contains the class in the unknown format as defined in
/// [Section 5 of RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::RClass;
/// // Known Record Class with mnemonic.
/// assert_eq!("IN", format!("{}", RClass::IN));
/// // Unknown Record Class.
/// assert_eq!("CLASS42", format!("{}", RClass::from(42)));
/// ```
///
/// [Section 5 of RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
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

#[cfg(feature = "alloc")]
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
    use super::{RClass, RType, Record, TTL, UnparsedRecordData};

    use crate::new::base::{
        QClass, QType,
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

    #[test]
    fn test_rtype_from_mnemonic() {
        assert_eq!(RType::from_mnemonic("A").unwrap(), RType::A);
        assert_eq!(RType::from_mnemonic("MX").unwrap(), RType::MX);
        // Make sure from_mnemonic does NOT parse unknown format.
        assert!(RType::from_mnemonic("TYPE10").is_none());
    }

    #[test]
    fn test_rclass_from_mnemonic() {
        assert_eq!(RClass::from_mnemonic("IN").unwrap(), RClass::IN);
        assert_eq!(RClass::from_mnemonic("CH").unwrap(), RClass::CH);
        // Make sure from_mnemonic does NOT parse unknown format.
        assert!(RClass::from_mnemonic("CLASS10").is_none());
    }

    // Currently `RType` (Record Type) and `QType` (Question Type) are
    // separate. Reason is that the overlap between the two is big but not
    // complete. See IANA definition below.
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    //
    // To prevent drift of the implementation this test confirms the overlap
    // but keeps track of exceptions where there is no overlap.
    #[test]
    fn test_rtype_qtype_sync() {
        // Specify the special cases
        const RTYPE_ONLY: &[RType] = &[];
        const QTYPE_ONLY: &[QType] = &[QType::IXFR, QType::AXFR, QType::ANY];

        let mut rtype: Option<&str>;
        let mut qtype: Option<&str>;

        // Iterate over the entire Type space
        for i in 0..=u16::MAX {
            rtype = RType::from(i).get_mnemonic();
            qtype = QType::from(i).get_mnemonic();
            match (rtype, qtype) {
                // Both implement this type. This should be the most common
                // case. Now make sure the resulting mnemonic is the same.
                (Some(rtype), Some(qtype)) => {
                    assert_eq!(rtype, qtype);
                }
                // Both do not implement this Type. This is ok.
                (None, None) => (),

                // RType does not implement this Type, but QType does. This is
                // _only_ in specific cases ok.
                (None, Some(qtype)) => {
                    // check if the QType is allowed.
                    assert!(
                        QTYPE_ONLY.contains(&i.into()),
                        "Failed for {qtype:?}"
                    );
                }
                // RType does implement this Type, but QType does not. This is
                // _only_ in specific cases ok.
                (Some(rtype), None) => {
                    assert!(
                        RTYPE_ONLY.contains(&i.into()),
                        "Failed for {rtype:?}"
                    );
                }
            }
        }
    }

    // The same (as for QType and RType, see above) applies for RClass and
    // QClass. But currently there are no differences in the defined Classes
    // therefore a quick comparision is enough.
    #[test]
    fn test_rclass_qclass_sync() {
        let mut rclass: Option<&str>;
        let mut qclass: Option<&str>;
        for i in 0..=u16::MAX {
            rclass = RClass::from(i).get_mnemonic();
            qclass = QClass::from(i).get_mnemonic();
            match (rclass, qclass) {
                // Both implement this type. This should be the most common
                // case. Now make sure the resulting mnemonic is the same.
                (Some(rtype), Some(qtype)) => {
                    assert_eq!(rtype, qtype);
                }
                // Both do not implement this Type. This is ok.
                (None, None) => (),
                (None, Some(qclass)) => {
                    panic!("{qclass:?} not correctly implemented for both")
                }
                (Some(rclass), None) => {
                    panic!("{rclass:?} not correctly implemented for both")
                }
            }
        }
    }
}
