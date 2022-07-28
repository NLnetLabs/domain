//! Record data from [RFC 5155]: NSEC3 and NSEC3PARAM records.
//!
//! This RFC defines the NSEC3 and NSEC3PARAM resource records.
//!
//! [RFC 5155]: https://tools.ietf.org/html/rfc5155

use super::rfc4034::RtypeBitmap;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Nsec3HashAlg, Rtype};
use crate::base::octets::{
    Compose, EmptyBuilder, FromBuilder, OctetsBuilder, OctetsFrom, OctetsRef,
    Parse, ParseError, Parser, ShortBuf,
};
#[cfg(feature = "serde")]
use crate::base::octets::{DeserializeOctets, SerializeOctets};
use crate::base::rdata::RtypeRecordData;
use crate::base::scan::{
    ConvertSymbols, EntrySymbol, Scan, Scanner, ScannerError
};
#[cfg(feature = "master")]
use crate::master::scan::{self as old_scan, CharSource, ScanError};
use crate::utils::{base16, base32};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::cmp::Ordering;
use core::{fmt, hash, ops, str};

//------------ Nsec3 ---------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octets: crate::base::octets::SerializeOctets + AsRef<[u8]>,
        ",
        deserialize = "
            Octets: FromBuilder + crate::base::octets::DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder
                + AsRef<[u8]> + AsMut<[u8]>,
        ",
    ))
)]
pub struct Nsec3<Octets> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: Nsec3Salt<Octets>,
    next_owner: OwnerHash<Octets>,
    types: RtypeBitmap<Octets>,
}

impl<Octets> Nsec3<Octets> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: Nsec3Salt<Octets>,
        next_owner: OwnerHash<Octets>,
        types: RtypeBitmap<Octets>,
    ) -> Self {
        Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_owner,
            types,
        }
    }

    pub fn hash_algorithm(&self) -> Nsec3HashAlg {
        self.hash_algorithm
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn opt_out(&self) -> bool {
        self.flags & 0x01 != 0
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &Nsec3Salt<Octets> {
        &self.salt
    }

    pub fn next_owner(&self) -> &OwnerHash<Octets> {
        &self.next_owner
    }

    pub fn types(&self) -> &RtypeBitmap<Octets> {
        &self.types
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Nsec3<SrcOctets>> for Nsec3<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Nsec3<SrcOctets>) -> Result<Self, ShortBuf> {
        Ok(Nsec3::new(
            source.hash_algorithm,
            source.flags,
            source.iterations,
            Nsec3Salt::octets_from(source.salt)?,
            OwnerHash::octets_from(source.next_owner)?,
            RtypeBitmap::octets_from(source.types)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Nsec3<Other>> for Nsec3<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Nsec3<Other>) -> bool {
        self.hash_algorithm == other.hash_algorithm
            && self.flags == other.flags
            && self.iterations == other.iterations
            && self.salt == other.salt
            && self.next_owner == other.next_owner
            && self.types == other.types
    }
}

impl<Octets: AsRef<[u8]>> Eq for Nsec3<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Nsec3<Other>> for Nsec3<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Nsec3<Other>) -> Option<Ordering> {
        match self.hash_algorithm.partial_cmp(&other.hash_algorithm) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.iterations.partial_cmp(&other.iterations) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.salt.partial_cmp(&other.salt) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.next_owner.partial_cmp(&other.next_owner) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.types.partial_cmp(&other.types)
    }
}

impl<Octets, Other> CanonicalOrd<Nsec3<Other>> for Nsec3<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Nsec3<Other>) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.salt.canonical_cmp(&other.salt) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.next_owner.canonical_cmp(&other.next_owner) {
            Ordering::Equal => {}
            other => return other,
        }
        self.types.canonical_cmp(&other.types)
    }
}

impl<Octets: AsRef<[u8]>> Ord for Nsec3<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Nsec3<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash_algorithm.hash(state);
        self.flags.hash(state);
        self.iterations.hash(state);
        self.salt.hash(state);
        self.next_owner.hash(state);
        self.types.hash(state);
    }
}

//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Nsec3<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let hash_algorithm = Nsec3HashAlg::parse(parser)?;
        let flags = u8::parse(parser)?;
        let iterations = u16::parse(parser)?;
        let salt = Nsec3Salt::parse(parser)?;
        let next_owner = OwnerHash::parse(parser)?;
        let types = RtypeBitmap::parse(parser)?;
        Ok(Self::new(
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_owner,
            types,
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        Nsec3HashAlg::skip(parser)?;
        u8::skip(parser)?;
        u16::skip(parser)?;
        Nsec3Salt::skip(parser)?;
        OwnerHash::skip(parser)?;
        RtypeBitmap::skip(parser)?;
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.hash_algorithm.compose(buf)?;
            self.flags.compose(buf)?;
            self.iterations.compose(buf)?;
            self.salt.compose(buf)?;
            self.next_owner.compose(buf)?;
            self.types.compose(buf)
        })
    }
}

//--- Scan, Display, and Debug

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Nsec3<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            Nsec3Salt::scan(scanner)?,
            OwnerHash::scan(scanner)?,
            RtypeBitmap::scan(scanner)?,
        ))
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for Nsec3<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            <Nsec3HashAlg as old_scan::Scan>::scan(scanner)?,
            <u8 as old_scan::Scan>::scan(scanner)?,
            <u16 as old_scan::Scan>::scan(scanner)?,
            <Nsec3Salt<_> as old_scan::Scan>::scan(scanner)?,
            <OwnerHash<_> as old_scan::Scan>::scan(scanner)?,
            <RtypeBitmap<_> as old_scan::Scan>::scan(scanner)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} ",
            self.hash_algorithm, self.flags, self.iterations, self.salt
        )?;
        base32::display_hex(&self.next_owner, f)?;
        write!(f, " {}", self.types)
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for Nsec3<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Nsec3")
            .field("hash_algorithm", &self.hash_algorithm)
            .field("flags", &self.flags)
            .field("iterations", &self.iterations)
            .field("salt", &self.salt)
            .field("next_owner", &self.next_owner)
            .field("types", &self.types)
            .finish()
    }
}

//--- RtypeRecordData

impl<Octets> RtypeRecordData for Nsec3<Octets> {
    const RTYPE: Rtype = Rtype::Nsec3;
}

//------------ Nsec3Param ----------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octets: crate::base::octets::SerializeOctets + AsRef<[u8]>,
        ",
        deserialize = "
            Octets: FromBuilder + crate::base::octets::DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        ",
    ))
)]
pub struct Nsec3param<Octets> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: Nsec3Salt<Octets>,
}

impl<Octets> Nsec3param<Octets> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: Nsec3Salt<Octets>,
    ) -> Self {
        Nsec3param {
            hash_algorithm,
            flags,
            iterations,
            salt,
        }
    }

    pub fn hash_algorithm(&self) -> Nsec3HashAlg {
        self.hash_algorithm
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &Nsec3Salt<Octets> {
        &self.salt
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Nsec3param<SrcOctets>>
    for Nsec3param<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Nsec3param<SrcOctets>) -> Result<Self, ShortBuf> {
        Ok(Nsec3param::new(
            source.hash_algorithm,
            source.flags,
            source.iterations,
            Nsec3Salt::octets_from(source.salt)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Nsec3param<Other>> for Nsec3param<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Nsec3param<Other>) -> bool {
        self.hash_algorithm == other.hash_algorithm
            && self.flags == other.flags
            && self.iterations == other.iterations
            && self.salt == other.salt
    }
}

impl<Octets: AsRef<[u8]>> Eq for Nsec3param<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Nsec3param<Other>> for Nsec3param<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Nsec3param<Other>) -> Option<Ordering> {
        match self.hash_algorithm.partial_cmp(&other.hash_algorithm) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.iterations.partial_cmp(&other.iterations) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.salt.partial_cmp(&other.salt)
    }
}

impl<Octets, Other> CanonicalOrd<Nsec3param<Other>> for Nsec3param<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Nsec3param<Other>) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => {}
            other => return other,
        }
        self.salt.canonical_cmp(&other.salt)
    }
}

impl<Octets: AsRef<[u8]>> Ord for Nsec3param<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => {}
            other => return other,
        }
        self.salt.cmp(&other.salt)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Nsec3param<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash_algorithm.hash(state);
        self.flags.hash(state);
        self.iterations.hash(state);
        self.salt.hash(state);
    }
}

//--- Parse, ParseAll, and Compose

impl<Ref: OctetsRef> Parse<Ref> for Nsec3param<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(
            Nsec3HashAlg::parse(parser)?,
            u8::parse(parser)?,
            u16::parse(parser)?,
            Nsec3Salt::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance(4)?;
        Nsec3Salt::skip(parser)
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3param<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.hash_algorithm.compose(buf)?;
            self.flags.compose(buf)?;
            self.iterations.compose(buf)?;
            self.salt.compose(buf)
        })
    }
}

//--- Scan, Display, and Debug

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Nsec3param<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            Nsec3Salt::scan(scanner)?,
        ))
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for Nsec3param<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            <Nsec3HashAlg as old_scan::Scan>::scan(scanner)?,
            <u8 as old_scan::Scan>::scan(scanner)?,
            <u16 as old_scan::Scan>::scan(scanner)?,
            <Nsec3Salt<_> as old_scan::Scan>::scan(scanner)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3param<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.hash_algorithm, self.flags, self.iterations, self.salt
        )
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for Nsec3param<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Nsec3param")
            .field("hash_algorithm", &self.hash_algorithm)
            .field("flags", &self.flags)
            .field("iterations", &self.iterations)
            .field("salt", &self.salt)
            .finish()
    }
}

//--- RtypeRecordData

impl<Octets> RtypeRecordData for Nsec3param<Octets> {
    const RTYPE: Rtype = Rtype::Nsec3param;
}

//------------ Nsec3Salt -----------------------------------------------------

/// The salt value of an NSEC3 record.
///
/// The salt can never be longer than 255 octets since its length is encoded
/// as a single octet.
///
/// The salt uses Base 16 (i.e., hex digits) as its representation format with
/// no whitespace allowed.
#[derive(Clone)]
pub struct Nsec3Salt<Octets: ?Sized>(Octets);

impl<Octets: ?Sized> Nsec3Salt<Octets> {
    /// Creates an empty salt value.
    pub fn empty() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        Self(b"".as_ref().into())
    }

    /// Crates a new salt value from the given octets.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octets) -> Result<Self, Nsec3SaltError>
    where
        Octets: AsRef<[u8]> + Sized,
    {
        if octets.as_ref().len() > 255 {
            Err(Nsec3SaltError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a salt value from octets without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_octets_unchecked(octets: Octets) -> Self
    where
        Octets: Sized,
    {
        Self(octets)
    }

    /// Converts the salt value into the underlying octets.
    pub fn into_octets(self) -> Octets
    where
        Octets: Sized,
    {
        self.0
    }

    /// Returns a reference to a slice of the salt.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }
}

#[cfg(feature = "bytes")]
#[cfg_attr(docsrs, doc(cfg(feature = "bytes")))]
impl Nsec3Salt<Bytes> {
    /// Creates a new salt from a bytes value.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, Nsec3SaltError> {
        Self::from_octets(bytes)
    }
}

impl Nsec3Salt<[u8]> {
    /// Creates a new salt value from an octet slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, Nsec3SaltError> {
        if slice.len() > 255 {
            Err(Nsec3SaltError)
        } else {
            Ok(unsafe { &*(slice as *const [u8] as *const Nsec3Salt<[u8]>) })
        }
    }
}

//--- OctetsFrom and FromStr

impl<Octets, SrcOctets> OctetsFrom<Nsec3Salt<SrcOctets>> for Nsec3Salt<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Nsec3Salt<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Octets> str::FromStr for Nsec3Salt<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    type Err = base16::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(unsafe {
                Self::from_octets_unchecked(Octets::Builder::empty().freeze())
            })
        } else {
            base16::decode(s)
                .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
        }
    }
}

//--- Deref and AsRef

impl<Octets: ?Sized> ops::Deref for Nsec3Salt<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Octets: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for Nsec3Salt<Octets> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

//--- PartialEq and Eq

impl<T, U> PartialEq<U> for Nsec3Salt<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &U) -> bool {
        self.as_slice().eq(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Eq for Nsec3Salt<T> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<T, U> PartialOrd<U> for Nsec3Salt<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &U) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Ord for Nsec3Salt<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.as_ref())
    }
}

impl<T, U> CanonicalOrd<Nsec3Salt<U>> for Nsec3Salt<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &Nsec3Salt<U>) -> Ordering {
        match self.0.as_ref().len().cmp(&other.0.as_ref().len()) {
            Ordering::Equal => {}
            other => return other,
        }
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<T: AsRef<[u8]> + ?Sized> hash::Hash for Nsec3Salt<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Nsec3Salt<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let len = parser.parse_u8()? as usize;
        parser.advance(len)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Compose for Nsec3Salt<Octets> {
    fn compose<Target: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut Target,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.as_ref().len() as u8).compose(target)?;
            target.append_slice(self.as_ref())
        })
    }
}

//--- Scan and Display

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Nsec3Salt<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        #[derive(Default)]
        struct Converter(Option<Option<base16::SymbolConverter>>);

        impl<Sym, Error> ConvertSymbols<Sym, Error> for Converter
        where
            Sym: Into<EntrySymbol>,
            Error: ScannerError,
        {
            fn process_symbol(
                &mut self, symbol: Sym,
            ) -> Result<Option<&[u8]>, Error> {
                let symbol = symbol.into();
                // If we are none, this is the first symbol. A '-' means
                // empty. Anything else means Base 16.
                if self.0.is_none() {
                    match symbol {
                        EntrySymbol::Symbol(symbol)
                            if symbol.into_char() == Ok('-')
                        => {
                            self.0 = Some(None);
                            return Ok(None)
                        }
                        _ => {
                            self.0 = Some(Some(
                                base16::SymbolConverter::new()
                            ));
                        }
                    }
                }

                match self.0.as_mut() {
                    None => unreachable!(),
                    Some(None) => {
                        Err(Error::custom("illegal NSEC3 salt"))
                    }
                    Some(Some(ref mut base16)) => {
                        base16.process_symbol(symbol)
                    }
                }
            }

            fn process_tail(&mut self) -> Result<Option<&[u8]>, Error> {
                if let Some(Some(ref mut base16)) = self.0 {
                    <base16::SymbolConverter
                        as ConvertSymbols<Sym, Error>
                    >::process_tail(base16)
                }
                else {
                    Ok(None)
                }
            }
        }

        scanner.convert_token(Converter::default()).map(|res| {
            unsafe { Self::from_octets_unchecked(res) } 
        })
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for Nsec3Salt<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        if let Ok(()) = scanner.skip_literal("-") {
            Ok(Self::empty())
        } else {
            scanner.scan_hex_word(|b| unsafe {
                Ok(Self::from_octets_unchecked(b))
            })
        }
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display for Nsec3Salt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.as_slice(), f)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Debug for Nsec3Salt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Nsec3Salt")
            .field(&format_args!("{}", self))
            .finish()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<T: AsRef<[u8]> + SerializeOctets> serde::Serialize for Nsec3Salt<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "Nsec3Salt",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "Nsec3Salt",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for Nsec3Salt<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = Nsec3Salt<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an NSEC3 salt value")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                Nsec3Salt::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    Nsec3Salt::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    Nsec3Salt::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = Nsec3Salt<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an NSEC3 salt value")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "Nsec3Salt",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ OwnerHash -----------------------------------------------------

/// The hash over the next owner name.
///
/// This hash is used instead of the actual owner name in an NSEC3 record.
///
/// The hash can never be longer than 255 octets since its lenght is encoded
/// as a single octet.
///
/// For its presentation format, the hash uses an unpadded Base 32 encoding
/// with no whitespace allowed.
#[derive(Clone)]
pub struct OwnerHash<Octets: ?Sized>(Octets);

impl<Octets: ?Sized> OwnerHash<Octets> {
    /// Creates a new owner hash from the given octets.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octets) -> Result<Self, OwnerHashError>
    where
        Octets: AsRef<[u8]> + Sized,
    {
        if octets.as_ref().len() > 255 {
            Err(OwnerHashError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates an owner hash from octets without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_octets_unchecked(octets: Octets) -> Self
    where
        Octets: Sized,
    {
        Self(octets)
    }

    /// Converts the hash into the underlying octets.
    pub fn into_octets(self) -> Octets
    where
        Octets: Sized,
    {
        self.0
    }

    /// Returns a reference to a slice of the hash.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }
}

#[cfg(feature = "bytes")]
#[cfg_attr(docsrs, doc(cfg(feature = "bytes")))]
impl OwnerHash<Bytes> {
    /// Creates a new owner hash from a bytes value.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, OwnerHashError> {
        Self::from_octets(bytes)
    }
}

impl OwnerHash<[u8]> {
    /// Creates a new owner hash from an octet slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, OwnerHashError> {
        if slice.len() > 255 {
            Err(OwnerHashError)
        } else {
            Ok(unsafe { &*(slice as *const [u8] as *const OwnerHash<[u8]>) })
        }
    }
}

//--- OctetsFrom and FromStr

impl<Octets, SrcOctets> OctetsFrom<OwnerHash<SrcOctets>> for OwnerHash<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: OwnerHash<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Octets> str::FromStr for OwnerHash<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    type Err = base32::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        base32::decode_hex(s)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- Deref and AsRef

impl<Octets: ?Sized> ops::Deref for OwnerHash<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Octets: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for OwnerHash<Octets> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

//--- PartialEq and Eq

impl<T, U> PartialEq<U> for OwnerHash<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &U) -> bool {
        self.as_slice().eq(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Eq for OwnerHash<T> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<T, U> PartialOrd<U> for OwnerHash<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &U) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Ord for OwnerHash<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.as_ref())
    }
}

impl<T, U> CanonicalOrd<OwnerHash<U>> for OwnerHash<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &OwnerHash<U>) -> Ordering {
        match self.0.as_ref().len().cmp(&other.0.as_ref().len()) {
            Ordering::Equal => {}
            other => return other,
        }
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<T: AsRef<[u8]> + ?Sized> hash::Hash for OwnerHash<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for OwnerHash<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let len = parser.parse_u8()? as usize;
        parser.advance(len)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Compose for OwnerHash<Octets> {
    fn compose<Target: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut Target,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.as_ref().len() as u8).compose(target)?;
            target.append_slice(self.as_ref())
        })
    }
}

//--- Scan and Display

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for OwnerHash<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        scanner.convert_token(
            base32::SymbolConverter::new()
        ).map(|octets| {
            unsafe { Self::from_octets_unchecked(octets) }
        })
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for OwnerHash<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        scanner.scan_base32hex_phrase(|b| unsafe {
            Ok(Self::from_octets_unchecked(b))
        })
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display for OwnerHash<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base32::display_hex(self.as_slice(), f)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Debug for OwnerHash<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("OwnerHash")
            .field(&format_args!("{}", self))
            .finish()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<T: AsRef<[u8]> + SerializeOctets> serde::Serialize for OwnerHash<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "OwnerHash",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "OwnerHash",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for OwnerHash<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = OwnerHash<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an owner name hash value")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                OwnerHash::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    OwnerHash::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    OwnerHash::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = OwnerHash<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an owner name hash value")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "OwnerHash",
            NewtypeVisitor(PhantomData),
        )
    }
}

//============ Error Types ===================================================

//------------ Nsec3SaltError ------------------------------------------------

/// A byte sequence does not represent a valid NSEC3 salt.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Nsec3SaltError;

impl fmt::Display for Nsec3SaltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("illegal NSEC3 salt")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Nsec3SaltError {}

//------------ OwnerHashError ------------------------------------------------

/// A byte sequence does not represent a valid owner hash.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerHashError;

impl fmt::Display for OwnerHashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("illegal owner name hash")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OwnerHashError {}
