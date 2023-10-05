//! Record data from [RFC 5155]: NSEC3 and NSEC3PARAM records.
//!
//! This RFC defines the NSEC3 and NSEC3PARAM resource records.
//!
//! [RFC 5155]: https://tools.ietf.org/html/rfc5155

use super::dnssec::RtypeBitmap;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Nsec3HashAlg, Rtype};
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use crate::base::scan::{
    ConvertSymbols, EntrySymbol, Scan, Scanner, ScannerError,
};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use crate::utils::{base16, base32};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::cmp::Ordering;
use core::{fmt, hash, str};
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder,
};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};

//------------ Nsec3 ---------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>,
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                EmptyBuilder + octseq::builder::Truncate
                + AsRef<[u8]> + AsMut<[u8]>,
        ",
    ))
)]
pub struct Nsec3<Octs> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: Nsec3Salt<Octs>,
    next_owner: OwnerHash<Octs>,
    types: RtypeBitmap<Octs>,
}

impl<Octs> Nsec3<Octs> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: Nsec3Salt<Octs>,
        next_owner: OwnerHash<Octs>,
        types: RtypeBitmap<Octs>,
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

    pub fn salt(&self) -> &Nsec3Salt<Octs> {
        &self.salt
    }

    pub fn next_owner(&self) -> &OwnerHash<Octs> {
        &self.next_owner
    }

    pub fn types(&self) -> &RtypeBitmap<Octs> {
        &self.types
    }

    pub(super) fn convert_octets<Target>(
        self,
    ) -> Result<Nsec3<Target>, Target::Error>
    where
        Target: OctetsFrom<Octs>,
    {
        Ok(Nsec3::new(
            self.hash_algorithm,
            self.flags,
            self.iterations,
            self.salt.try_octets_into()?,
            self.next_owner.try_octets_into()?,
            self.types.try_octets_into()?,
        ))
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Nsec3<Target>, Target::Error> {
        self.convert_octets()
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
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

impl<Octs: AsRef<[u8]>> Nsec3<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
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
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Nsec3<SrcOcts>> for Nsec3<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Nsec3<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(Nsec3::new(
            source.hash_algorithm,
            source.flags,
            source.iterations,
            Nsec3Salt::try_octets_from(source.salt)?,
            OwnerHash::try_octets_from(source.next_owner)?,
            RtypeBitmap::try_octets_from(source.types)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Nsec3<Other>> for Nsec3<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs: AsRef<[u8]>> Eq for Nsec3<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Nsec3<Other>> for Nsec3<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs, Other> CanonicalOrd<Nsec3<Other>> for Nsec3<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs: AsRef<[u8]>> Ord for Nsec3<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Nsec3<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash_algorithm.hash(state);
        self.flags.hash(state);
        self.iterations.hash(state);
        self.salt.hash(state);
        self.next_owner.hash(state);
        self.types.hash(state);
    }
}

//--- RecordData

impl<Octs> RecordData for Nsec3<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Nsec3
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Nsec3<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Nsec3 {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Nsec3<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::checked_add(
                Nsec3HashAlg::COMPOSE_LEN
                    + u8::COMPOSE_LEN
                    + u16::COMPOSE_LEN,
                self.salt.compose_len(),
            )
            .expect("long NSEC3")
            .checked_add(self.next_owner.compose_len())
            .expect("long NSEC3")
            .checked_add(self.types.compose_len())
            .expect("long NSEC3"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.hash_algorithm.compose(target)?;
        self.flags.compose(target)?;
        self.iterations.compose(target)?;
        self.salt.compose(target)?;
        self.next_owner.compose(target)?;
        self.types.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display, and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for Nsec3<Octs> {
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

impl<Octs: AsRef<[u8]>> fmt::Debug for Nsec3<Octs> {
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

//------------ Nsec3Param ----------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>,
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        ",
    ))
)]
pub struct Nsec3param<Octs> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: Nsec3Salt<Octs>,
}

impl<Octs> Nsec3param<Octs> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: Nsec3Salt<Octs>,
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

    pub fn salt(&self) -> &Nsec3Salt<Octs> {
        &self.salt
    }

    pub(super) fn convert_octets<Target>(
        self,
    ) -> Result<Nsec3param<Target>, Target::Error>
    where
        Target: OctetsFrom<Octs>,
    {
        Ok(Nsec3param::new(
            self.hash_algorithm,
            self.flags,
            self.iterations,
            self.salt.try_octets_into()?,
        ))
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Nsec3param<Target>, Target::Error> {
        self.convert_octets()
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            Nsec3HashAlg::parse(parser)?,
            u8::parse(parser)?,
            u16::parse(parser)?,
            Nsec3Salt::parse(parser)?,
        ))
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            Nsec3Salt::scan(scanner)?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Nsec3param<SrcOcts>> for Nsec3param<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Nsec3param<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Ok(Nsec3param::new(
            source.hash_algorithm,
            source.flags,
            source.iterations,
            Nsec3Salt::try_octets_from(source.salt)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Nsec3param<Other>> for Nsec3param<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Nsec3param<Other>) -> bool {
        self.hash_algorithm == other.hash_algorithm
            && self.flags == other.flags
            && self.iterations == other.iterations
            && self.salt == other.salt
    }
}

impl<Octs: AsRef<[u8]>> Eq for Nsec3param<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Nsec3param<Other>> for Nsec3param<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs, Other> CanonicalOrd<Nsec3param<Other>> for Nsec3param<Octs>
where
    Octs: AsRef<[u8]>,
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

impl<Octs: AsRef<[u8]>> Ord for Nsec3param<Octs> {
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

impl<Octs: AsRef<[u8]>> hash::Hash for Nsec3param<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.hash_algorithm.hash(state);
        self.flags.hash(state);
        self.iterations.hash(state);
        self.salt.hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Nsec3param<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Nsec3param
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Nsec3param<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Nsec3param {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Nsec3param<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::checked_add(
                Nsec3HashAlg::COMPOSE_LEN
                    + u8::COMPOSE_LEN
                    + u16::COMPOSE_LEN,
                self.salt.compose_len(),
            )
            .expect("long NSEC3"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.hash_algorithm.compose(target)?;
        self.flags.compose(target)?;
        self.iterations.compose(target)?;
        self.salt.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for Nsec3param<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.hash_algorithm, self.flags, self.iterations, self.salt
        )
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for Nsec3param<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Nsec3param")
            .field("hash_algorithm", &self.hash_algorithm)
            .field("flags", &self.flags)
            .field("iterations", &self.iterations)
            .field("salt", &self.salt)
            .finish()
    }
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
pub struct Nsec3Salt<Octs: ?Sized>(Octs);

impl Nsec3Salt<()> {
    /// The salt has a maximum length 255 octets since its length is encoded
    /// as a single octet.
    pub const MAX_LEN: usize = 255;
}

impl<Octs: ?Sized> Nsec3Salt<Octs> {
    /// Creates an empty salt value.
    pub fn empty() -> Self
    where
        Octs: From<&'static [u8]>,
    {
        Self(b"".as_ref().into())
    }

    /// Crates a new salt value from the given octets.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octs) -> Result<Self, Nsec3SaltError>
    where
        Octs: AsRef<[u8]> + Sized,
    {
        if octets.as_ref().len() > Nsec3Salt::MAX_LEN {
            Err(Nsec3SaltError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a salt value from octets without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_octets_unchecked(octets: Octs) -> Self
    where
        Octs: Sized,
    {
        Self(octets)
    }

    /// Converts the salt value into the underlying octets.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.0
    }

    /// Returns a reference to a slice of the salt.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    fn salt_len(&self) -> u8
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref().len().try_into().expect("long salt")
    }

    fn compose_len(&self) -> u16
    where
        Octs: AsRef<[u8]>,
    {
        u16::from(self.salt_len()) + 1
    }

    fn compose<Target: Composer /*OctetsBuilder*/ + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>
    where
        Octs: AsRef<[u8]>,
    {
        self.salt_len().compose(target)?;
        target.append_slice(self.0.as_ref())
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
        if slice.len() > Nsec3Salt::MAX_LEN {
            Err(Nsec3SaltError)
        } else {
            Ok(unsafe { &*(slice as *const [u8] as *const Nsec3Salt<[u8]>) })
        }
    }
}

impl<Octs> Nsec3Salt<Octs> {
    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        #[derive(Default)]
        struct Converter(Option<Option<base16::SymbolConverter>>);

        impl<Sym, Error> ConvertSymbols<Sym, Error> for Converter
        where
            Sym: Into<EntrySymbol>,
            Error: ScannerError,
        {
            fn process_symbol(
                &mut self,
                symbol: Sym,
            ) -> Result<Option<&[u8]>, Error> {
                let symbol = symbol.into();
                // If we are none, this is the first symbol. A '-' means
                // empty. Anything else means Base 16.
                if self.0.is_none() {
                    match symbol {
                        EntrySymbol::Symbol(symbol)
                            if symbol.into_char() == Ok('-') =>
                        {
                            self.0 = Some(None);
                            return Ok(None);
                        }
                        _ => {
                            self.0 =
                                Some(Some(base16::SymbolConverter::new()));
                        }
                    }
                }

                match self.0.as_mut() {
                    None => unreachable!(),
                    Some(None) => Err(Error::custom("illegal NSEC3 salt")),
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
                } else {
                    Ok(None)
                }
            }
        }

        scanner
            .convert_token(Converter::default())
            .map(|res| unsafe { Self::from_octets_unchecked(res) })
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
            .map_err(Into::into)
    }
}

//--- OctetsFrom and FromStr

impl<Octs, SrcOcts> OctetsFrom<Nsec3Salt<SrcOcts>> for Nsec3Salt<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Nsec3Salt<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Octs> str::FromStr for Nsec3Salt<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder,
{
    type Err = base16::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(unsafe {
                Self::from_octets_unchecked(Octs::Builder::empty().freeze())
            })
        } else {
            base16::decode(s)
                .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
        }
    }
}

//--- AsRef

impl<Octs: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for Nsec3Salt<Octs> {
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

//--- Display and Debug

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Nsec3Salt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.as_slice(), f)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Nsec3Salt<Octs> {
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
impl<'de, Octs> serde::Deserialize<'de> for Nsec3Salt<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for InnerVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        {
            type Value = Nsec3Salt<Octs>;

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

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        {
            type Value = Nsec3Salt<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an NSEC3 salt value")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octs::visitor()))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octs::visitor()),
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
pub struct OwnerHash<Octs: ?Sized>(Octs);

impl OwnerHash<()> {
    /// The hash has a maximum length 255 octets since its length is encoded
    /// as a single octet.
    pub const MAX_LEN: usize = 255;
}

impl<Octs> OwnerHash<Octs> {
    /// Creates a new owner hash from the given octets.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octs) -> Result<Self, OwnerHashError>
    where
        Octs: AsRef<[u8]>,
    {
        if octets.as_ref().len() > OwnerHash::MAX_LEN {
            Err(OwnerHashError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates an owner hash from octets without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Self(octets)
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner
            .convert_token(base32::SymbolConverter::new())
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Converts the hash into the underlying octets.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.0
    }
}

impl<Octs: ?Sized> OwnerHash<Octs> {
    /// Returns a reference to a slice of the hash.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    fn hash_len(&self) -> u8
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref().len().try_into().expect("long hash")
    }

    fn compose_len(&self) -> u16
    where
        Octs: AsRef<[u8]>,
    {
        u16::from(self.hash_len()) + 1
    }

    fn compose<Target: Composer /*OctetsBuilder*/ + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>
    where
        Octs: AsRef<[u8]>,
    {
        self.hash_len().compose(target)?;
        target.append_slice(self.0.as_ref())
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
        if slice.len() > OwnerHash::MAX_LEN {
            Err(OwnerHashError)
        } else {
            Ok(unsafe { &*(slice as *const [u8] as *const OwnerHash<[u8]>) })
        }
    }
}

impl<Octs> OwnerHash<Octs> {
    fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
            .map_err(Into::into)
    }
}

//--- OctetsFrom and FromStr

impl<Octs, SrcOcts> OctetsFrom<OwnerHash<SrcOcts>> for OwnerHash<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: OwnerHash<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Octs> str::FromStr for OwnerHash<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
{
    type Err = base32::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        base32::decode_hex(s)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- AsRef

impl<Octs: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for OwnerHash<Octs> {
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

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for OwnerHash<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base32::display_hex(self.as_slice(), f)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for OwnerHash<Octs> {
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
impl<'de, Octs> serde::Deserialize<'de> for OwnerHash<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for InnerVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        {
            type Value = OwnerHash<Octs>;

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

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        {
            type Value = OwnerHash<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an owner name hash value")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octs::visitor()))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octs::visitor()),
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

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::super::dnssec::RtypeBitmapBuilder;
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use std::vec::Vec;

    #[test]
    fn nsec3_compose_parse_scan() {
        let mut rtype = RtypeBitmapBuilder::new_vec();
        rtype.add(Rtype::A).unwrap();
        rtype.add(Rtype::Srv).unwrap();
        let rdata = Nsec3::new(
            Nsec3HashAlg::Sha1,
            10,
            11,
            Nsec3Salt::from_octets(Vec::from("bar")).unwrap(),
            OwnerHash::from_octets(Vec::from("foo")).unwrap(),
            rtype.finalize(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Nsec3::parse(parser));
        test_scan(
            &["1", "10", "11", "626172", "CPNMU", "A", "SRV"],
            Nsec3::scan,
            &rdata,
        );
    }

    #[test]
    fn nsec3param_compose_parse_scan() {
        let rdata = Nsec3param::new(
            Nsec3HashAlg::Sha1,
            10,
            11,
            Nsec3Salt::from_octets(Vec::from("bar")).unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Nsec3param::parse(parser));
        test_scan(&["1", "10", "11", "626172"], Nsec3param::scan, &rdata);
    }
}
