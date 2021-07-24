//! Record data from [RFC 5155]: NSEC3 and NSEC3PARAM records.
//!
//! This RFC defines the NSEC3 and NSEC3PARAM resource records.
//!
//! [RFC 5155]: https://tools.ietf.org/html/rfc5155

use super::rfc4034::RtypeBitmap;
use crate::base::charstr::CharStr;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Nsec3HashAlg, Rtype};
use crate::base::octets::{
    Compose, OctetsBuilder, OctetsFrom, OctetsRef, Parse, ParseError, Parser,
    ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
#[cfg(feature = "scan")]
use crate::scan::{RdataError, Scan, Scanner};
use crate::utils::base32;
#[cfg(feature = "scan")]
use bytes::Bytes;
use core::cmp::Ordering;
use core::{fmt, hash};

//------------ Nsec3 ---------------------------------------------------------

#[derive(Clone)]
pub struct Nsec3<Octets> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: CharStr<Octets>,
    next_owner: CharStr<Octets>,
    types: RtypeBitmap<Octets>,
}

impl<Octets> Nsec3<Octets> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: CharStr<Octets>,
        next_owner: CharStr<Octets>,
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

    pub fn salt(&self) -> &CharStr<Octets> {
        &self.salt
    }

    pub fn next_owner(&self) -> &CharStr<Octets> {
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
            CharStr::octets_from(source.salt)?,
            CharStr::octets_from(source.next_owner)?,
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
        let salt = CharStr::parse(parser)?;
        let next_owner = CharStr::parse(parser)?;
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
        CharStr::skip(parser)?;
        RtypeBitmap::skip(parser)?;
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3<Octets> {
    fn compose<T: OctetsBuilder>(
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

#[cfg(feature = "scan")]
impl Scan for Nsec3<Bytes> {
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            scan_salt(scanner)?,
            scan_hash(scanner)?,
            RtypeBitmap::scan(scanner)?,
        ))
    }
}

#[cfg(feature = "scan")]
fn scan_salt<S: Scanner>(scanner: &mut S) -> Result<CharStr<Bytes>, S::Err> {
    if let Ok(()) = scanner.skip_literal("-") {
        Ok(CharStr::empty())
    } else {
        CharStr::scan_hex(scanner)
    }
}

#[cfg(feature = "scan")]
fn scan_hash<S: Scanner>(scanner: &mut S) -> Result<CharStr<Bytes>, S::Err> {
    scanner.scan_base32hex_phrase(|bytes| {
        CharStr::from_bytes(bytes).map_err(RdataError::content)
    })
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:X} ",
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

//------------ Nsec3param ----------------------------------------------------

#[derive(Clone)]
pub struct Nsec3param<Octets> {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: CharStr<Octets>,
}

impl<Octets> Nsec3param<Octets> {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: CharStr<Octets>,
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

    pub fn salt(&self) -> &CharStr<Octets> {
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
            CharStr::octets_from(source.salt)?,
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
            CharStr::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance(4)?;
        CharStr::skip(parser)
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3param<Octets> {
    fn compose<T: OctetsBuilder>(
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

#[cfg(feature = "scan")]
impl Scan for Nsec3param<Bytes> {
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Err> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            scan_salt(scanner)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3param<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {:X}",
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
