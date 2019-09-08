//! Record data from [RFC 5155].
//!
//! This RFC defines the NSEC3 and NSEC3PARAM resource records.
//!
//! [RFC 5155]: https://tools.ietf.org/html/rfc5155

use core::{fmt, hash};
use core::cmp::Ordering;
#[cfg(feature="bytes")] use bytes::Bytes;
use derive_more::Display;
use crate::charstr::CharStr;
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, ComposeTarget};
use crate::parse::{
    Parse, ParseAll, ParseAllError, Parser, ParseSource, ShortBuf
};
use crate::iana::{Nsec3HashAlg, Rtype};
#[cfg(feature="bytes")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError, SyntaxError
};
use crate::utils::base32;
use super::{RtypeRecordData, RdataParseError};
use super::rfc4034::{RtypeBitmap, RtypeBitmapError};


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
        types: RtypeBitmap<Octets>
    ) -> Self {
        Nsec3 { hash_algorithm, flags, iterations, salt, next_owner, types }
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


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Nsec3<Other>> for Nsec3<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &Nsec3<Other>) -> bool {
        self.hash_algorithm == other.hash_algorithm
        && self.flags == other.flags
        && self.iterations == other.iterations
        && self.salt == other.salt
        && self.next_owner == other.next_owner
        && self.types == other.types
    }
}

impl<Octets: AsRef<[u8]>> Eq for Nsec3<Octets> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Nsec3<Other>> for Nsec3<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Nsec3<Other>) -> Option<Ordering> {
        match self.hash_algorithm.partial_cmp(&other.hash_algorithm) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.iterations.partial_cmp(&other.iterations) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.salt.partial_cmp(&other.salt) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.next_owner.partial_cmp(&other.next_owner) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.types.partial_cmp(&other.types)
    }
}

impl<Octets, Other> CanonicalOrd<Nsec3<Other>> for Nsec3<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &Nsec3<Other>) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => { }
            other => return other
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => { }
            other => return other
        }
        match self.salt.canonical_cmp(&other.salt) {
            Ordering::Equal => { }
            other => return other
        }
        match self.next_owner.canonical_cmp(&other.next_owner) {
            Ordering::Equal => { }
            other => return other
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

impl<Octets: ParseSource> ParseAll<Octets> for Nsec3<Octets> {
    type Err = ParseNsec3Error;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len < 6 {
            return Err(ShortBuf.into())
        }
        let start = parser.pos();
        let hash_algorithm = Nsec3HashAlg::parse(parser)?;
        let flags = u8::parse(parser)?;
        let iterations = u16:: parse(parser)?;
        let salt = CharStr::parse(parser)?;
        let next_owner = CharStr::parse(parser)?;
        let len = if parser.pos() > start + len {
            return Err(ShortBuf.into())
        }
        else {
            len - (parser.pos() - start)
        };
        let types = RtypeBitmap::parse_all(parser, len)?;
        Ok(Self::new(
            hash_algorithm, flags, iterations, salt, next_owner, types
        ))
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3<Octets> {
    fn compose<T: ComposeTarget + ?Sized>(&self, buf: &mut T) {
        self.hash_algorithm.compose(buf);
        self.flags.compose(buf);
        self.iterations.compose(buf);
        self.salt.compose(buf);
        self.next_owner.compose(buf);
        self.types.compose(buf);
    }
}


//--- Scan, Display, and Debug

#[cfg(feature="bytes")]
impl Scan for Nsec3<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            scan_salt(scanner)?,
            scan_hash(scanner)?,
            RtypeBitmap::scan(scanner)?
        ))
    }
}

#[cfg(feature="bytes")]
fn scan_salt<C: CharSource>(
    scanner: &mut Scanner<C>
) -> Result<CharStr<Bytes>, ScanError> {
    if let Ok(()) = scanner.skip_literal("-") {    
        Ok(CharStr::empty())
    }
    else {
        CharStr::scan_hex(scanner)
    }
}

#[cfg(feature="bytes")]
fn scan_hash<C: CharSource>(
    scanner: &mut Scanner<C>
) -> Result<CharStr<Bytes>, ScanError> {
    scanner.scan_base32hex_phrase(|bytes| {
        CharStr::from_bytes(bytes).map_err(SyntaxError::content)
    })
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_algorithm, self.flags,
               self.iterations)?;
        self.salt.display_hex(f)?;
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
        salt: CharStr<Octets>
    ) -> Self {
        Nsec3param { hash_algorithm, flags, iterations, salt } 
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


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Nsec3param<Other>> for Nsec3param<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &Nsec3param<Other>) -> bool {
        self.hash_algorithm == other.hash_algorithm
        && self.flags == other.flags
        && self.iterations == other.iterations
        && self.salt == other.salt
    }
}

impl<Octets: AsRef<[u8]>> Eq for Nsec3param<Octets> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Nsec3param<Other>> for Nsec3param<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Nsec3param<Other>) -> Option<Ordering> {
        match self.hash_algorithm.partial_cmp(&other.hash_algorithm) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.iterations.partial_cmp(&other.iterations) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.salt.partial_cmp(&other.salt)
    }
}

impl<Octets, Other> CanonicalOrd<Nsec3param<Other>> for Nsec3param<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &Nsec3param<Other>) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => { }
            other => return other
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => { }
            other => return other
        }
        self.salt.canonical_cmp(&other.salt)
    }
}

impl<Octets: AsRef<[u8]>> Ord for Nsec3param<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.hash_algorithm.cmp(&other.hash_algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => { }
            other => return other
        }
        match self.iterations.cmp(&other.iterations) {
            Ordering::Equal => { }
            other => return other
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

impl<Octets: ParseSource> Parse<Octets> for Nsec3param<Octets> {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser<Octets>) -> Result<Self, Self::Err> {
        Ok(Self::new(
            Nsec3HashAlg::parse(parser)?,
            u8::parse(parser)?,
            u16::parse(parser)?,
            CharStr::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<Octets>) -> Result<(), Self::Err> {
        parser.advance(4)?;
        CharStr::skip(parser)
    }
}

impl<Octets: ParseSource> ParseAll<Octets> for Nsec3param<Octets> {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len < 5 {
            return Err(ParseAllError::ShortField)
        }
        Ok(Self::new(
            Nsec3HashAlg::parse(parser)?,
            u8::parse(parser)?,
            u16::parse(parser)?,
            CharStr::parse_all(parser, len - 4)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> Compose for Nsec3param<Octets> {
    fn compose<T: ComposeTarget + ?Sized>(&self, buf: &mut T) {
        self.hash_algorithm.compose(buf);
        self.flags.compose(buf);
        self.iterations.compose(buf);
        self.salt.compose(buf);
    }
}


//--- Scan, Display, and Debug

#[cfg(feature="bytes")]
impl Scan for Nsec3param<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            Nsec3HashAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u16::scan(scanner)?,
            scan_salt(scanner)?
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsec3param<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_algorithm, self.flags,
               self.iterations)?;
        self.salt.display_hex(f)
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


//------------ ParseNsec3Error -----------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum ParseNsec3Error {
    #[display(fmt="short field")]
    ShortField,

    #[display(fmt="invalid record type bitmap")]
    BadRtypeBitmap,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNsec3Error { }

impl From<ShortBuf> for ParseNsec3Error {
    fn from(_: ShortBuf) -> Self {
        ParseNsec3Error::ShortField
    }
}

impl From<RtypeBitmapError> for ParseNsec3Error {
    fn from(err: RtypeBitmapError) -> Self {
        match err {
            RtypeBitmapError::ShortBuf => ParseNsec3Error::ShortField,
            RtypeBitmapError::BadRtypeBitmap => ParseNsec3Error::BadRtypeBitmap
        }
    }
}

impl From<ParseNsec3Error> for RdataParseError {
    fn from(err: ParseNsec3Error) -> RdataParseError {
        match err {
            ParseNsec3Error::ShortField => {
                RdataParseError::ParseAllError(
                    ParseAllError::ShortField
                )
            }
            ParseNsec3Error::BadRtypeBitmap => {
                RdataParseError::FormErr("invalid record type bitmap")
            }
        }
    }
}


//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Nsec3, Nsec3param};
}

