//! Record data from [RFC 5155].
//!
//! This RFC defines the NSEC3 and NSEC3PARAM resource records.
//!
//! [RFC 5155]: https://tools.ietf.org/html/rfc5155

use std::{error, fmt};
use bytes::BufMut;
use crate::charstr::CharStr;
use crate::compose::{Compose, Compress, Compressor};
use crate::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use crate::iana::{Nsec3HashAlg, Rtype};
use crate::master::scan::{CharSource, Scan, Scanner, ScanError, SyntaxError};
use crate::record::RtypeRecordData;
use crate::utils::base32;
use super::rfc4034::{RtypeBitmap, RtypeBitmapError};


//------------ Nsec3 ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsec3 {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: CharStr,
    next_owner: CharStr,
    types: RtypeBitmap,
}

impl Nsec3 {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: CharStr,
        next_owner: CharStr,
        types: RtypeBitmap
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

    pub fn salt(&self) -> &CharStr {
        &self.salt
    }

    pub fn next_owner(&self) -> &CharStr {
        &self.next_owner
    }

    pub fn types(&self) -> &RtypeBitmap {
        &self.types
    }
}


//--- ParseAll, Compose, Compress

impl ParseAll for Nsec3 {
    type Err = ParseNsec3Error;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
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

impl Compose for Nsec3 {
    fn compose_len(&self) -> usize {
        4 + self.salt.compose_len() + self.next_owner.compose_len() +
            self.types.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.hash_algorithm.compose(buf);
        self.flags.compose(buf);
        self.iterations.compose(buf);
        self.salt.compose(buf);
        self.next_owner.compose(buf);
        self.types.compose(buf);
    }
}

impl Compress for Nsec3 {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//------------ Scan and Display ----------------------------------------------

impl Scan for Nsec3 {
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

fn scan_salt<C: CharSource>(
    scanner: &mut Scanner<C>
) -> Result<CharStr, ScanError> {
    if let Ok(()) = scanner.skip_literal("-") {    
        Ok(CharStr::empty())
    }
    else {
        CharStr::scan_hex(scanner)
    }
}

fn scan_hash<C: CharSource>(
    scanner: &mut Scanner<C>
) -> Result<CharStr, ScanError> {
    scanner.scan_base32hex_phrase(|bytes| {
        CharStr::from_bytes(bytes).map_err(SyntaxError::content)
    })
}

impl fmt::Display for Nsec3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_algorithm, self.flags,
               self.iterations)?;
        self.salt.display_hex(f)?;
        base32::display_hex(&self.next_owner, f)?;
        write!(f, " {}", self.types)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Nsec3 {
    const RTYPE: Rtype = Rtype::Nsec3;
}


//------------ Nsec3param ----------------------------------------------------


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsec3param {
    hash_algorithm: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: CharStr,
}

impl Nsec3param {
    pub fn new(
        hash_algorithm: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: CharStr
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

    pub fn salt(&self) -> &CharStr {
        &self.salt
    }
}


//--- Parse, ParseAll, Compose, Compres

impl Parse for Nsec3param {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(
            Nsec3HashAlg::parse(parser)?,
            u8::parse(parser)?,
            u16::parse(parser)?,
            CharStr::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        parser.advance(4)?;
        CharStr::skip(parser)
    }
}

impl ParseAll for Nsec3param {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
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

impl Compose for Nsec3param {
    fn compose_len(&self) -> usize {
        4 + self.salt.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.hash_algorithm.compose(buf);
        self.flags.compose(buf);
        self.iterations.compose(buf);
        self.salt.compose(buf);
    }
}

impl Compress for Nsec3param {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Nsec3param {
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

impl fmt::Display for Nsec3param {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.hash_algorithm, self.flags,
               self.iterations)?;
        self.salt.display_hex(f)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Nsec3param {
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

impl error::Error for ParseNsec3Error { }

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


//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Nsec3, Nsec3param};
}

