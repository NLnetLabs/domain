//! Record data from [RFC 4034].
//!
//! This RFC defines the record types for DNSSEC.
//!
//! [RFC 4034]: https://tools.ietf.org/html/rfc4034

use std::{fmt, ptr};
use bytes::{BufMut, Bytes, BytesMut};
use failure::Fail;
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::name::{Dname, DnameBytesError};
use ::bits::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use ::bits::rdata::RtypeRecordData;
use ::bits::serial::Serial;
use ::iana::{DigestAlg, Rtype, SecAlg};
use ::master::scan::{CharSource, ScanError, Scan, Scanner};
use ::utils::base64;


//------------ Dnskey --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Dnskey {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    public_key: Bytes,
}

impl Dnskey {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Bytes)
    -> Self {
        Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn public_key(&self) -> &Bytes {
        &self.public_key
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Dnskey {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser,
        len: usize,
    ) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ParseAllError::ShortField);
        }
        Ok(Self::new(
            u16::parse(parser)?,
            u8::parse(parser)?,
            SecAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?
        ))
    }
}

impl Compose for Dnskey {
    fn compose_len(&self) -> usize {
        4 + self.public_key.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.flags.compose(buf);
        self.protocol.compose(buf);
        self.algorithm.compose(buf);
        self.public_key.compose(buf);
    }
}

impl Compress for Dnskey {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Dnskey {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?
        ))
    }
}

impl fmt::Display for Dnskey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}


//--- RecordData

impl RtypeRecordData for Dnskey {
    const RTYPE: Rtype = Rtype::Dnskey;
}


//------------ Rrsig ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub struct Rrsig {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: u32,
    expiration: Serial,
    inception: Serial,
    key_tag: u16,
    signer_name: Dname,
    signature: Bytes,
}

impl Rrsig {
    #[allow(too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: u32,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Dname,
        signature: Bytes
    ) -> Self {
        Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature
        }
    }

    pub fn type_covered(&self) -> Rtype {
        self.type_covered
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    pub fn expiration(&self) -> Serial {
        self.expiration
    }

    pub fn inception(&self) -> Serial {
        self.inception
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signer_name(&self) -> &Dname {
        &self.signer_name
    }

    pub fn signature(&self) -> &Bytes {
        &self.signature
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Rrsig {
    type Err = DnameBytesError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let start = parser.pos();
        let type_covered = Rtype::parse(parser)?;
        let algorithm = SecAlg::parse(parser)?;
        let labels = u8::parse(parser)?;
        let original_ttl = u32::parse(parser)?;
        let expiration = Serial::parse(parser)?;
        let inception = Serial::parse(parser)?;
        let key_tag = u16::parse(parser)?;
        let signer_name = Dname::parse(parser)?;
        let len = if parser.pos() > start + len {
            return Err(ShortBuf.into())
        }
        else {
            len - (parser.pos() - start)
        };
        let signature = Bytes::parse_all(parser, len)?;
        Ok(Self::new(
            type_covered, algorithm, labels, original_ttl, expiration,
            inception, key_tag, signer_name, signature
        ))
    }
}

impl Compose for Rrsig {
    fn compose_len(&self) -> usize {
        18 + self.signer_name.compose_len() + self.signature.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.type_covered.compose(buf);
        self.algorithm.compose(buf);
        self.labels.compose(buf);
        self.original_ttl.compose(buf);
        self.expiration.compose(buf);
        self.inception.compose(buf);
        self.key_tag.compose(buf);
        self.signer_name.compose(buf);
        self.signature.compose(buf);
    }
}

impl Compress for Rrsig {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Rrsig {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            Rtype::scan(scanner)?,
            SecAlg::scan(scanner)?,
            u8::scan(scanner)?,
            u32::scan(scanner)?,
            Serial::scan_rrsig(scanner)?,
            Serial::scan_rrsig(scanner)?,
            u16::scan(scanner)?,
            Dname::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?
        ))
    }
}

impl fmt::Display for Rrsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {} {} ",
               self.type_covered, self.algorithm, self.labels,
               self.original_ttl, self.expiration, self.inception,
               self.key_tag, self.signer_name)?;
        base64::display(&self.signature, f)
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Rrsig {
    const RTYPE: Rtype = Rtype::Rrsig;
}


//------------ Nsec ----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsec<N> {
    next_name: N,
    types: RtypeBitmap,
}

impl<N> Nsec<N> {
    pub fn new(next_name: N, types: RtypeBitmap) -> Self {
        Nsec { next_name, types }
    }

    pub fn next_name(&self) -> &N {
        &self.next_name
    }

    pub fn types(&self) -> &RtypeBitmap {
        &self.types
    }
}


//--- ParseAll, Compose, and Compress

impl<N: Parse> ParseAll for Nsec<N>
where <N as Parse>::Err: Fail {
    type Err = ParseNsecError<<N as Parse>::Err>;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let start = parser.pos();
        let next_name = N::parse(parser).map_err(ParseNsecError::BadNextName)?;
        let len = if parser.pos() > start + len {
            return Err(ShortBuf.into())
        }
        else {
            len - (parser.pos() - start)
        };
        let types = RtypeBitmap::parse_all(parser, len)?;
        Ok(Nsec::new(next_name, types))
    }
}

impl<N: Compose> Compose for Nsec<N> {
    fn compose_len(&self) -> usize {
        self.next_name.compose_len() + self.types.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.next_name.compose(buf);
        self.types.compose(buf);
    }
}

impl<N: Compose> Compress for Nsec<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl<N: Scan> Scan for Nsec<N> {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            N::scan(scanner)?,
            RtypeBitmap::scan(scanner)?,
        ))
    }
}

impl<N: fmt::Display> fmt::Display for Nsec<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.next_name, self.types)
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Nsec<N> {
    const RTYPE: Rtype = Rtype::Nsec;
}


//------------ Ds -----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ds {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    digest: Bytes,
}

impl Ds {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Bytes
    ) -> Self {
        Ds { key_tag, algorithm, digest_type, digest }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn digest_type(&self) -> DigestAlg {
        self.digest_type
    }

    pub fn digest(&self) -> &Bytes {
        &self.digest
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Ds {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ShortBuf)
        }
        Ok(Self::new(
            u16::parse(parser)?,
            SecAlg::parse(parser)?,
            DigestAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?
        ))
    }
}

impl Compose for Ds {
    fn compose_len(&self) -> usize {
        self.digest.len() + 4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.key_tag.compose(buf);
        self.algorithm.compose(buf);
        self.digest_type.compose(buf);
        self.digest.compose(buf);
    }
}

impl Compress for Ds {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Ds {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.scan_hex_words(Ok)?,
        ))
    }
}

impl fmt::Display for Ds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.key_tag, self.algorithm,
               self.digest_type)?;
        for ch in self.digest() {
            write!(f, "{:02x}", ch)?
        }
        Ok(())
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Ds {
    const RTYPE: Rtype = Rtype::Ds;
}


//------------ RtypeBitmap ---------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RtypeBitmap(Bytes);

impl RtypeBitmap {
    pub fn from_bytes(bytes: Bytes) -> Result<Self, RtypeBitmapError> {
        {
            let mut data = bytes.as_ref();
            while !data.is_empty() {
                let len = (data[1] as usize) + 2;
                if len > 34 {
                    return Err(RtypeBitmapError::BadRtypeBitmap)
                }
                if data.len() < len {
                    return Err(RtypeBitmapError::ShortBuf)
                }
                data = &data[len..];
            }
        }
        Ok(RtypeBitmap(bytes))
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn iter(&self) -> RtypeBitmapIter {
        RtypeBitmapIter::new(self.0.as_ref())
    }

    pub fn contains(&self, rtype: Rtype) -> bool {
        let (block, octet, mask) = split_rtype(rtype);
        let octet = octet + 2;
        let mut data = self.0.as_ref();
        while !data.is_empty() {
            if data[0] == block {
                return !((data[1] as usize) < octet || data[octet] & mask == 0)
            }
            data = &data[data[1] as usize..]
        }
        false
    }
}

impl AsRef<Bytes> for RtypeBitmap {
    fn as_ref(&self) -> &Bytes {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for RtypeBitmap {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a RtypeBitmap {
    type Item = Rtype;
    type IntoIter = RtypeBitmapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- ParseAll, Compose, Compress

impl ParseAll for RtypeBitmap {
    type Err = RtypeBitmapError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let bytes = parser.parse_bytes(len)?;
        RtypeBitmap::from_bytes(bytes)
    }
}

impl Compose for RtypeBitmap {
    fn compose_len(&self) -> usize {
        self.0.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.0.compose(buf)
    }
}

impl Compress for RtypeBitmap {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for RtypeBitmap {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        let mut builder = RtypeBitmapBuilder::new();
        while let Ok(rtype) = Rtype::scan(scanner) {
            builder.add(rtype)
        }
        Ok(builder.finalize())
    }
}

impl fmt::Display for RtypeBitmap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let first = true;
        for rtype in self {
            if first {
                rtype.fmt(f)?
            }
            else {
                write!(f, " {}", rtype)?
            }
        }
        Ok(())
    }
}


//------------ RtypeBitmapBuilder --------------------------------------------

/// A builder for a record type bitmap.
//
//  Here is how this is going to work: We keep one long BytesMut into which
//  we place all added types. The buffer contains a sequence of blocks
//  encoded similar to the final format but with all 32 octets of the
//  bitmap present. Blocks are in order and are only added when needed (which
//  means we may have to insert a block in the middle). When finalizing, we
//  compress the block buffer by dropping the unncessary octets of each
//  block.
#[derive(Clone, Debug)]
pub struct RtypeBitmapBuilder {
    buf: BytesMut,
}

impl RtypeBitmapBuilder {
    pub fn new() -> Self {
        RtypeBitmapBuilder {
            // Start out with the capacity for one block.
            buf: BytesMut::with_capacity(34)
        }
    }

    pub fn add(&mut self, rtype: Rtype) {
        let (block, octet, bit) = split_rtype(rtype);
        let block = self.get_block(block);
        if (block[1] as usize) < (octet + 1) {
            block[1] = (octet + 1) as u8
        }
        block[octet + 2] |= bit;
    }

    fn get_block(&mut self, block: u8) -> &mut [u8] {
        let mut pos = 0;
        while pos < self.buf.len() {
            if self.buf[pos] == block {
                return &mut self.buf[pos..pos + 34]
            }
            else if self.buf[pos] > block {
                let len = self.buf.len() - pos;
                self.buf.extend_from_slice(&[0; 34]);
                unsafe {
                    ptr::copy(
                        self.buf.as_ptr().offset(pos as isize),
                        self.buf.as_mut_ptr().offset(pos as isize + 34),
                        len
                    );
                    ptr::write_bytes(
                        self.buf.as_mut_ptr().offset(pos as isize),
                        0,
                        34
                    );
                }
                self.buf[pos] = block;
                return &mut self.buf[pos..pos + 34]
            }
            else {
                pos += 34
            }
        }

        self.buf.extend_from_slice(&[0; 34]);
        self.buf[pos] = block;
        &mut self.buf[pos..pos + 34]
    }

    pub fn finalize(mut self) -> RtypeBitmap {
        let mut src_pos = 0;
        let mut dst_pos = 0;
        while src_pos < self.buf.len() {
            let len = (self.buf[src_pos + 1] as usize) + 2;
            if src_pos != dst_pos {
                unsafe {
                    ptr::copy(
                        self.buf.as_ptr().offset(src_pos as isize),
                        self.buf.as_mut_ptr().offset(dst_pos as isize),
                        len
                    )
                }
            }
            dst_pos += len;
            src_pos += 34;
        }
        self.buf.truncate(dst_pos);
        RtypeBitmap(self.buf.freeze())
    }
}


//--- Default

impl Default for RtypeBitmapBuilder {
    fn default() -> Self {
        Self::new()
    }
}


//------------ RtypeBitmapIter -----------------------------------------------

pub struct RtypeBitmapIter<'a> {
    data: &'a [u8],
    block: u16,
    len: usize,

    octet: usize,
    bit: u16
}

impl<'a> RtypeBitmapIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        if data.is_empty() {
            RtypeBitmapIter {
                data,
                block: 0, len: 0, octet: 0, bit: 0
            }
        }
        else {
            let mut res = RtypeBitmapIter {
                data: &data[2..],
                block: u16::from(data[0]) << 8,
                len: usize::from(data[1]),
                octet: 0,
                bit: 0
            };
            if res.data[0] & 0x80 == 0 {
                res.advance()
            }
            res
        }
    }

    fn advance(&mut self) {
        loop {
            self.bit += 1;
            if self.bit == 7 {
                self.bit = 0;
                self.octet += 1;
                if self.octet == self.len {
                    self.data = &self.data[self.len..];
                    if self.data.is_empty() {
                        return;
                    }
                    self.block = u16::from(self.data[0]) << 8;
                    self.len = self.data[1] as usize;
                    self.octet = 0;
                }
            }
            if self.data[self.octet] & (0x80 >> self.bit) != 0 {
                return
            }
        }
    }
}

impl<'a> Iterator for RtypeBitmapIter<'a> {
    type Item = Rtype;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None
        }
        let res = Rtype::from_int(
            u16::from(self.data[0]) << 8 | (self.octet as u16) << 3 | self.bit
        );
        self.advance();
        Some(res)
    }
}


//------------ ParseNsecError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParseNsecError<E: Fail> {
    #[fail(display="short field")]
    ShortField,

    #[fail(display="{}", _0)]
    BadNextName(E),

    #[fail(display="invalid record type bitmap")]
    BadRtypeBitmap,
}

impl<E: Fail> From<ShortBuf> for ParseNsecError<E> {
    fn from(_: ShortBuf) -> Self {
        ParseNsecError::ShortField
    }
}

impl<E: Fail> From<RtypeBitmapError> for ParseNsecError<E> {
    fn from(err: RtypeBitmapError) -> Self {
        match err {
            RtypeBitmapError::ShortBuf => ParseNsecError::ShortField,
            RtypeBitmapError::BadRtypeBitmap => ParseNsecError::BadRtypeBitmap
        }
    }
}


//------------ RtypeBitmapError ----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum RtypeBitmapError {
    #[fail(display="short field")]
    ShortBuf,

    #[fail(display="invalid record type bitmap")]
    BadRtypeBitmap,
}

impl From<ShortBuf> for RtypeBitmapError {
    fn from(_: ShortBuf) -> Self {
        RtypeBitmapError::ShortBuf
    }
}

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Dnskey, Rrsig, Nsec, Ds};
}


//------------ Friendly Helper Functions -------------------------------------

/// Splits an Rtype value into window number, octet number, and octet mask.
fn split_rtype(rtype: Rtype) -> (u8, usize, u8) {
    let rtype = rtype.to_int();
    (
        (rtype >> 8) as u8,
        ((rtype & 0xFF) >> 3) as usize,
        0x80u8 >> (rtype & 0x07)
    )
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;
    use ::iana::Rtype;

    #[test]
    fn rtype_bitmap_builder() {
        let mut builder = RtypeBitmapBuilder::new();
        builder.add(Rtype::Int(1234)); // 0x04D2
        builder.add(Rtype::A);         // 0x0001
        builder.add(Rtype::Mx);        // 0x000F
        builder.add(Rtype::Rrsig);     // 0x002E
        builder.add(Rtype::Nsec);      // 0x002F
        assert_eq!(builder.finalize().as_slice(),
                   &b"\x00\x06\x40\x01\x00\x00\x00\x03\
                     \x04\x1b\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x20"[..]);
    }
}
