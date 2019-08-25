//! Record data from [RFC 4034].
//!
//! This RFC defines the record types for DNSSEC.
//!
//! [RFC 4034]: https://tools.ietf.org/html/rfc4034

use std::{error, fmt, hash, ptr};
use std::cmp::Ordering;
use std::convert::TryInto;
use bytes::{BufMut, Bytes, BytesMut};
use derive_more::Display;
use unwrap::unwrap;
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::{DigestAlg, Rtype, SecAlg};
use crate::master::scan::{CharSource, ScanError, Scan, Scanner};
use crate::name::ToDname;
use crate::utils::base64;
use crate::name::{Dname, DnameBytesError};
use crate::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use crate::serial::Serial;
use super::RtypeRecordData;


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

    /// Returns true if the key has been revoked.
    /// See [RFC 5011, Section 3](https://tools.ietf.org/html/rfc5011#section-3).
    pub fn is_revoked(&self) -> bool {
        self.flags() & 0b0000_0000_1000_0000 != 0
    }

    /// Returns true if the key has SEP (Secure Entry Point) bit set.
    /// See [RFC 4034, Section 2.1.1](https://tools.ietf.org/html/rfc4034#section-2.1.1)
    ///
    /// ```text
    /// 2.1.1.  The Flags Field
    ///
    ///    This flag is only intended to be a hint to zone signing or debugging software as to the
    ///    intended use of this DNSKEY record; validators MUST NOT alter their
    ///    behavior during the signature validation process in any way based on
    ///    the setting of this bit.
    /// ```
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags() & 0b0000_0000_0000_0001 != 0
    }

    /// Returns true if the key is ZSK (Zone Signing Key) bit set. If the ZSK is not set, the
    /// key MUST NOT be used to verify RRSIGs that cover RRSETs.
    /// See [RFC 4034, Section 2.1.1](https://tools.ietf.org/html/rfc4034#section-2.1.1)
    pub fn is_zsk(&self) -> bool {
        self.flags() & 0b0000_0001_0000_0000 != 0
    }

    /// Returns the key tag for this DNSKEY data.
    pub fn key_tag(&self) -> u16 {
        if self.algorithm == SecAlg::RsaMd5 {
            // The key tag is third-to-last and second-to-last octets of the
            // key as a big-endian u16. If we don’t have enough octets in the
            // key, we return 0.
            let len = self.public_key.len();
            if len > 2 {
                u16::from_be_bytes(unwrap!(
                    self.public_key[len - 3..len - 1].try_into()
                ))
            }
            else {
                0
            }
        }
        else {
            // Treat record data as a octet sequence. Add octets at odd
            // indexes as they are, add octets at even indexes shifted left
            // by 8 bits.
            let mut res = u32::from(self.flags);
            res += u32::from(self.protocol) << 8;
            res += u32::from(self.algorithm.to_int());
            let mut iter = self.public_key().as_ref().iter();
            loop {
                match iter.next() {
                    Some(&x) => res += u32::from(x) << 8,
                    None => break
                }
                match iter.next() {
                    Some(&x) => res += u32::from(x),
                    None => break
                }
            }
            res += (res >> 16) & 0xFFFF;
            (res & 0xFFFF) as u16
        }
    }
}


//--- CanonicalOrd

impl CanonicalOrd for Dnskey {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
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

#[derive(Clone, Debug)]
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
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
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

    pub fn set_signature(&mut self, signature: Bytes) {
        self.signature = signature
    }
}


//--- PartialEq and Eq

impl PartialEq for Rrsig {
    fn eq(&self, other: &Self) -> bool {
        self.type_covered == other.type_covered
        && self.algorithm == other.algorithm
        && self.labels == other.labels
        && self.original_ttl == other.original_ttl
        && self.expiration.into_int() == other.expiration.into_int()
        && self.inception.into_int() == other.inception.into_int()
        && self.key_tag == other.key_tag
        && self.signer_name == other.signer_name
        && self.signature == other.signature
    }
}

impl Eq for Rrsig { }


//--- PartialOrd, Ord, and CanonicalOrd

impl PartialOrd for Rrsig {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.type_covered.partial_cmp(&other.type_covered) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.algorithm.partial_cmp(&other.algorithm) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.labels.partial_cmp(&other.labels) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.original_ttl.partial_cmp(&other.original_ttl) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.expiration.partial_cmp(&other.expiration) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.inception.partial_cmp(&other.inception) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.key_tag.partial_cmp(&other.key_tag) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.signer_name.partial_cmp(&other.signer_name) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.signature.partial_cmp(&other.signature)
    }
}

impl CanonicalOrd for Rrsig {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        match self.type_covered.cmp(&other.type_covered) {
            Ordering::Equal => { }
            other => return other
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        match self.labels.cmp(&other.labels) {
            Ordering::Equal => { }
            other => return other
        }
        match self.original_ttl.cmp(&other.original_ttl) {
            Ordering::Equal => { }
            other => return other
        }
        match self.expiration.canonical_cmp(&other.expiration) {
            Ordering::Equal => { }
            other => return other
        }
        match self.inception.canonical_cmp(&other.inception) {
            Ordering::Equal => { }
            other => return other
        }
        match self.key_tag.cmp(&other.key_tag) {
            Ordering::Equal => { }
            other => return other
        }
        match self.signer_name.lowercase_composed_cmp(&other.signer_name) {
            Ordering::Equal => { }
            other => return other
        }
        self.signature.cmp(&other.signature)
    }
}


//--- Hash

impl hash::Hash for Rrsig {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.type_covered.hash(state);
        self.algorithm.hash(state);
        self.labels.hash(state);
        self.original_ttl.hash(state);
        self.expiration.into_int().hash(state);
        self.inception.into_int().hash(state);
        self.key_tag.hash(state);
        self.signer_name.hash(state);
        self.signature.hash(state);
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

    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        self.type_covered.compose(buf);
        self.algorithm.compose(buf);
        self.labels.compose(buf);
        self.original_ttl.compose(buf);
        self.expiration.compose(buf);
        self.inception.compose(buf);
        self.key_tag.compose(buf);
        self.signer_name.compose_canonical(buf);
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
        write!(f, "{} {} {} {} {} {} {} {}. ",
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

#[derive(Clone, Debug, Hash)]
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

    pub fn set_next_name(&mut self, next_name: N) {
        self.next_name = next_name
    }

    pub fn types(&self) -> &RtypeBitmap {
        &self.types
    }
}


//--- PartialEq and Eq

impl<N: PartialEq<NN>, NN> PartialEq<Nsec<NN>> for Nsec<N> {
    fn eq(&self, other: &Nsec<NN>) -> bool {
        self.next_name.eq(&other.next_name)
        && self.types == other.types
    }
}

impl<N: Eq> Eq for Nsec<N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N: PartialOrd<NN>, NN> PartialOrd<Nsec<NN>> for Nsec<N> {
    fn partial_cmp(&self, other: &Nsec<NN>) -> Option<Ordering> {
        match self.next_name.partial_cmp(&other.next_name) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.types.partial_cmp(&self.types)
    }
}

impl<N: Ord> Ord for Nsec<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.next_name.cmp(&other.next_name) {
            Ordering::Equal => { }
            other => return other
        }
        self.types.cmp(&self.types)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Nsec<NN>> for Nsec<N> {
    fn canonical_cmp(&self, other: &Nsec<NN>) -> Ordering {
        // RFC 6840 says that Nsec::next_name is not converted to lower case.
        match self.next_name.composed_cmp(&other.next_name) {
            Ordering::Equal => { }
            other => return other
        }
        self.types.cmp(&self.types)
    }
}


//--- ParseAll, Compose, and Compress

impl<N: Parse> ParseAll for Nsec<N>
where <N as Parse>::Err: error::Error {
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

    // Default compose_canonical is correct as we keep the case.
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
        write!(f, "{}. {}", self.next_name, self.types)
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


//--- CanonicalOrd

impl CanonicalOrd for Ds {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
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
                // https://tools.ietf.org/html/rfc4034#section-4.1.2:
                //  Blocks with no types present MUST NOT be included.
                if len == 2 {
                    return Err(RtypeBitmapError::BadRtypeBitmap);
                }
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

    pub fn builder() -> RtypeBitmapBuilder {
        RtypeBitmapBuilder::new()
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
        let mut data = self.0.as_ref();
        while !data.is_empty() {
            let ((window_num, window), next_data) = read_window(data).unwrap();
            if window_num == block {
                return !(window.len() < octet || window[octet] & mask == 0);
            }
            data = next_data;
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
        let mut iter = self.iter();
        if let Some(rtype) = iter.next() {
            rtype.fmt(f)?;
        }
        for rtype in iter {
            write!(f, " {}", rtype)?
        }
        Ok(())
    }
}


//------------ RtypeBitmapBuilder --------------------------------------------

/// A builder for a record type bitmap.
//
//  Here is how this is going to work: We keep one long BytesMut into which
//  we place all added types. The buffer contains a sequence of blocks
//  encoded similarly to the final format but with all 32 octets of the
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
                        self.buf.as_ptr().add(pos),
                        self.buf.as_mut_ptr().add(pos + 34),
                        len
                    );
                    ptr::write_bytes(
                        self.buf.as_mut_ptr().add(pos),
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
                        self.buf.as_ptr().add(src_pos),
                        self.buf.as_mut_ptr().add(dst_pos),
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
    /// The data to iterate over.
    ///
    /// This starts with the octets of the current block without the block
    /// number and length.
    data: &'a [u8],

    /// The base value of the current block, i.e., its upper 8 bits.
    block: u16,

    /// The length of the current block’s data.
    len: usize,

    /// Index of the current octet in the current block.
    octet: usize,

    /// Index of the next set bit in the current octet in the current block.
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
            self.block | (self.octet as u16) << 3 | self.bit
        );
        self.advance();
        Some(res)
    }
}


//------------ ParseNsecError ------------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum ParseNsecError<E: error::Error> {
    #[display(fmt="short field")]
    ShortField,

    #[display(fmt="{}", _0)]
    BadNextName(E),

    #[display(fmt="invalid record type bitmap")]
    BadRtypeBitmap,
}

impl<E: error::Error> error::Error for ParseNsecError<E> { }

impl<E: error::Error> From<ShortBuf> for ParseNsecError<E> {
    fn from(_: ShortBuf) -> Self {
        ParseNsecError::ShortField
    }
}

impl<E: error::Error> From<RtypeBitmapError> for ParseNsecError<E> {
    fn from(err: RtypeBitmapError) -> Self {
        match err {
            RtypeBitmapError::ShortBuf => ParseNsecError::ShortField,
            RtypeBitmapError::BadRtypeBitmap => ParseNsecError::BadRtypeBitmap
        }
    }
}


//------------ RtypeBitmapError ----------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum RtypeBitmapError {
    #[display(fmt="short field")]
    ShortBuf,

    #[display(fmt="invalid record type bitmap")]
    BadRtypeBitmap,
}

impl error::Error for RtypeBitmapError { }

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
        0b1000_0000 >> (rtype & 0x07)
    )
}

/// Splits the next bitmap window from the bitmap and returns None when there's no next window.
#[allow(clippy::type_complexity)]
fn read_window(data: &[u8]) -> Option<((u8, &[u8]), &[u8])> {
    data.split_first()
        .and_then(|(n, data)| {
            data.split_first()
                .and_then(|(l, data)| if data.len() >= usize::from(*l) {
                    let (window, data) = data.split_at(usize::from(*l));
                    Some(((*n, window), data))
                } else {
                    None
                })
        })
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
    use crate::iana::Rtype;
    use super::*;

    #[test]
    fn rtype_split() {
        assert_eq!(split_rtype(Rtype::A),   (0, 0, 0b01000000));
        assert_eq!(split_rtype(Rtype::Ns),  (0, 0, 0b00100000));
        assert_eq!(split_rtype(Rtype::Caa), (1, 0, 0b01000000));
    }

    #[test]
    fn rtype_bitmap_read_window() {
        let mut builder = RtypeBitmapBuilder::new();
        builder.add(Rtype::A);
        builder.add(Rtype::Caa);
        let bitmap = builder.finalize();

        let ((n, window), data) = read_window(bitmap.as_slice()).unwrap();
        assert_eq!((n, window), (0u8, b"\x40".as_ref()));
        let ((n, window), data) = read_window(data).unwrap();
        assert_eq!((n, window), (1u8, b"\x40".as_ref()));
        assert!(data.is_empty());
        assert!(read_window(data).is_none());
    }

    #[test]
    fn rtype_bitmap_builder() {
        let mut builder = RtypeBitmapBuilder::new();
        builder.add(Rtype::Int(1234)); // 0x04D2
        builder.add(Rtype::A); // 0x0001
        builder.add(Rtype::Mx); // 0x000F
        builder.add(Rtype::Rrsig); // 0x002E
        builder.add(Rtype::Nsec); // 0x002F
        let bitmap = builder.finalize();
        assert_eq!(
            bitmap.as_slice(),
            &b"\x00\x06\x40\x01\x00\x00\x00\x03\
                     \x04\x1b\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x20"[..]
        );

        assert!(bitmap.contains(Rtype::A));
        assert!(bitmap.contains(Rtype::Mx));
        assert!(bitmap.contains(Rtype::Rrsig));
        assert!(bitmap.contains(Rtype::Nsec));
        assert!(bitmap.contains(Rtype::Int(1234)));
        assert!(!bitmap.contains(Rtype::Int(1235)));
        assert!(!bitmap.contains(Rtype::Ns));
    }

    #[test]
    fn dnskey_key_tag() {
        assert_eq!(
            Dnskey::new(
                256, 3, SecAlg::RsaSha256,
                unwrap!(base64::decode(
                    "AwEAAcTQyaIe6nt3xSPOG2L/YfwBkOVTJN6mlnZ249O5Rtt3ZSRQHxQS\
                     W61AODYw6bvgxrrGq8eeOuenFjcSYgNAMcBYoEYYmKDW6e9EryW4ZaT/\
                     MCq+8Am06oR40xAA3fClOM6QjRcT85tP41Go946AicBGP8XOP/Aj1aI/\
                     oPRGzRnboUPUok/AzTNnW5npBU69+BuiIwYE7mQOiNBFePyvjQBdoiuY\
                     bmuD3Py0IyjlBxzZUXbqLsRL9gYFkCqeTY29Ik7usuzMTa+JRSLz6KGS\
                     5RSJ7CTSMjZg8aNaUbN2dvGhakJPh92HnLvMA3TefFgbKJphFNPA3BWS\
                     KLZ02cRWXqM="
                ))
            ).key_tag(),
            59944
        );
        assert_eq!(
            Dnskey::new(
                257, 3, SecAlg::RsaSha256,
                unwrap!(base64::decode(
                    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTO\
                    iW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN\
                    7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5\
                    LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8\
                    efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7\
                    pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY\
                    A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws\
                    9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
                ))
            ).key_tag(),
            20326
        );
        assert_eq!(
            Dnskey::new(
                257, 3, SecAlg::RsaMd5,
                unwrap!(base64::decode(
                    "AwEAAcVaA4jSBIGRrSzpecoJELvKE9+OMuFnL8mmUBsY\
                    lB6epN1CqX7NzwjDpi6VySiEXr0C4uTYkU/L1uMv2mHE\
                    AljThFDJ1GuozJ6gA7jf3lnaGppRg2IoVQ9IVmLORmjw\
                    C+7Eoi12SqybMTicD3Ezwa9XbG1iPjmjhbMrLh7MSQpX"
                ))
            ).key_tag(),
            18698
        );
    }

    #[test]
    fn dnskey_flags() {
        let dnskey = Dnskey::new(257, 3, SecAlg::RsaSha256, Bytes::new());
        assert_eq!(dnskey.is_zsk(), true);
        assert_eq!(dnskey.is_secure_entry_point(), true);
        assert_eq!(dnskey.is_revoked(), false);
    }
}
