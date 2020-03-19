//! Record data from [RFC 4034].
//!
//! This RFC defines the record types for DNSSEC.
//!
//! [RFC 4034]: https://tools.ietf.org/html/rfc4034

use core::{fmt, hash, ptr};
use core::cmp::Ordering;
use core::convert::TryInto;
#[cfg(feature = "std")] use std::vec::Vec;
#[cfg(feature="master")] use bytes::{Bytes, BytesMut};
use derive_more::Display;
use unwrap::unwrap;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, Rtype, SecAlg};
use crate::base::name::{ParsedDname, ToDname};
use crate::base::octets::{
    Compose, EmptyBuilder, FormError, FromBuilder, IntoOctets, OctetsBuilder,
    OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use crate::base::rdata::{RtypeRecordData};
use crate::base::serial::Serial;
use crate::base::utils::base64;
#[cfg(feature="master")] use crate::base::name::Dname;
#[cfg(feature="master")] use crate::master::scan::{ 
    CharSource, ScanError, Scan, Scanner
};


//------------ Dnskey --------------------------------------------------------

#[derive(Clone)]
pub struct Dnskey<Octets> {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    public_key: Octets,
}

impl<Octets> Dnskey<Octets> {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octets)
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

    pub fn public_key(&self) -> &Octets {
        &self.public_key
    }

    pub fn into_public_key(self) -> Octets {
        self.public_key
    }

    pub fn convert<Other: From<Octets>>(
        self
    ) -> Dnskey<Other> {
        Dnskey {
            flags: self.flags,
            protocol: self.protocol,
            algorithm: self.algorithm,
            public_key: self.public_key.into()
        }
    }

    /// Returns whether the Revoke flag is set.
    ///
    /// See [RFC 5011, Section 3].
    ///
    /// [RFC 5011, Section 3]: https://tools.ietf.org/html/rfc5011#section-3
    pub fn is_revoked(&self) -> bool {
        self.flags() & 0b0000_0000_1000_0000 != 0
    }

    /// Returns whether the the Secure Entry Point (SEP) flag is set.
    ///
    /// See [RFC 4034, Section 2.1.1]:
    ///
    /// > This flag is only intended to be a hint to zone signing or
    /// > debugging software as to the intended use of this DNSKEY record;
    /// > validators MUST NOT alter their behavior during the signature
    /// > validation process in any way based on the setting of this bit.
    ///
    /// [RFC 4034, Section 2.1.1]: https://tools.ietf.org/html/rfc4034#section-2.1.1
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags() & 0b0000_0000_0000_0001 != 0
    }

    /// Returns whether the Zone Key flag is set. 
    ///
    /// If the flag is not set, the key MUST NOT be used to verify RRSIGs that
    /// cover RRSETs. See [RFC 4034, Section 2.1.1].
    ///
    /// [RFC 4034, Section 2.1.1]: https://tools.ietf.org/html/rfc4034#section-2.1.1
    pub fn is_zsk(&self) -> bool {
        self.flags() & 0b0000_0001_0000_0000 != 0
    }

    /// Returns the key tag for this DNSKEY data.
    pub fn key_tag(&self) -> u16
    where Octets: AsRef<[u8]> {
        if self.algorithm == SecAlg::RsaMd5 {
            // The key tag is third-to-last and second-to-last octets of the
            // key as a big-endian u16. If we don’t have enough octets in the
            // key, we return 0.
            let len = self.public_key.as_ref().len();
            if len > 2 {
                u16::from_be_bytes(unwrap!(
                    self.public_key.as_ref()[len - 3..len - 1].try_into()
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


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Dnskey<Other>> for Dnskey<Octets> 
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &Dnskey<Other>) -> bool {
        self.flags == other.flags
        && self.protocol == other.protocol
        && self.algorithm == other.algorithm
        && self.public_key.as_ref() == other.public_key.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> Eq for Dnskey<Octets> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Dnskey<Other>> for Dnskey<Octets> 
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Dnskey<Other>) -> Option<Ordering> {
        Some(self.canonical_cmp(other))
    }
}

impl<Octets, Other> CanonicalOrd<Dnskey<Other>> for Dnskey<Octets> 
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &Dnskey<Other>) -> Ordering {
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => { }
            other => return other
        }
        match self.protocol.cmp(&other.protocol) {
            Ordering::Equal => { }
            other => return other
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        self.public_key.as_ref().cmp(other.public_key.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for Dnskey<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}


//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Dnskey<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.flags.hash(state);
        self.protocol.hash(state);
        self.algorithm.hash(state);
        self.public_key.as_ref().hash(state);
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Dnskey<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortBuf)
        };
        Ok(Self::new(
            u16::parse(parser)?,
            u8::parse(parser)?,
            SecAlg::parse(parser)?,
            parser.parse_octets(len)?
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortBuf)
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Dnskey<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.flags.compose(buf)?;
            self.protocol.compose(buf)?;
            self.algorithm.compose(buf)?;
            buf.append_slice(self.public_key.as_ref())
        })
    }
}


//--- Scan and Display

#[cfg(feature="master")]
impl Scan for Dnskey<Bytes> {
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

impl<Octets: AsRef<[u8]>> fmt::Display for Dnskey<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}


//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for Dnskey<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Dnskey")
            .field("flags", &self.flags)
            .field("protocol", &self.protocol)
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key.as_ref())
            .finish()
    }
}


//--- RtypeRecordData

impl<Octets> RtypeRecordData for Dnskey<Octets> {
    const RTYPE: Rtype = Rtype::Dnskey;
}


//------------ ProtoRrsig ----------------------------------------------------

/// The RRSIG RDATA to be included when creating the signature.
#[derive(Clone)]
pub struct ProtoRrsig<Name> {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: u32,
    expiration: Serial,
    inception: Serial,
    key_tag: u16,
    signer_name: Name,
}

impl<Name> ProtoRrsig<Name> {
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: u32,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Name,
    ) -> Self {
        ProtoRrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
        }
    }

    pub fn into_rrsig<Octets>(
        self,
        signature: Octets
    ) -> Rrsig<Octets, Name> {
        Rrsig::new(
            self.type_covered, self.algorithm, self.labels,
            self.original_ttl, self.expiration, self.inception,
            self.key_tag, self.signer_name, signature
        )
    }
}

//--- Compose

impl<Name: Compose> Compose for ProtoRrsig<Name> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.type_covered.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.labels.compose(buf)?;
            self.original_ttl.compose(buf)?;
            self.expiration.compose(buf)?;
            self.inception.compose(buf)?;
            self.key_tag.compose(buf)?;
            self.signer_name.compose(buf)
        })
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.type_covered.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.labels.compose(buf)?;
            self.original_ttl.compose(buf)?;
            self.expiration.compose(buf)?;
            self.inception.compose(buf)?;
            self.key_tag.compose(buf)?;
            self.signer_name.compose_canonical(buf)
        })
    }
}



//------------ Rrsig ---------------------------------------------------------

#[derive(Clone)]
pub struct Rrsig<Octets, Name> {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: u32,
    expiration: Serial,
    inception: Serial,
    key_tag: u16,
    signer_name: Name,
    signature: Octets,
}

impl<Octets, Name> Rrsig<Octets, Name> {
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: u32,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Name,
        signature: Octets
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

    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    pub fn signature(&self) -> &Octets {
        &self.signature
    }

    pub fn set_signature(&mut self, signature: Octets) {
        self.signature = signature
    }
}


//--- PartialEq and Eq

impl<N, NN, O, OO> PartialEq<Rrsig<OO, NN>> for Rrsig<O, N>
where N: ToDname, NN: ToDname, O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn eq(&self, other: &Rrsig<OO, NN>) -> bool {
        self.type_covered == other.type_covered
        && self.algorithm == other.algorithm
        && self.labels == other.labels
        && self.original_ttl == other.original_ttl
        && self.expiration.into_int() == other.expiration.into_int()
        && self.inception.into_int() == other.inception.into_int()
        && self.key_tag == other.key_tag
        && self.signer_name.name_eq(&other.signer_name)
        && self.signature.as_ref() == other.signature.as_ref()
    }
}

impl<Octets, Name> Eq for Rrsig<Octets, Name>
where Octets: AsRef<[u8]>, Name: ToDname { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<N, NN, O, OO> PartialOrd<Rrsig<OO, NN>> for Rrsig<O, N>
where N: ToDname, NN: ToDname, O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Rrsig<OO, NN>) -> Option<Ordering> {
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
        match self.signer_name.name_cmp(&other.signer_name) {
            Ordering::Equal => { }
            other => return Some(other)
        }
        self.signature.as_ref().partial_cmp(other.signature.as_ref())
    }
}

impl<N, NN, O, OO> CanonicalOrd<Rrsig<OO, NN>> for Rrsig<O, N>
where N: ToDname, NN: ToDname, O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &Rrsig<OO, NN>) -> Ordering {
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
        self.signature.as_ref().cmp(other.signature.as_ref())
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Ord for Rrsig<O, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}


//--- Hash

impl<O: AsRef<[u8]>, N: hash::Hash> hash::Hash for Rrsig<O, N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.type_covered.hash(state);
        self.algorithm.hash(state);
        self.labels.hash(state);
        self.original_ttl.hash(state);
        self.expiration.into_int().hash(state);
        self.inception.into_int().hash(state);
        self.key_tag.hash(state);
        self.signer_name.hash(state);
        self.signature.as_ref().hash(state);
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Rrsig<Ref::Range, ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let type_covered = Rtype::parse(parser)?;
        let algorithm = SecAlg::parse(parser)?;
        let labels = u8::parse(parser)?;
        let original_ttl = u32::parse(parser)?;
        let expiration = Serial::parse(parser)?;
        let inception = Serial::parse(parser)?;
        let key_tag = u16::parse(parser)?;
        let signer_name = ParsedDname::parse(parser)?;
        let len = parser.remaining();
        let signature = parser.parse_octets(len)?;
        Ok(Self::new(
            type_covered, algorithm, labels, original_ttl, expiration,
            inception, key_tag, signer_name, signature
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        Rtype::skip(parser)?;
        SecAlg::skip(parser)?;
        u8::skip(parser)?;
        u32::skip(parser)?;
        Serial::skip(parser)?;
        Serial::skip(parser)?;
        u16::skip(parser)?;
        ParsedDname::skip(parser)?;
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>, Name: Compose> Compose for Rrsig<Octets, Name> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.type_covered.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.labels.compose(buf)?;
            self.original_ttl.compose(buf)?;
            self.expiration.compose(buf)?;
            self.inception.compose(buf)?;
            self.key_tag.compose(buf)?;
            self.signer_name.compose(buf)?;
            buf.append_slice(self.signature.as_ref())
        })
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.type_covered.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.labels.compose(buf)?;
            self.original_ttl.compose(buf)?;
            self.expiration.compose(buf)?;
            self.inception.compose(buf)?;
            self.key_tag.compose(buf)?;
            self.signer_name.compose_canonical(buf)?;
            buf.append_slice(self.signature.as_ref())
        })
    }
}


//--- Scan and Display

#[cfg(feature="master")]
impl Scan for Rrsig<Bytes, Dname<Bytes>> {
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

impl<Octets, Name> fmt::Display for Rrsig<Octets, Name>
where Octets: AsRef<[u8]>, Name: fmt::Display {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {} {} {} {} {}. ",
               self.type_covered, self.algorithm, self.labels,
               self.original_ttl, self.expiration, self.inception,
               self.key_tag, self.signer_name)?;
        base64::display(&self.signature, f)
    }
}


//--- Debug

impl<Octets, Name> fmt::Debug for Rrsig<Octets, Name>
where Octets: AsRef<[u8]>, Name: fmt::Debug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Rrsig")
            .field("type_covered", &self.type_covered)
            .field("algorithm", &self.algorithm)
            .field("labels", &self.labels)
            .field("original_ttl", &self.original_ttl)
            .field("expiration", &self.expiration)
            .field("inception", &self.inception)
            .field("key_tag", &self.key_tag)
            .field("signer_name", &self.signer_name)
            .field("signature", &self.signature.as_ref())
            .finish()
    }
}


//--- RtypeRecordData

impl<Octets, Name> RtypeRecordData for Rrsig<Octets, Name> {
    const RTYPE: Rtype = Rtype::Rrsig;
}


//------------ Nsec ----------------------------------------------------------

#[derive(Clone)]
pub struct Nsec<Octets, Name> {
    next_name: Name,
    types: RtypeBitmap<Octets>,
}

impl<Octets, Name> Nsec<Octets, Name> {
    pub fn new(next_name: Name, types: RtypeBitmap<Octets>) -> Self {
        Nsec { next_name, types }
    }

    pub fn next_name(&self) -> &Name {
        &self.next_name
    }

    pub fn set_next_name(&mut self, next_name: Name) {
        self.next_name = next_name
    }

    pub fn types(&self) -> &RtypeBitmap<Octets> {
        &self.types
    }
}


//--- PartialEq and Eq

impl<O, OO, N, NN> PartialEq<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>, OO: AsRef<[u8]>,
    N: ToDname, NN: ToDname,
{
    fn eq(&self, other: &Nsec<OO, NN>) -> bool {
        self.next_name.name_eq(&other.next_name)
        && self.types == other.types
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Eq for Nsec<O, N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<O, OO, N, NN> PartialOrd<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>, OO: AsRef<[u8]>,
    N: ToDname, NN: ToDname,
{
    fn partial_cmp(&self, other: &Nsec<OO, NN>) -> Option<Ordering> {
        match self.next_name.name_cmp(&other.next_name) {
            Ordering::Equal => { }
            other => return Some(other)
        }
        self.types.partial_cmp(&self.types)
    }
}

impl<O, OO, N, NN> CanonicalOrd<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>, OO: AsRef<[u8]>,
    N: ToDname, NN: ToDname,
{
    fn canonical_cmp(&self, other: &Nsec<OO, NN>) -> Ordering {
        // RFC 6840 says that Nsec::next_name is not converted to lower case.
        match self.next_name.composed_cmp(&other.next_name) {
            Ordering::Equal => { }
            other => return other
        }
        self.types.cmp(&self.types)
    }
}

impl<O, N> Ord for Nsec<O, N>
where O: AsRef<[u8]>, N: ToDname {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.next_name.name_cmp(&other.next_name) {
            Ordering::Equal => { }
            other => return other
        }
        self.types.cmp(&self.types)
    }
}


//--- Hash

impl<Octets: AsRef<[u8]>, Name: hash::Hash> hash::Hash for Nsec<Octets, Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.next_name.hash(state);
        self.types.hash(state);
    }
}


//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Nsec<Ref::Range, ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Nsec::new(
            ParsedDname::parse(parser)?,
            RtypeBitmap::parse(parser)?
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        ParsedDname::skip(parser)?;
        RtypeBitmap::skip(parser)
    }
}

impl<Octets: AsRef<[u8]>, Name: Compose> Compose for Nsec<Octets, Name> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.next_name.compose(target)?;
            self.types.compose(target)
        })
    }

    // Default compose_canonical is correct as we keep the case.
}


//--- Scan and Display

#[cfg(feature="master")]
impl<N: Scan> Scan for Nsec<Bytes, N> {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            N::scan(scanner)?,
            RtypeBitmap::scan(scanner)?,
        ))
    }
}

impl<Octets, Name> fmt::Display for Nsec<Octets, Name>
where Octets: AsRef<[u8]>, Name: fmt::Display {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}", self.next_name, self.types)
    }
}


//--- Debug

impl<Octets, Name> fmt::Debug for Nsec<Octets, Name>
where Octets: AsRef<[u8]>, Name: fmt::Debug {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Nsec")
            .field("next_name", &self.next_name)
            .field("types", &self.types)
            .finish()
    }
}


//--- RtypeRecordData

impl<Octets, Name> RtypeRecordData for Nsec<Octets, Name> {
    const RTYPE: Rtype = Rtype::Nsec;
}


//------------ Ds -----------------------------------------------------------

#[derive(Clone)]
pub struct Ds<Octets> {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    digest: Octets,
}

impl<Octets> Ds<Octets> {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octets
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

    pub fn digest(&self) -> &Octets {
        &self.digest
    }

    pub fn into_digest(self) -> Octets {
        self.digest
    }
}


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Ds<Other>> for Ds<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &Ds<Other>) -> bool {
        self.key_tag == other.key_tag
        && self.algorithm == other.algorithm
        && self.digest_type == other.digest_type
        && self.digest.as_ref().eq(other.digest.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for Ds<Octets> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Ds<Other>> for Ds<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Ds<Other>) -> Option<Ordering> {
        match self.key_tag.partial_cmp(&other.key_tag) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.algorithm.partial_cmp(&other.algorithm) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.digest_type.partial_cmp(&other.digest_type) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.digest.as_ref().partial_cmp(other.digest.as_ref())
    }
}

impl<Octets, Other> CanonicalOrd<Ds<Other>> for Ds<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &Ds<Other>) -> Ordering {
        match self.key_tag.cmp(&other.key_tag) {
            Ordering::Equal => { }
            other => return other
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => { }
            other => return other
        }
        match self.digest_type.cmp(&other.digest_type) {
            Ordering::Equal => { }
            other => return other
        }
        self.digest.as_ref().cmp(other.digest.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for Ds<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}


//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Ds<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key_tag.hash(state);
        self.algorithm.hash(state);
        self.digest_type.hash(state);
        self.digest.as_ref().hash(state);
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Ds<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortBuf)
        };
        Ok(Self::new(
            u16::parse(parser)?,
            SecAlg::parse(parser)?,
            DigestAlg::parse(parser)?,
            parser.parse_octets(len)?
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortBuf);
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Ds<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.key_tag.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.digest_type.compose(buf)?;
            buf.append_slice(self.digest.as_ref())
        })
    }
}


//--- Scan and Display

#[cfg(feature="master")]
impl Scan for Ds<Bytes> {
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

impl<Octets: AsRef<[u8]>> fmt::Display for Ds<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.key_tag, self.algorithm,
               self.digest_type)?;
        for ch in self.digest.as_ref() {
            write!(f, "{:02x}", ch)?
        }
        Ok(())
    }
}


//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for Ds<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ds")
            .field("key_tag", &self.key_tag)
            .field("algorithm", &self.algorithm)
            .field("digest_type", &self.digest_type)
            .field("digest", &self.digest.as_ref())
            .finish()
    }
}


//--- RtypeRecordData

impl<Octets> RtypeRecordData for Ds<Octets> {
    const RTYPE: Rtype = Rtype::Ds;
}


//------------ RtypeBitmap ---------------------------------------------------

#[derive(Clone)]
pub struct RtypeBitmap<Octets>(Octets);

impl<Octets> RtypeBitmap<Octets> {
    pub fn from_octets(octets: Octets) -> Result<Self, RtypeBitmapError>
    where Octets: AsRef<[u8]> {
        {
            let mut data = octets.as_ref();
            while !data.is_empty() {
                // At least bitmap number and length must be present.
                if data.len() < 2 {
                    return Err(RtypeBitmapError::ShortBuf)
                }

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
        Ok(RtypeBitmap(octets))
    }

    pub fn builder() -> RtypeBitmapBuilder<Octets::Builder>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder
    {
        RtypeBitmapBuilder::new()
    }

    pub fn as_octets(&self) -> &Octets {
        &self.0
    }
}

impl<Octets: AsRef<[u8]>> RtypeBitmap<Octets> {
    pub fn as_slice(&self) -> &[u8]
    where Octets: AsRef<[u8]> {
        self.0.as_ref()
    }

    pub fn iter(&self) -> RtypeBitmapIter {
        RtypeBitmapIter::new(self.0.as_ref())
    }

    pub fn contains(&self, rtype: Rtype) -> bool
    where Octets: AsRef<[u8]> {
        let (block, octet, mask) = split_rtype(rtype);
        let mut data = self.0.as_ref();
        while !data.is_empty() {
            let ((window_num, window), next_data) = read_window(data).unwrap();
            if window_num == block {
                return !(window.len() <= octet || window[octet] & mask == 0);
            }
            data = next_data;
        }
        false
    }
}


//--- AsRef

impl<T, Octets: AsRef<T>> AsRef<T> for RtypeBitmap<Octets> {
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}


//--- PartialEq and Eq

impl<O, OO> PartialEq<RtypeBitmap<OO>> for RtypeBitmap<O>
where O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn eq(&self, other: &RtypeBitmap<OO>) -> bool {
        self.0.as_ref().eq(other.0.as_ref())
    }
}

impl<O: AsRef<[u8]>> Eq for RtypeBitmap<O> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<O, OO> PartialOrd<RtypeBitmap<OO>> for RtypeBitmap<O>
where O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn partial_cmp(&self, other: &RtypeBitmap<OO>) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.0.as_ref())
    }
}

impl<O, OO> CanonicalOrd<RtypeBitmap<OO>> for RtypeBitmap<O>
where O: AsRef<[u8]>, OO: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &RtypeBitmap<OO>) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl<O: AsRef<[u8]>> Ord for RtypeBitmap<O> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}


//--- Hash

impl<O: AsRef<[u8]>> hash::Hash for RtypeBitmap<O> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}


//--- IntoIterator

impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a RtypeBitmap<Octets> {
    type Item = Rtype;
    type IntoIter = RtypeBitmapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for RtypeBitmap<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        RtypeBitmap::from_octets(parser.parse_octets(len)?).map_err(Into::into)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for RtypeBitmap<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.0.as_ref())
    }
}


//--- Scan and Display

#[cfg(feature="master")]
impl Scan for RtypeBitmap<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        let mut builder = RtypeBitmapBuilder::<BytesMut>::new();
        while let Ok(rtype) = Rtype::scan(scanner) {
            unwrap!(builder.add(rtype))
        }
        Ok(builder.finalize())
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for RtypeBitmap<Octets> {
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

//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for RtypeBitmap<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RtypeBitmap(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}


//------------ RtypeBitmapBuilder --------------------------------------------

/// A builder for a record type bitmap.
//
//  Here is how this is going to work: We keep one long Builder into which
//  we place all added types. The buffer contains a sequence of blocks
//  encoded similarly to the final format but with all 32 octets of the
//  bitmap present. Blocks are in order and are only added when needed (which
//  means we may have to insert a block in the middle). When finalizing, we
//  compress the block buffer by dropping the unncessary octets of each
//  block.
#[derive(Clone, Debug)]
pub struct RtypeBitmapBuilder<Builder> {
    buf: Builder,
}

impl<Builder: OctetsBuilder> RtypeBitmapBuilder<Builder> {
    pub fn new() -> Self
    where Builder: EmptyBuilder {
        RtypeBitmapBuilder {
            // Start out with the capacity for one block.
            buf: Builder::with_capacity(34)
        }
    }
}

#[cfg(feature = "std")]
impl RtypeBitmapBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::new()
    }
}

impl<Builder: OctetsBuilder> RtypeBitmapBuilder<Builder> {
    pub fn add(&mut self, rtype: Rtype) -> Result<(), ShortBuf> {
        let (block, octet, bit) = split_rtype(rtype);
        let block = self.get_block(block)?;
        if (block[1] as usize) < (octet + 1) {
            block[1] = (octet + 1) as u8
        }
        block[octet + 2] |= bit;
        Ok(())
    }

    fn get_block(&mut self, block: u8) -> Result<&mut [u8], ShortBuf> {
        let mut pos = 0;
        while pos < self.buf.as_ref().len() {
            if self.buf.as_ref()[pos] == block {
                return Ok(&mut self.buf.as_mut()[pos..pos + 34])
            }
            else if self.buf.as_ref()[pos] > block {
                let len = self.buf.as_ref().len() - pos;
                self.buf.append_slice(&[0; 34])?;
                let buf = self.buf.as_mut();
                unsafe {
                    ptr::copy(
                        buf.as_ptr().add(pos),
                        buf.as_mut_ptr().add(pos + 34),
                        len
                    );
                    ptr::write_bytes(
                        buf.as_mut_ptr().add(pos),
                        0,
                        34
                    );
                }
                buf[pos] = block;
                return Ok(&mut buf[pos..pos + 34])
            }
            else {
                pos += 34
            }
        }

        self.buf.append_slice(&[0; 34])?;
        self.buf.as_mut()[pos] = block;
        Ok(&mut self.buf.as_mut()[pos..pos + 34])
    }

    pub fn finalize(mut self) -> RtypeBitmap<Builder::Octets>
    where Builder: IntoOctets {
        let mut src_pos = 0;
        let mut dst_pos = 0;
        while src_pos < self.buf.as_ref().len() {
            let len = (self.buf.as_ref()[src_pos + 1] as usize) + 2;
            if src_pos != dst_pos {
                let buf = self.buf.as_mut();
                unsafe {
                    ptr::copy(
                        buf.as_ptr().add(src_pos),
                        buf.as_mut_ptr().add(dst_pos),
                        len
                    )
                }
            }
            dst_pos += len;
            src_pos += 34;
        }
        self.buf.truncate(dst_pos);
        RtypeBitmap(self.buf.into_octets())
    }
}


//--- Default

impl<Builder> Default for RtypeBitmapBuilder<Builder>
where Builder: OctetsBuilder + EmptyBuilder {
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
            if self.bit == 8 {
                self.bit = 0;
                self.octet += 1;
                if self.octet == self.len {
                    self.data = &self.data[self.len..];
                    if self.data.is_empty() {
                        return;
                    }
                    self.block = u16::from(self.data[0]) << 8;
                    self.len = usize::from(self.data[1]);
                    self.data = &self.data[2..];
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


//------------ RtypeBitmapError ----------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum RtypeBitmapError {
    #[display(fmt="short field")]
    ShortBuf,

    #[display(fmt="invalid record type bitmap")]
    BadRtypeBitmap,
}

#[cfg(feature = "std")]
impl std::error::Error for RtypeBitmapError { }

impl From<ShortBuf> for RtypeBitmapError {
    fn from(_: ShortBuf) -> Self {
        RtypeBitmapError::ShortBuf
    }
}

impl From<RtypeBitmapError> for ParseError {
    fn from(err: RtypeBitmapError) -> ParseError {
        match err {
            RtypeBitmapError::ShortBuf => ParseError::ShortBuf,
            RtypeBitmapError::BadRtypeBitmap => {
                FormError::new("invalid NSEC bitmap").into()
            }
        }
    }
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
    use crate::base::iana::Rtype;
    use std::vec::Vec;
    use super::*;

    #[test]
    fn rtype_split() {
        assert_eq!(split_rtype(Rtype::A),   (0, 0, 0b01000000));
        assert_eq!(split_rtype(Rtype::Ns),  (0, 0, 0b00100000));
        assert_eq!(split_rtype(Rtype::Caa), (1, 0, 0b01000000));
    }

    #[test]
    fn rtype_bitmap_read_window() {
        let mut builder = RtypeBitmapBuilder::new_vec();
        builder.add(Rtype::A).unwrap();
        builder.add(Rtype::Caa).unwrap();
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
        let mut builder = RtypeBitmapBuilder::new_vec();
        builder.add(Rtype::Int(1234)).unwrap(); // 0x04D2
        builder.add(Rtype::A).unwrap(); // 0x0001
        builder.add(Rtype::Mx).unwrap(); // 0x000F
        builder.add(Rtype::Rrsig).unwrap(); // 0x002E
        builder.add(Rtype::Nsec).unwrap(); // 0x002F
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
    fn rtype_bitmap_iter() {
        let mut builder = RtypeBitmapBuilder::new_vec();
        let types = vec![
            Rtype::Ns, Rtype::Soa, Rtype::Mx, Rtype::Txt, Rtype::Rrsig,
            Rtype::Dnskey, Rtype::Nsec3param, Rtype::Spf, Rtype::Caa
        ];
        for t in types.iter()  {
            builder.add(*t).unwrap();
        }

        let bitmap = builder.finalize();
        let bitmap_types: Vec<_> = bitmap.iter().collect();
        assert_eq!(types, bitmap_types);
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

