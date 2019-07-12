use std::fmt;
use std::cmp::Ordering;
use bytes::{BufMut, Bytes};
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::{DigestAlg, Rtype, SecAlg};
use crate::master::scan::{CharSource, Scan, ScanError, Scanner};
use crate::utils::base64;
use crate::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use super::RtypeRecordData;

//------------ Cdnskey --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cdnskey {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    public_key: Bytes,
}

impl Cdnskey {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Bytes
    ) -> Self {
        Cdnskey {
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


//--- CanonicalOrd

impl CanonicalOrd for Cdnskey {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Cdnskey {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ParseAllError::ShortField);
        }
        Ok(Self::new(
            u16::parse(parser)?,
            u8::parse(parser)?,
            SecAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?,
        ))
    }
}

impl Compose for Cdnskey {
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

impl Compress for Cdnskey {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Cdnskey {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?,
        ))
    }
}

impl fmt::Display for Cdnskey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}


//--- RecordData

impl RtypeRecordData for Cdnskey {
    const RTYPE: Rtype = Rtype::Cdnskey;
}


//------------ Cds -----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cds {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    digest: Bytes,
}

impl Cds {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Bytes
    ) -> Self {
        Cds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
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

impl CanonicalOrd for Cds {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- ParseAll, Compose, and Compress

impl ParseAll for Cds {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            return Err(ShortBuf);
        }
        Ok(Self::new(
            u16::parse(parser)?,
            SecAlg::parse(parser)?,
            DigestAlg::parse(parser)?,
            Bytes::parse_all(parser, len - 4)?,
        ))
    }
}

impl Compose for Cds {
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

impl Compress for Cds {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Display

impl Scan for Cds {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>) -> Result<Self, ScanError> {
        Ok(Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.scan_hex_words(Ok)?,
        ))
    }
}

impl fmt::Display for Cds {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.key_tag, self.algorithm, self.digest_type
        )?;
        for ch in self.digest() {
            write!(f, "{:02x}", ch)?
        }
        Ok(())
    }
}


//--- RtypeRecordData

impl RtypeRecordData for Cds {
    const RTYPE: Rtype = Rtype::Cds;
}

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Cdnskey, Cds};
}
