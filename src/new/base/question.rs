//! DNS questions.

use core::fmt;

use domain_macros::*;

use super::{
    build::{BuildInMessage, NameCompressor, TruncationError},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseError, U16},
};

//----------- Question -------------------------------------------------------

/// A DNS question.
#[derive(
    Clone, Debug, BuildBytes, ParseBytes, SplitBytes, PartialEq, Eq, Hash,
)]
pub struct Question<N> {
    /// The domain name being requested.
    pub qname: N,

    /// The type of the requested records.
    pub qtype: QType,

    /// The class of the requested records.
    pub qclass: QClass,
}

//--- Construction

impl<N> Question<N> {
    /// Construct a new [`Question`].
    pub fn new(qname: N, qtype: QType, qclass: QClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

//--- Transformation

impl<N> Question<N> {
    /// Transform this type's generic parameters.
    pub fn transform<NN>(
        self,
        name_map: impl FnOnce(N) -> NN,
    ) -> Question<NN> {
        Question {
            qname: (name_map)(self.qname),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }

    /// Transform this type's generic parameters by reference.
    pub fn transform_ref<'a, NN>(
        &'a self,
        name_map: impl FnOnce(&'a N) -> NN,
    ) -> Question<NN> {
        Question {
            qname: (name_map)(&self.qname),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N> SplitMessageBytes<'a> for Question<N>
where
    N: SplitMessageBytes<'a>,
{
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (qname, rest) = N::split_message_bytes(contents, start)?;
        let (&qtype, rest) = <&QType>::split_message_bytes(contents, rest)?;
        let (&qclass, rest) = <&QClass>::split_message_bytes(contents, rest)?;
        Ok((Self::new(qname, qtype, qclass), rest))
    }
}

impl<'a, N> ParseMessageBytes<'a> for Question<N>
where
    // TODO: Reduce to 'ParseMessageBytes'.
    N: SplitMessageBytes<'a>,
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

impl<N> BuildInMessage for Question<N>
where
    N: BuildInMessage,
{
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self.qname.build_in_message(contents, start, compressor)?;
        // For more efficiency, copy the bytes manually.
        let end = start + 4;
        let bytes = contents.get_mut(start..end).ok_or(TruncationError)?;
        bytes[0..2].copy_from_slice(self.qtype.as_bytes());
        bytes[2..4].copy_from_slice(self.qclass.as_bytes());
        Ok(end)
    }
}

//----------- QType ----------------------------------------------------------

/// The type of a question.
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
pub struct QType {
    /// The type code.
    pub code: U16,
}

//--- Associated Constants

impl QType {
    /// Create a new [`QType`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of queries for [`A`](crate::new::rdata::A) records.
    pub const A: Self = Self::new(1);

    /// The type of queries for [`Ns`](crate::new::rdata::Ns) records.
    pub const NS: Self = Self::new(2);

    /// The type of queries for [`CName`](crate::new::rdata::CName) records.
    pub const CNAME: Self = Self::new(5);

    /// The type of queries for [`Soa`](crate::new::rdata::Soa) records.
    pub const SOA: Self = Self::new(6);

    /// The type of queries for [`Ptr`](crate::new::rdata::Ptr) records.
    pub const PTR: Self = Self::new(12);

    /// The type of queries for [`HInfo`](crate::new::rdata::HInfo) records.
    pub const HINFO: Self = Self::new(13);

    /// The type of queries for [`Mx`](crate::new::rdata::Mx) records.
    pub const MX: Self = Self::new(15);

    /// The type of queries for [`Txt`](crate::new::rdata::Txt) records.
    pub const TXT: Self = Self::new(16);

    /// The type of queries for [`Rp`](crate::new::rdata::Rp) records.
    pub const RP: Self = Self::new(17);

    /// The type of queries for [`Aaaa`](crate::new::rdata::Aaaa) records.
    pub const AAAA: Self = Self::new(28);

    /// The type of queries for [`DName`](crate::new::rdata::DName) records.
    pub const DNAME: Self = Self::new(39);

    /// The type of queries for [`Opt`](crate::new::rdata::Opt) records.
    pub const OPT: Self = Self::new(41);

    /// The type of queries for [`Ds`](crate::new::rdata::Ds) records.
    pub const DS: Self = Self::new(43);

    /// The type of queries for [`RRSig`](crate::new::rdata::RRSig) records.
    pub const RRSIG: Self = Self::new(46);

    /// The type of queries for [`NSec`](crate::new::rdata::NSec) records.
    pub const NSEC: Self = Self::new(47);

    /// The type of queries for [`DNSKey`](crate::new::rdata::DNSKey) records.
    pub const DNSKEY: Self = Self::new(48);

    /// The type of queries for [`NSec3`](crate::new::rdata::NSec3) records.
    pub const NSEC3: Self = Self::new(50);

    /// The type of queries for [`NSec3Param`](crate::new::rdata::NSec3Param) records.
    pub const NSEC3PARAM: Self = Self::new(51);

    /// The type of querios for `Cds` records.
    pub const CDS: Self = Self::new(59);

    /// The type of querios for `CDNSKey` records.
    pub const CDNSKEY: Self = Self::new(60);

    /// The type of querios for [`ZoneMD`](crate::new::rdata::ZoneMD) records.
    pub const ZONEMD: Self = Self::new(63);

    /// The type of querios for `TSig` records.
    pub const TSIG: Self = Self::new(250);

    /// The type of requests for incremental zone transfers (IXFRs).
    pub const IXFR: Self = Self::new(251);

    /// The type of requests for authoritative zone transfers (AXFRs).
    pub const AXFR: Self = Self::new(252);

    /// The type of queries for all available records.
    pub const ANY: Self = Self::new(255);
}

//--- Conversion to and from 'u16'

impl From<u16> for QType {
    fn from(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

impl From<QType> for u16 {
    fn from(value: QType) -> Self {
        value.code.get()
    }
}

//--- Formatting

impl fmt::Debug for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::A => "QType::A",
            Self::NS => "QType::NS",
            Self::CNAME => "QType::CNAME",
            Self::SOA => "QType::SOA",
            Self::PTR => "QType::PTR",
            Self::HINFO => "QType::HINFO",
            Self::MX => "QType::MX",
            Self::TXT => "QType::TXT",
            Self::RP => "QType::RP",
            Self::AAAA => "QType::AAAA",
            Self::DNAME => "QType::DNAME",
            Self::OPT => "QType::OPT",
            Self::DS => "QType::DS",
            Self::RRSIG => "QType::RRSIG",
            Self::NSEC => "QType::NSEC",
            Self::DNSKEY => "QType::DNSKEY",
            Self::NSEC3 => "QType::NSEC3",
            Self::NSEC3PARAM => "QType::NSEC3PARAM",
            Self::CDS => "QType::CDS",
            Self::CDNSKEY => "QType::CDNSKEY",
            Self::ZONEMD => "QType::ZONEMD",
            Self::TSIG => "QType::TSIG",
            Self::IXFR => "QType::IXFR",
            Self::AXFR => "QType::AXFR",
            Self::ANY => "QType::ANY",
            _ => return write!(f, "QType({})", self.code),
        })
    }
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
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
pub struct QClass {
    /// The class code.
    pub code: U16,
}

//--- Associated Constants

impl QClass {
    /// Create a new [`QClass`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of queries in the Internet class.
    pub const IN: Self = Self::new(1);

    /// The type of queries in the CHAOS class.
    pub const CH: Self = Self::new(3);
}

//--- Formatting

impl fmt::Debug for QClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::IN => "QClass::IN",
            Self::CH => "QClass::CH",
            _ => return write!(f, "QClass({})", self.code),
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::{QClass, QType, Question};

    use crate::new::base::{
        name::Name,
        wire::{BuildBytes, ParseBytes, ParseError, SplitBytes},
    };

    #[test]
    fn parse_build() {
        let bytes = b"\x03com\x00\x00\x01\x00\x01\x2A";
        let (question, rest) = <Question<&Name>>::split_bytes(bytes).unwrap();
        assert_eq!(question.qname.as_bytes(), b"\x03com\x00");
        assert_eq!(question.qtype, QType::A);
        assert_eq!(question.qclass, QClass::IN);
        assert_eq!(rest, b"\x2A");

        assert_eq!(<Question<&Name>>::parse_bytes(bytes), Err(ParseError));
        assert!(<Question<&Name>>::parse_bytes(&bytes[..9]).is_ok());

        let mut buffer = [0u8; 9];
        assert_eq!(
            question.build_bytes(&mut buffer),
            Ok(&mut [] as &mut [u8])
        );
        assert_eq!(buffer, &bytes[..9]);
    }
}
