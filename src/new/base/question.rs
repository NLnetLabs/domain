//! DNS questions.

use core::fmt;

use domain_macros::*;

use crate::new::base::parse::split_without_compression;

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
        let (&qtype, rest) = split_without_compression(contents, rest)?;
        let (&qclass, rest) = split_without_compression(contents, rest)?;
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
///
/// IANA maintains [the registry][iana-qtype] of assignments for Question
/// Types.
///
/// [iana-qtype]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
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

impl QType {
    /// Create a new [`QType`].
    pub const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

//--- Associated Constants

known_values_define! (
    QType::(pub TYPES, pub MNEMONICS) = [
        /// The type of queries for [`A`](crate::new::rdata::A) records.
        "A" as A = Self::new(1),

        /// The type of queries for [`Ns`](crate::new::rdata::Ns) records.
        "NS" as NS = Self::new(2),

        /// The type of queries for [`CName`](crate::new::rdata::CName) records.
        "CNAME" as CNAME = Self::new(5),

        /// The type of queries for [`Soa`](crate::new::rdata::Soa) records.
        "SOA" as SOA = Self::new(6),

        /// The type of queries for [`Ptr`](crate::new::rdata::Ptr) records.
        "PTR" as PTR = Self::new(12),

        /// The type of queries for [`HInfo`](crate::new::rdata::HInfo) records.
        "HINFO" as HINFO = Self::new(13),

        /// The type of queries for [`Mx`](crate::new::rdata::Mx) records.
        "MX" as MX = Self::new(15),

        /// The type of queries for [`Txt`](crate::new::rdata::Txt) records.
        "TXT" as TXT = Self::new(16),

        /// The type of queries for [`Rp`](crate::new::rdata::Rp) records.
        "RP" as RP = Self::new(17),

        /// The type of queries for [`Aaaa`](crate::new::rdata::Aaaa) records.
        "AAAA" as AAAA = Self::new(28),

        /// The type of queries for [`Srv`](crate::new::rdata::Srv) records.
        "SRV" as SRV = Self::new(33),

        /// The type of queries for [`DName`](crate::new::rdata::DName) records.
        "DNAME" as DNAME = Self::new(39),

        /// The type of queries for [`Opt`](crate::new::rdata::Opt) records.
        "OPT" as OPT = Self::new(41),

        /// The type of queries for [`Ds`](crate::new::rdata::Ds) records.
        "DS" as DS = Self::new(43),

        /// The type of queries for [`Rrsig`](crate::new::rdata::Rrsig) records.
        "RRSIG" as RRSIG = Self::new(46),

        /// The type of queries for [`Nsec`](crate::new::rdata::Nsec) records.
        "NSEC" as NSEC = Self::new(47),

        /// The type of queries for [`DNSKey`](crate::new::rdata::DNSKey) records.
        "DNSKEY" as DNSKEY = Self::new(48),

        /// The type of queries for [`Nsec3`](crate::new::rdata::Nsec3) records.
        "NSEC3" as NSEC3 = Self::new(50),

        /// The type of queries for [`Nsec3Param`](crate::new::rdata::Nsec3Param) records.
        "NSEC3PARAM" as NSEC3PARAM = Self::new(51),

        /// The type of queries for `Cds` records.
        "CDS" as CDS = Self::new(59),

        /// The type of queries for `CDNSKey` records.
        "CDNSKEY" as CDNSKEY = Self::new(60),

        /// The type of queries for [`ZoneMD`](crate::new::rdata::ZoneMD) records.
        "ZONEMD" as ZONEMD = Self::new(63),

        /// The type of queries for `TSig` records.
        "TSIG" as TSIG = Self::new(250),

        //----- QType specific

        /// The type of requests for incremental zone transfers (IXFRs).
        "IXFR" as IXFR = Self::new(251),

        /// The type of requests for authoritative zone transfers (AXFRs).
        "AXFR" as AXFR = Self::new(252),

        /// The type of queries for all available records.
        "ANY" as ANY = Self::new(255),
    ];

);

//--- Conversion to and from 'u16'

known_values_from_and_to_primitive!(QType, u16);

//--- Formatting

/// Format a [`QType`] for debugging.
///
/// The output displays the mnemonic, if known, and the code associated to the
/// [`QType`].
///
/// ```
/// # use domain::new::base::QType;
/// // Known Question Type.
/// assert_eq!(
///     "QType::A(1)",
///     format!("{:?}", QType::A)
/// );
/// // Unknown Question Type.
/// assert_eq!(
///     "QType(42)",
///     format!("{:?}", QType::from(42))
/// );
/// ```
impl fmt::Debug for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "QType::{}({})", m, self.code),
            None => write!(f, "QType({})", self.code),
        }
    }
}

/// Format a [`QType`] in a human-readable way.
///
/// Return the mnemonic of [`QType`]. If [`QType`] is unknown, then the
/// returned string contains the type in the unknown format as defined in
/// [Section 5 of RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::QType;
/// // Known Question Type with mnemonic.
/// assert_eq!("A", format!("{}", QType::A));
/// // Unknown Question Type.
/// assert_eq!("TYPE265", format!("{}", QType::from(265)));
/// ```
///
/// [Section 5 of RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
impl fmt::Display for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "{}", m),
            None => write!(f, "TYPE{}", self.code),
        }
    }
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
///
/// IANA maintains [the registry][iana-qclass] of assignments for Question
/// Classes.
///
/// [iana-qclass]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
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

impl QClass {
    /// Create a new [`QClass`].
    pub const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }
}

//--- Associated Constants

known_values_define! (
    QClass::(pub CLASSES, pub MNEMONICS) = [
        /// The Internet class.
        "IN" as IN = Self::new(1),
        /// The CHAOS class.
        "CH" as CH = Self::new(3),
    ];
);

//--- Conversion to and from 'u16'

known_values_from_and_to_primitive!(QClass, u16);

//--- Formatting

/// Format a [`QClass`] for debugging.
///
/// The output displays the mnemonic, if known, and the code associated to the
/// [`QClass`].
///
/// ```
/// # use domain::new::base::QClass;
/// // Known Question Class.
/// assert_eq!(
///     "QClass::IN(1)",
///     format!("{:?}", QClass::IN)
/// );
/// // Unknown Question Class.
/// assert_eq!(
///     "QClass(42)",
///     format!("{:?}", QClass::from(42))
/// );
/// ```
impl fmt::Debug for QClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "QClass::{}({})", m, self.code),
            None => write!(f, "QClass({})", self.code),
        }
    }
}

/// Format a [`QClass`] in a human-readable way.
///
/// Return the mnemonic of [`QClass`]. If [`QClass`] is unknown, then the
/// returned string contains the class in the unknown format as defined in
/// [Section 5 of RFC3597].
///
/// The mnemonics are consolidated by [IANA].
///
/// ```
/// # use domain::new::base::QClass;
/// // Known Question Class with mnemonic.
/// assert_eq!("IN", format!("{}", QClass::IN));
/// // Unknown Question Class.
/// assert_eq!("CLASS42", format!("{}", QClass::from(42)));
/// ```
///
/// [Section 5 of RFC3597]: https://datatracker.ietf.org/doc/html/rfc3597#section-5
/// [IANA]: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
impl fmt::Display for QClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_mnemonic() {
            Some(m) => write!(f, "{}", m),
            None => write!(f, "CLASS{}", self.code),
        }
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

    #[test]
    fn test_qclass_from() {
        let qclass: QClass = 1.into();
        assert_eq!(qclass, QClass::IN);

        let number: u16 = qclass.into();
        assert_eq!(number, 1);
    }

    #[test]
    fn test_qtype_from() {
        let qtype: QType = 6.into();
        assert_eq!(qtype, QType::SOA);

        let number: u16 = qtype.into();
        assert_eq!(number, 6);
    }

    #[test]
    fn test_qtype_from_mnemonic() {
        assert_eq!(QType::from_mnemonic("A").unwrap(), QType::A);
        assert_eq!(QType::from_mnemonic("MX").unwrap(), QType::MX);
        // Make sure from_mnemonic does NOT parse unknown format.
        assert!(QType::from_mnemonic("TYPE10").is_none());
    }

    #[test]
    fn test_qclass_from_mnemonic() {
        assert_eq!(QClass::from_mnemonic("IN").unwrap(), QClass::IN);
        assert_eq!(QClass::from_mnemonic("CH").unwrap(), QClass::CH);
        // Make sure from_mnemonic does NOT parse unknown format.
        assert!(QClass::from_mnemonic("CLASS10").is_none());
    }
}
