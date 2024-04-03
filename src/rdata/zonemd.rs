//! ZONEMD record data.
//!
//! The ZONEMD Resource Record conveys the digest data in the zone itself.
//!
//! [RFC 8976]: https://tools.ietf.org/html/rfc8976

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::scan::{Scan, Scanner};
use crate::base::serial::Serial;
use crate::base::wire::{Composer, ParseError};
use crate::utils::base16;
use core::cmp::Ordering;
use core::{fmt, hash};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

// section 2.2.4
const DIGEST_MIN_LEN: usize = 12;

/// The ZONEMD Resource Record conveys the digest data in the zone itself.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Zonemd<Octs: ?Sized> {
    serial: Serial,
    scheme: Scheme,
    algo: Algorithm,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "octseq::serde::SerializeOctets::serialize_octets",
            deserialize_with = "octseq::serde::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octs: octseq::serde::SerializeOctets",
                deserialize = "Octs: octseq::serde::DeserializeOctets<'de>",
            )
        )
    )]
    digest: Octs,
}

impl<Octs> Zonemd<Octs> {
    /// Create a Zonemd record data from provided parameters.
    pub fn new(
        serial: Serial,
        scheme: Scheme,
        algo: Algorithm,
        digest: Octs,
    ) -> Self {
        Self {
            serial,
            scheme,
            algo,
            digest,
        }
    }

    /// Get the serial field.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Get the scheme field.
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Get the hash algorithm field.
    pub fn algorithm(&self) -> Algorithm {
        self.algo
    }

    /// Get the digest field.
    pub fn digest(&self) -> &Octs {
        &self.digest
    }

    /// Parse the record data from wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let serial = Serial::parse(parser)?;
        let scheme = parser.parse_u8()?.into();
        let algo = parser.parse_u8()?.into();
        let len = parser.remaining();
        if len < DIGEST_MIN_LEN {
            return Err(ParseError::ShortInput);
        }
        let digest = parser.parse_octets(len)?;
        Ok(Self {
            serial,
            scheme,
            algo,
            digest,
        })
    }

    /// Parse the record data from zonefile format.
    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        let serial = Serial::scan(scanner)?;
        let scheme = u8::scan(scanner)?.into();
        let algo = u8::scan(scanner)?.into();
        let digest = scanner.convert_entry(base16::SymbolConverter::new())?;

        Ok(Self {
            serial,
            scheme,
            algo,
            digest,
        })
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Zonemd<Target>, Target::Error> {
        self.convert_octets()
    }

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Zonemd<Target>, Target::Error> {
        let Zonemd {
            serial,
            scheme,
            algo,
            digest,
        } = self;

        Ok(Zonemd {
            serial,
            scheme,
            algo,
            digest: digest.try_octets_into()?,
        })
    }
}

impl<Octs> RecordData for Zonemd<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Zonemd
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Zonemd<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            // serial + scheme + algorithm + digest_len
            u16::try_from(4 + 1 + 1 + self.digest.as_ref().len())
                .expect("long ZONEMD rdata"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.serial.into_int().to_be_bytes())?;
        target.append_slice(&[self.scheme.into()])?;
        target.append_slice(&[self.algo.into()])?;
        target.append_slice(self.digest.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

impl<Octs: AsRef<[u8]>> hash::Hash for Zonemd<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.serial.hash(state);
        self.scheme.hash(state);
        self.algo.hash(state);
        self.digest.as_ref().hash(state);
    }
}

impl<Octs, Other> PartialEq<Zonemd<Other>> for Zonemd<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Zonemd<Other>) -> bool {
        self.serial.eq(&other.serial)
            && self.scheme.eq(&other.scheme)
            && self.algo.eq(&other.algo)
            && self.digest.as_ref().eq(other.digest.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Zonemd<Octs> {}

// section 2.4
impl<Octs: AsRef<[u8]>> fmt::Display for Zonemd<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} ( ",
            self.serial,
            u8::from(self.scheme),
            u8::from(self.algo)
        )?;
        base16::display(&self.digest, f)?;
        write!(f, " )")
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for Zonemd<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Zonemd(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

impl<Octs, Other> PartialOrd<Zonemd<Other>> for Zonemd<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Zonemd<Other>) -> Option<Ordering> {
        match self.serial.partial_cmp(&other.serial) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.scheme.partial_cmp(&other.scheme) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.algo.partial_cmp(&other.algo) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.digest.as_ref().partial_cmp(other.digest.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Zonemd<Other>> for Zonemd<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Zonemd<Other>) -> Ordering {
        match self.serial.into_int().cmp(&other.serial.into_int()) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.scheme.cmp(&other.scheme) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.algo.cmp(&other.algo) {
            Ordering::Equal => {}
            other => return other,
        }
        self.digest.as_ref().cmp(other.digest.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for Zonemd<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.serial.into_int().cmp(&other.serial.into_int()) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.scheme.cmp(&other.scheme) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.algo.cmp(&other.algo) {
            Ordering::Equal => {}
            other => return other,
        }
        self.digest.as_ref().cmp(other.digest.as_ref())
    }
}

/// The data collation scheme.
///
/// This enumeration wraps an 8-bit unsigned integer that identifies the
/// methods by which data is collated and presented as input to the
/// hashing function.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Scheme {
    Reserved,
    Simple,
    Unassigned(u8),
    Private(u8),
}

impl From<Scheme> for u8 {
    fn from(s: Scheme) -> u8 {
        match s {
            Scheme::Reserved => 0,
            Scheme::Simple => 1,
            Scheme::Unassigned(n) => n,
            Scheme::Private(n) => n,
        }
    }
}

impl From<u8> for Scheme {
    fn from(n: u8) -> Self {
        match n {
            0 | 255 => Self::Reserved,
            1 => Self::Simple,
            2..=239 => Self::Unassigned(n),
            240..=254 => Self::Private(n),
        }
    }
}

/// The Hash Algorithm used to construct the digest.
///
/// This enumeration wraps an 8-bit unsigned integer that identifies
/// the cryptographic hash algorithm.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Algorithm {
    Reserved,
    Sha384,
    Sha512,
    Unassigned(u8),
    Private(u8),
}

impl From<Algorithm> for u8 {
    fn from(algo: Algorithm) -> u8 {
        match algo {
            Algorithm::Reserved => 0,
            Algorithm::Sha384 => 1,
            Algorithm::Sha512 => 2,
            Algorithm::Unassigned(n) => n,
            Algorithm::Private(n) => n,
        }
    }
}

impl From<u8> for Algorithm {
    fn from(n: u8) -> Self {
        match n {
            0 | 255 => Self::Reserved,
            1 => Self::Sha384,
            2 => Self::Sha512,
            3..=239 => Self::Unassigned(n),
            240..=254 => Self::Private(n),
        }
    }
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use crate::utils::base16::decode;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn zonemd_compose_parse_scan() {
        let serial = 2023092203;
        let scheme = 1.into();
        let algo = 241.into();
        let digest_str = "CDBE0DED9484490493580583BF868A3E95F89FC3515BF26ADBD230A6C23987F36BC6E504EFC83606F9445476D4E57FFB";
        let digest: Vec<u8> = decode(digest_str).unwrap();
        let rdata = Zonemd::new(serial.into(), scheme, algo, digest);
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Zonemd::parse(parser));
        test_scan(
            &[
                &serial.to_string(),
                &u8::from(scheme).to_string(),
                &u8::from(algo).to_string(),
                digest_str,
            ],
            Zonemd::scan,
            &rdata,
        );
    }

    #[cfg(feature = "zonefile")]
    #[test]
    fn zonemd_parse_zonefile() {
        use crate::base::Dname;
        use crate::rdata::ZoneRecordData;
        use crate::zonefile::inplace::{Entry, Zonefile};

        // section A.1
        let content = r#"
example.      86400  IN  SOA     ns1 admin 2018031900 (
                                 1800 900 604800 86400 )
              86400  IN  NS      ns1
              86400  IN  NS      ns2
              86400  IN  ZONEMD  2018031900 1 1 (
                                 c68090d90a7aed71
                                 6bc459f9340e3d7c
                                 1370d4d24b7e2fc3
                                 a1ddc0b9a87153b9
                                 a9713b3c9ae5cc27
                                 777f98b8e730044c )
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
"#;

        let mut zone = Zonefile::load(&mut content.as_bytes()).unwrap();
        zone.set_origin(Dname::root());
        while let Some(entry) = zone.next_entry().unwrap() {
            match entry {
                Entry::Record(record) => {
                    if record.rtype() != Rtype::Zonemd {
                        continue;
                    }
                    match record.into_data() {
                        ZoneRecordData::Zonemd(rd) => {
                            assert_eq!(2018031900, rd.serial().into_int());
                            assert_eq!(Scheme::Simple, rd.scheme());
                            assert_eq!(Algorithm::Sha384, rd.algorithm());
                        }
                        _ => panic!(),
                    }
                }
                _ => panic!(),
            }
        }
    }
}
