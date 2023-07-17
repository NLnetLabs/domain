//! Record data from [RFC 2845]: TSIG records.
//!
//! This RFC defines the TSIG record type used for signing DNS messages.
//!
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Rtype, TsigRcode};
use crate::base::name::{FlattenInto, ParsedDname, ToDname};
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData
};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use crate::utils::base64;
use core::cmp::Ordering;
use core::{fmt, hash};
use octseq::builder::OctetsBuilder;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
#[cfg(feature = "std")]
use std::time::SystemTime;

//------------ Tsig ----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tsig<Octs, Name> {
    /// The signature algorithm as a domain name.
    algorithm: Name,

    /// The Unix epoch time at which the signature was created.
    ///
    /// Note that this is an unsigned 48 bit value in wire format.
    time_signed: Time48,

    /// Seconds of error perimitted in time signed.
    fudge: u16,

    /// MAC.
    ///
    /// In wire format, consists of a unsigned 16 bit integer containing the
    /// length followed by that many octets of actual MAC.
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
    mac: Octs,

    /// Original message ID.
    original_id: u16,

    /// TSIG response code.
    error: TsigRcode,

    /// Other.
    ///
    /// This is normally empty unless a BADTIME error happened. In wire
    /// format, it is encoded as a unsigned 16 bit integer followed by that
    /// many octets.
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
    other: Octs,
}

impl<O, N> Tsig<O, N> {
    /// Creates new TSIG record data from its components.
    ///
    /// See the access methods for an explanation of these components. The
    /// function will return an error if the wire format length of the record
    /// would exceed 65,535 octets.
    pub fn new(
        algorithm: N,
        time_signed: Time48,
        fudge: u16,
        mac: O,
        original_id: u16,
        error: TsigRcode,
        other: O,
    ) -> Result<Self, LongRecordData>
    where O: AsRef<[u8]>, N: ToDname {
        LongRecordData::check_len(
            6 // time_signed
            + 2 // fudge
            + 2 // MAC length
            + 2 // original ID
            + 2 // error
            + 2 // other length
            + usize::from(algorithm.compose_len()).checked_add(
                mac.as_ref().len()
            ).expect("long MAC").checked_add(
                other.as_ref().len()
            ).expect("long TSIG")
        )?;
        Ok(unsafe {
            Tsig::new_unchecked(
                algorithm, time_signed, fudge, mac, original_id, error, other,
            )
        })
    }

    /// Creates new TSIG record data without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that the wire format length of the
    /// created record will not exceed 65,535 octets.
    pub unsafe fn new_unchecked(
        algorithm: N,
        time_signed: Time48,
        fudge: u16,
        mac: O,
        original_id: u16,
        error: TsigRcode,
        other: O,
    ) -> Self {
        Tsig {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        }
    }

    /// Returns a reference to the algorithm name.
    ///
    /// TSIG encodes the algorithm used for keys and signatures as a domain
    /// name. It does, however, only use the format. No structure is used at
    /// all.
    pub fn algorithm(&self) -> &N {
        &self.algorithm
    }

    /// Returns the Unix time when the signature is created.
    ///
    /// Despite its type, this is actually a 48 bit number. The upper 16 bits
    /// will never be set.
    pub fn time_signed(&self) -> Time48 {
        self.time_signed
    }

    /// Return the number of seconds of offset from signing time permitted.
    ///
    /// When a signature is checked, the local system time needs to be within
    /// this many seconds from `time_signed` to be accepted.
    pub fn fudge(&self) -> u16 {
        self.fudge
    }

    /// Returns a reference to the bytes value containing the MAC.
    pub fn mac(&self) -> &O {
        &self.mac
    }

    /// Returns an octet slice containing the MAC.
    pub fn mac_slice(&self) -> &[u8]
    where
        O: AsRef<[u8]>,
    {
        self.mac.as_ref()
    }

    /// Converts the record data into the MAC.
    pub fn into_mac(self) -> O {
        self.mac
    }

    /// Returns the original message ID.
    ///
    /// Since the message ID is part of the signature generation but may be
    /// changed for a forwarded message, it is included in the TSIG record.
    pub fn original_id(&self) -> u16 {
        self.original_id
    }

    /// Returns the TSIG error.
    pub fn error(&self) -> TsigRcode {
        self.error
    }

    /// Returns a reference to the other bytes.
    ///
    /// This field is only used for BADTIME errors to return the server time.
    /// Otherwise it is empty.
    pub fn other(&self) -> &O {
        &self.other
    }

    /// Returns the other bytes as the server time.
    ///
    /// If the other bytes field is exactly 6 bytes long, this methods
    /// returns it as a `u64` representation of the Unix time contained.
    pub fn other_time(&self) -> Option<Time48>
    where
        O: AsRef<[u8]>,
    {
        if self.other.as_ref().len() == 6 {
            Some(Time48::from_slice(self.other.as_ref()))
        } else {
            None
        }
    }

    /// Returns whether the record is valid at the given time.
    ///
    /// The method checks whether the given time is within [`fudge`]
    /// seconds of the [`time_signed`].
    ///
    /// [`fudge`]: #method.fudge
    /// [`time_signed`]: #method.time_signed
    pub fn is_valid_at(&self, now: Time48) -> bool {
        now.eq_fudged(self.time_signed, self.fudge.into())
    }

    /// Returns whether the record is valid right now.
    ///
    /// The method checks whether the current system time is within [`fudge`]
    /// seconds of the [`time_signed`].
    ///
    /// [`fudge`]: #method.fudge
    /// [`time_signed`]: #method.time_signed
    #[cfg(feature = "std")]
    pub fn is_valid_now(&self) -> bool {
        self.is_valid_at(Time48::now())
    }

    pub(super) fn convert_octets<TOcts, TName>(
        self,
    ) -> Result<Tsig<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<O>,
        TName: OctetsFrom<N, Error = TOcts::Error>,
    {
        Ok(unsafe {
            Tsig::new_unchecked(
                self.algorithm.try_octets_into()?,
                self.time_signed,
                self.fudge,
                self.mac.try_octets_into()?,
                self.original_id,
                self.error,
                self.other.try_octets_into()?,
            )
        })
    }

    pub(super) fn flatten<TOcts, TName>(
        self,
    ) -> Result<Tsig<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<O>,
        N: FlattenInto<TName, AppendError = TOcts::Error>,
    {
        Ok(unsafe {
            Tsig::new_unchecked(
                self.algorithm.try_flatten_into()?,
                self.time_signed,
                self.fudge,
                self.mac.try_octets_into()?,
                self.original_id,
                self.error,
                self.other.try_octets_into()?,
            )
        })
    }
}

impl<Octs> Tsig<Octs, ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let algorithm = ParsedDname::parse(parser)?;
        let time_signed = Time48::parse(parser)?;
        let fudge = u16::parse(parser)?;
        let mac_size = u16::parse(parser)?;
        let mac = parser.parse_octets(mac_size as usize)?;
        let original_id = u16::parse(parser)?;
        let error = TsigRcode::parse(parser)?;
        let other_len = u16::parse(parser)?;
        let other = parser.parse_octets(other_len as usize)?;
        Ok(unsafe {
            Tsig::new_unchecked(
                algorithm, time_signed, fudge, mac, original_id, error, other,
            )
        })
    }
}

//--- OctetsFrom and FlattenInto

impl<Octs, SrcOctets, Name, SrcName> OctetsFrom<Tsig<SrcOctets, SrcName>>
    for Tsig<Octs, Name>
where
    Octs: OctetsFrom<SrcOctets>,
    Name: OctetsFrom<SrcName>,
    Octs::Error: From<Name::Error>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Tsig<SrcOctets, SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Tsig::new_unchecked(
                Name::try_octets_from(source.algorithm)?,
                source.time_signed,
                source.fudge,
                Octs::try_octets_from(source.mac)?,
                source.original_id,
                source.error,
                Octs::try_octets_from(source.other)?,
            )
        })
    }
}

impl<Octs, TOcts, Name, TName> FlattenInto<Tsig<TOcts, TName>>
    for Tsig<Octs, Name>
where
    TOcts: OctetsFrom<Octs>,
    Name: FlattenInto<TName, AppendError = TOcts::Error>
{
    type AppendError = TOcts::Error;

    fn try_flatten_into(
        self
    ) -> Result<Tsig<TOcts, TName>, Self::AppendError > {
        self.flatten()
    }
}


//--- PartialEq and Eq

impl<O, OO, N, NN> PartialEq<Tsig<OO, NN>> for Tsig<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Tsig<OO, NN>) -> bool {
        self.algorithm.name_eq(&other.algorithm)
            && self.time_signed == other.time_signed
            && self.fudge == other.fudge
            && self.mac.as_ref().eq(other.mac.as_ref())
            && self.original_id == other.original_id
            && self.error == other.error
            && self.other.as_ref().eq(other.other.as_ref())
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Eq for Tsig<O, N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<O, OO, N, NN> PartialOrd<Tsig<OO, NN>> for Tsig<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Tsig<OO, NN>) -> Option<Ordering> {
        match self.algorithm.name_cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match self.time_signed.partial_cmp(&other.time_signed) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.fudge.partial_cmp(&other.fudge) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.mac.as_ref().partial_cmp(other.mac.as_ref()) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.original_id.partial_cmp(&other.original_id) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.error.partial_cmp(&other.error) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.other.as_ref().partial_cmp(other.other.as_ref())
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Ord for Tsig<O, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.algorithm.name_cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.time_signed.cmp(&other.time_signed) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.fudge.cmp(&other.fudge) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.mac.as_ref().cmp(other.mac.as_ref()) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.original_id.cmp(&other.original_id) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.error.cmp(&other.error) {
            Ordering::Equal => {}
            other => return other,
        }
        self.other.as_ref().cmp(other.other.as_ref())
    }
}

impl<O, OO, N, NN> CanonicalOrd<Tsig<OO, NN>> for Tsig<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn canonical_cmp(&self, other: &Tsig<OO, NN>) -> Ordering {
        match self.algorithm.composed_cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.time_signed.cmp(&other.time_signed) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.fudge.cmp(&other.fudge) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.mac.as_ref().len().cmp(&other.mac.as_ref().len()) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.mac.as_ref().cmp(other.mac.as_ref()) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.original_id.cmp(&other.original_id) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.error.cmp(&other.error) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.other.as_ref().len().cmp(&other.other.as_ref().len()) {
            Ordering::Equal => {}
            other => return other,
        }
        self.other.as_ref().cmp(other.other.as_ref())
    }
}

//--- Hash

impl<O: AsRef<[u8]>, N: hash::Hash> hash::Hash for Tsig<O, N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.time_signed.hash(state);
        self.fudge.hash(state);
        self.mac.as_ref().hash(state);
        self.original_id.hash(state);
        self.error.hash(state);
        self.other.as_ref().hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<O, N> RecordData for Tsig<O, N> {
    fn rtype(&self) -> Rtype {
        Rtype::Tsig
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Tsig<Octs::Range<'a>, ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Tsig {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>, Name: ToDname> ComposeRecordData
    for Tsig<Octs, Name>
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            6 // time_signed
            + 2 // fudge
            + 2 // MAC length
            + 2 // original ID
            + 2 // error
            + 2 // other length
            + self.algorithm.compose_len().checked_add(
                u16::try_from(self.mac.as_ref().len()).expect("long MAC")
            ).expect("long MAC").checked_add(
                u16::try_from(self.other.as_ref().len()).expect("long TSIG")
            ).expect("long TSIG"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.algorithm.compose(target)?;
        self.time_signed.compose(target)?;
        self.fudge.compose(target)?;
        u16::try_from(self.mac.as_ref().len())
            .expect("long MAC")
            .compose(target)?;
        target.append_slice(self.mac.as_ref())?;
        self.original_id.compose(target)?;
        self.error.compose(target)?;
        u16::try_from(self.other.as_ref().len())
            .expect("long MAC")
            .compose(target)?;
        target.append_slice(self.other.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display and Debug

impl<O: AsRef<[u8]>, N: fmt::Display> fmt::Display for Tsig<O, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}. {} {} ",
            self.algorithm, self.time_signed, self.fudge
        )?;
        base64::display(&self.mac, f)?;
        write!(f, " {} {} \"", self.original_id, self.error)?;
        base64::display(&self.other, f)?;
        write!(f, "\"")
    }
}

impl<O: AsRef<[u8]>, N: fmt::Debug> fmt::Debug for Tsig<O, N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Tsig")
            .field("algorithm", &self.algorithm)
            .field("time_signed", &self.time_signed)
            .field("fudge", &self.fudge)
            .field("mac", &self.mac.as_ref())
            .field("original_id", &self.original_id)
            .field("error", &self.error)
            .field("other", &self.other.as_ref())
            .finish()
    }
}

//------------ Time48 --------------------------------------------------------

/// A 48-bit Unix timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Time48(u64);

impl Time48 {
    /// Returns the timestamp of the current moment.
    ///
    /// The funtion will panic if for whatever reason the current moment is
    /// too far in the future to fit into this type. For a correctly set
    /// clock, this will happen in December 8,921,556, so should be fine.
    #[cfg(feature = "std")]
    pub fn now() -> Time48 {
        Self::from_u64(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time before Unix epoch")
                .as_secs(),
        )
    }

    /// Creates a value from a 64 bit integer.
    ///
    /// The upper 16 bits of the arument must be zero or else this function
    /// panics. This is also why we don’t implement `From`.
    pub fn from_u64(value: u64) -> Self {
        assert!(value & 0xFFFF_0000_0000_0000 == 0);
        Time48(value)
    }

    /// Creates a value from an octet slice.
    ///
    /// This slice should contain the octets of the value in network byte
    /// order.
    ///
    /// # Panics
    ///
    /// The function panics if the slice is shorter than 6 octets.
    fn from_slice(slice: &[u8]) -> Self {
        Time48(
            (u64::from(slice[0]) << 40)
                | (u64::from(slice[1]) << 32)
                | (u64::from(slice[2]) << 24)
                | (u64::from(slice[3]) << 16)
                | (u64::from(slice[4]) << 8)
                | (u64::from(slice[5])),
        )
    }

    /// Converts a value into its wire format.
    ///
    /// Returns the octets of the encoded value in network byte order.
    pub fn into_octets(self) -> [u8; 6] {
        let mut res = [0u8; 6];
        res[0] = (self.0 >> 40) as u8;
        res[1] = (self.0 >> 32) as u8;
        res[2] = (self.0 >> 24) as u8;
        res[3] = (self.0 >> 16) as u8;
        res[4] = (self.0 >> 8) as u8;
        res[5] = self.0 as u8;
        res
    }

    /// Returns whether the time is within a given period.
    ///
    /// Returns `true` iff `other` is at most `fudge` seconds before or after
    /// this value’s time.
    pub fn eq_fudged(self, other: Self, fudge: u64) -> bool {
        self.0.saturating_sub(fudge) <= other.0
            && self.0.saturating_add(fudge) >= other.0
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        let mut buf = [0u8; 6];
        parser.parse_buf(&mut buf)?;
        Ok(Time48::from_slice(&buf))
    }

    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.into_octets())
    }
}

//--- From

impl From<Time48> for u64 {
    fn from(value: Time48) -> u64 {
        value.0
    }
}

//--- Display

impl fmt::Display for Time48 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Dname;
    use crate::base::rdata::test::{test_compose_parse, test_rdlen};
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    fn tsig_compose_parse_scan() {
        let rdata = Tsig::new(
            Dname::<Vec<u8>>::from_str("key.example.com.").unwrap(),
            Time48::now(),
            12,
            "foo",
            13,
            TsigRcode::BadCookie,
            "",
        ).unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Tsig::parse(parser));
    }
}
