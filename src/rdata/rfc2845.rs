//! Record data from [RFC 2845]: TSIG records.
//!
//! This RFC defines the TSIG record type used for signing DNS messages.
//!
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Rtype, TsigRcode};
use crate::base::name::{ParsedDname, ToDname};
use crate::base::octets::{
    Compose, OctetsBuilder, OctetsFrom, OctetsRef, Parse, ParseError, Parser, ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
use crate::utils::base64;
use core::cmp::Ordering;
use core::{fmt, hash};
#[cfg(feature = "std")]
use std::time::SystemTime;

//------------ Tsig ----------------------------------------------------------

#[derive(Clone)]
pub struct Tsig<O, N> {
    /// The signature algorithm as a domain name.
    algorithm: N,

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
    mac: O,

    /// Original message ID.
    original_id: u16,

    /// TSIG response code.
    error: TsigRcode,

    /// Other.
    ///
    /// This is normally empty unless a BADTIME error happened. In wire
    /// format, it is encoded as a unsigned 16 bit integer followed by that
    /// many octets.
    other: O,
}

impl<O, N> Tsig<O, N> {
    /// Creates a new TSIG record from its components.
    ///
    /// See the access methods for an explanation of these components.
    ///
    /// # Panics
    ///
    /// Since `time_signed` is actually a 48 bit integer, the function will
    /// panic of the upper 16 bits are not all 0.
    pub fn new(
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

    /// Returns whether the record is valid right now.
    ///
    /// The method checks whether the current system time is within [`fudge`]
    /// seconds of the [`time_signed`].
    ///
    /// [`fudge`]: #method.fudge
    /// [`time_signed`]: #method.time_signed
    #[cfg(feature = "std")]
    pub fn is_valid_now(&self) -> bool {
        Time48::now().eq_fudged(self.time_signed, self.fudge.into())
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets, Name, SrcName> OctetsFrom<Tsig<SrcOctets, SrcName>> for Tsig<Octets, Name>
where
    Octets: OctetsFrom<SrcOctets>,
    Name: OctetsFrom<SrcName>,
{
    fn octets_from(source: Tsig<SrcOctets, SrcName>) -> Result<Self, ShortBuf> {
        Ok(Tsig::new(
            Name::octets_from(source.algorithm)?,
            source.time_signed,
            source.fudge,
            Octets::octets_from(source.mac)?,
            source.original_id,
            source.error,
            Octets::octets_from(source.other)?,
        ))
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

//--- Parse, ParseAll, Compose, and Compress

impl<Ref: OctetsRef> Parse<Ref> for Tsig<Ref::Range, ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let algorithm = ParsedDname::parse(parser)?;
        let time_signed = Time48::parse(parser)?;
        let fudge = u16::parse(parser)?;
        let mac_size = u16::parse(parser)?;
        let mac = parser.parse_octets(mac_size as usize)?;
        let original_id = u16::parse(parser)?;
        let error = TsigRcode::parse(parser)?;
        let other_len = u16::parse(parser)?;
        let other = parser.parse_octets(other_len as usize)?;
        Ok(Tsig {
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        ParsedDname::skip(parser)?;
        Time48::skip(parser)?;
        u16::skip(parser)?;
        let mac_size = u16::parse(parser)?;
        parser.advance(mac_size as usize)?;
        u16::skip(parser)?;
        TsigRcode::skip(parser)?;
        let other_len = u16::parse(parser)?;
        parser.advance(other_len as usize)?;
        Ok(())
    }
}

impl<O: AsRef<[u8]>, N: Compose> Compose for Tsig<O, N> {
    fn compose<T: OctetsBuilder>(&self, target: &mut T) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.algorithm.compose(buf)?;
            self.time_signed.compose(buf)?;
            self.fudge.compose(buf)?;
            (self.mac.as_ref().len() as u16).compose(buf)?;
            buf.append_slice(self.mac.as_ref())?;
            self.original_id.compose(buf)?;
            self.error.compose(buf)?;
            (self.other.as_ref().len() as u16).compose(buf)?;
            buf.append_slice(self.other.as_ref())
        })
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

//--- RtypeRecordData

impl<O, N> RtypeRecordData for Tsig<O, N> {
    const RTYPE: Rtype = Rtype::Tsig;
}

//------------ Time48 --------------------------------------------------------

/// A 48-bit Unix timestamp.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
        self.0.saturating_sub(fudge) <= other.0 && self.0.saturating_add(fudge) >= other.0
    }
}

//--- From

impl From<Time48> for u64 {
    fn from(value: Time48) -> u64 {
        value.0
    }
}

//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for Time48 {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 6];
        parser.parse_buf(&mut buf)?;
        Ok(Time48::from_slice(&buf))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance(6)
    }
}

impl Compose for Time48 {
    fn compose<T: OctetsBuilder>(&self, target: &mut T) -> Result<(), ShortBuf> {
        target.append_slice(&self.into_octets())
    }
}

//--- Display

impl fmt::Display for Time48 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}
