//! Record data from [RFC 2845].
//!
//! This RFC defines the TSIG record type used for signing DNS messages.
//!
//! [RFC 2845]: https://tools.ietf.org/html/rfc2845

use std::fmt;
use std::time::SystemTime;
use bytes::{BufMut, Bytes};
use crate::compose::{Compose, Compress, Compressor};
use crate::iana::{Rtype, TsigRcode};
use crate::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use crate::utils::base64;
use super::RtypeRecordData;


//------------ Tsig ----------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Tsig<N> {
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
    mac: Bytes,

    /// Original message ID.
    original_id: u16,

    /// TSIG response code.
    error: TsigRcode,

    /// Other.
    ///
    /// This is normally empty unless a BADTIME error happened. In wire
    /// format, it is encoded as a unsigned 16 bit integer followed by that
    /// many octets.
    other: Bytes,
}

impl<N> Tsig<N> {
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
        mac: Bytes,
        original_id: u16,
        error: TsigRcode,
        other: Bytes
    ) -> Self {
        Tsig {
            algorithm, time_signed, fudge, mac, original_id, error, other
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
    pub fn mac(&self) -> &Bytes {
        &self.mac
    }

    /// Returns an octet slice containing the MAC.
    pub fn mac_slice(&self) -> &[u8] {
        self.mac.as_ref()
    }

    /// Converts the record data into the MAC.
    pub fn into_mac(self) -> Bytes {
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
    pub fn other(&self) -> &Bytes {
        &self.other
    }

    /// Returns the other bytes as the server time.
    ///
    /// If the other bytes field is exactly 6 bytes long, this methods
    /// returns it as a `u64` representation of the Unix time contained.
    pub fn other_time(&self) -> Option<Time48> {
        if self.other.len() == 6 {
            Some(Time48::from_slice(self.other.as_ref()))
        }
        else {
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
    pub fn is_valid_now(&self) -> bool {
        Time48::now().eq_fudged(self.time_signed, self.fudge.into())
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl<N: Parse> Parse for Tsig<N>
where N::Err: From<ShortBuf> {
    type Err = N::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let algorithm = N::parse(parser)?;
        let time_signed = Time48::parse(parser)?;
        let fudge = u16::parse(parser)?;
        let mac_size = u16::parse(parser)?;
        let mac = parser.parse_bytes(mac_size as usize)?;
        let original_id = u16::parse(parser)?;
        let error = TsigRcode::parse(parser)?;
        let other_len = u16::parse(parser)?;
        let other = parser.parse_bytes(other_len as usize)?;
        Ok(Tsig {
            algorithm, time_signed, fudge, mac, original_id, error, other
        })
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        N::skip(parser)?;
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

impl<N: ParseAll + Parse> ParseAll for Tsig<N>
where
    <N as ParseAll>::Err: From<<N as Parse>::Err>,
    <N as ParseAll>::Err: From<ParseAllError>,
    <N as Parse>::Err: From<ShortBuf>
{
    type Err = <N as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let mut tmp = parser.clone();
        let res = <Self as Parse>::parse(&mut tmp)?;
        if tmp.pos() - parser.pos() < len {
            Err(ParseAllError::TrailingData.into())
        }
        else if tmp.pos() - parser.pos() > len {
            Err(ParseAllError::ShortField.into())
        }
        else {
            parser.advance(len)?;
            Ok(res)
        }
    }
}
        
impl<N: Compose> Compose for Tsig<N> {
    fn compose_len(&self) -> usize {
        assert!(self.mac.len() <= usize::from(std::u16::MAX));
        assert!(self.other.len() <= usize::from(std::u16::MAX));
        self.algorithm.compose_len() + self.mac.len() + self.other.len() + 16
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        assert!(self.mac.len() <= usize::from(std::u16::MAX));
        assert!(self.other.len() <= usize::from(std::u16::MAX));
        self.algorithm.compose(buf);
        self.time_signed.compose(buf);
        self.fudge.compose(buf);
        (self.mac.len() as u16).compose(buf);
        self.mac.compose(buf);
        self.original_id.compose(buf);
        self.error.compose(buf);
        (self.other.len() as u16).compose(buf);
        self.other.compose(buf);
    }
}

impl<N: Compose> Compress for Tsig<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Display

impl<N: fmt::Display> fmt::Display for Tsig<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {} {} ", self.algorithm, self.time_signed, self.fudge)?;
        base64::display(&self.mac, f)?;
        write!(f, " {} {} \"", self.original_id, self.error)?;
        base64::display(&self.other, f)?;
        write!(f, "\"")
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Tsig<N> {
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
    pub fn now() -> Time48 {
        Self::from_u64(
            SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
                .expect("system time before Unix epoch")
                .as_secs()
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
            (u64::from(slice[0]) << 40) |
            (u64::from(slice[1]) << 32) |
            (u64::from(slice[2]) << 24) |
            (u64::from(slice[3]) << 16) |
            (u64::from(slice[4]) << 8) |
            (u64::from(slice[5]))
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

    /// Converts a value into a bytes value.
    pub fn into_bytes(self) -> Bytes {
        Bytes::from(self.into_octets().as_ref())
    }

    /// Returns whether the time is within a given period.
    ///
    /// Returns `true` iff `other` is at most `fudge` seconds before or after
    /// this value’s time.
    pub fn eq_fudged(self, other: Self, fudge: u64) -> bool {
        self.0.saturating_sub(fudge) <= other.0 &&
        self.0.saturating_add(fudge) >= other.0
    }
}


//--- From

impl From<Time48> for u64 {
    fn from(value: Time48) -> u64 {
        value.0
    }
}


//--- Parse and Compose

impl Parse for Time48 {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let mut buf = [0u8; 6];
        parser.parse_buf(&mut buf)?;
        Ok(Time48::from_slice(&buf))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        parser.advance(6)
    }
}

impl Compose for Time48 {
    fn compose_len(&self) -> usize {
        6
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.into_octets())
    }
}


//--- Display

impl fmt::Display for Time48 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

