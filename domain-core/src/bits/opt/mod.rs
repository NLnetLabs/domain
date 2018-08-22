// XXX TODO: Easier access to indivdual options.
// XXX TODO: Documentation and tests.
//
//! Record data for OPT records.
//!
//! Since DNS message headers are relatively short, the amount of information
//! that can be conveyed through them is very limited. In order to provide an
//! extensible means to transmit additional information, [RFC 6891] introduces
//! a resource record called OPT that can be added to the additional section
//! of a message. The record data in turn consists of a sequence of options.
//!
//! This module contains the types for working with both the OPT record and
//! its record data. It defines types for each of the currently defined
//! options. As with record data types in the [rdata] module, these are
//! arranged in sub-modules according to the RFC that defined them and then
//! re-exported here.
//! 
//! [RFC 6891]: https://tools.ietf.org/html/rfc6891
//! [rdata]: ../rdata/index.html


//============ Sub-modules and Re-exports ====================================

pub mod rfc5001;
pub mod rfc6975;
pub mod rfc7314;
pub mod rfc7828;
pub mod rfc7830;
pub mod rfc7871;
pub mod rfc7873;
pub mod rfc7901;
pub mod rfc8145;

pub use self::rfc5001::Nsid;
pub use self::rfc6975::{Dau, Dhu, N3u};
pub use self::rfc7314::Expire;
pub use self::rfc7828::TcpKeepalive;
pub use self::rfc7830::Padding;
pub use self::rfc7871::ClientSubnet;
pub use self::rfc7873::Cookie;
pub use self::rfc7901::Chain;
pub use self::rfc8145::KeyTag;


//============ Module Content ================================================

use std::mem;
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use ::iana::{OptionCode, OptRcode, Rtype};
use super::compose::{Compose, Compress, Compressor};
use super::header::Header;
use super::parse::{Parse, ParseAll, Parser, ShortBuf};
use super::rdata::RtypeRecordData;


//------------ Opt -----------------------------------------------------------

/// OPT record data.
///
/// This type wraps a bytes value containing the record data of an OPT record.
#[derive(Clone, Debug)]
pub struct Opt {
    bytes: Bytes,
}

impl Opt {
    /// Creates OPT record data from the underlying bytes value.
    ///
    /// The function checks whether the bytes value contains a sequence of
    /// options. It does not check whether the options itself are valid.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortBuf> {
        let mut parser = Parser::from_bytes(bytes);
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16()?;
            parser.advance(len as usize)?;
        }
        Ok(Opt { bytes: parser.unwrap() })
    }

    /// Returns an iterator over options of a given type.
    ///
    /// The returned iterator will return only options represented by type
    /// `D` and quietly skip over all the others.
    pub fn iter<D: OptData>(&self) -> OptIter<D> {
        OptIter::new(self.bytes.clone())
    }
}


//--- ParseAll, Compose, Compress

impl ParseAll for Opt {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Self::from_bytes(parser.parse_bytes(len)?)
    }
}

impl Compose for Opt {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.bytes.as_ref())
    }
}

impl Compress for Opt {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}

impl RtypeRecordData for Opt {
    const RTYPE: Rtype = Rtype::Opt;
}


//------------ OptHeader -----------------------------------------------------

/// The header of an OPT record.
///
/// The OPT record reappropriates the record header for encoding some
/// basic information. This type provides access to this information. It
/// consists of the record header accept for its `rdlen` field.
///
/// This is so that `OptBuilder` can safely deref to this type.
///
//    +------------+--------------+------------------------------+
//    | Field Name | Field Type   | Description                  |
//    +------------+--------------+------------------------------+
//    | NAME       | domain name  | MUST be 0 (root domain)      |
//    | TYPE       | u_int16_t    | OPT (41)                     |
//    | CLASS      | u_int16_t    | requestor's UDP payload size |
//    | TTL        | u_int32_t    | extended RCODE and flags     |
//    | RDLEN      | u_int16_t    | length of all RDATA          |
//    | RDATA      | octet stream | {attribute,value} pairs      |
//    +------------+--------------+------------------------------+
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OptHeader {
    /// The bytes of the header.
    inner: [u8; 9],
}

impl OptHeader {
    pub fn for_record_slice(slice: &[u8]) -> &OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &*(slice.as_ptr() as *const OptHeader) }
    }

    pub fn for_record_slice_mut(slice: &mut [u8]) -> &mut OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &mut *(slice.as_ptr() as *mut OptHeader) }
    }

    pub fn udp_payload_size(&self) -> u16 {
        BigEndian::read_u16(&self.inner[3..])
    }

    pub fn set_udp_payload_size(&mut self, value: u16) {
        BigEndian::write_u16(&mut self.inner[3..], value)
    }

    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.inner[5])
    }

    pub fn set_rcode(&mut self, rcode: OptRcode) {
        self.inner[5] = rcode.ext()
    }

    pub fn version(&self) -> u8 {
        self.inner[6]
    }

    pub fn dnssec_ok(&self) -> bool {
        self.inner[7] & 0x80 != 0
    }

    pub fn set_dnssec_ok(&mut self, value: bool) {
        if value {
            self.inner[7] |= 0x80
        }
        else {
            self.inner[7] &= 0x7F
        }
    }
}

impl Default for OptHeader {
    fn default() -> Self {
        OptHeader { inner: [0, 0, 41, 0, 0, 0, 0, 0, 0] }
    }
}

impl Compose for OptHeader {
    fn compose_len(&self) -> usize {
        9
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.inner)
    }
}


//------------ OptionHeader --------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptionHeader {
    code: u16,
    len: u16,
}

#[allow(len_without_is_empty)]
impl OptionHeader {
    pub fn new(code: u16, len: u16) -> Self {
        OptionHeader { code, len }
    }

    pub fn code(&self) -> u16 {
        self.code
    }

    pub fn len(&self) -> u16 {
        self.len
    }
}

impl Parse for OptionHeader {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(OptionHeader::new(parser.parse_u16()?, parser.parse_u16()?))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        parser.advance(4)
    }
}

impl Compose for OptionHeader {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.code.compose(buf);
        self.len.compose(buf);
    }
}


//------------ OptIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptIter<D: OptData> { 
    parser: Parser,
    marker: PhantomData<D>
}

impl<D: OptData> OptIter<D> {
    fn new(bytes: Bytes) -> Self {
        OptIter { parser: Parser::from_bytes(bytes), marker: PhantomData }
    }
}

impl<D: OptData> Iterator for OptIter<D> {
    type Item = Result<D, D::ParseErr>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => { }
                Err(err) => return Some(Err(err)),
            }
        }
        None
    }
}

impl<D: OptData> OptIter<D> {
    fn next_step(&mut self) -> Result<Option<D>, D::ParseErr> {
        let code = self.parser.parse_u16().unwrap().into();
        let len = self.parser.parse_u16().unwrap() as usize;
        D::parse_option(code, &mut self.parser, len)
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData: Compose + Sized {
    type ParseErr;

    fn code(&self) -> OptionCode;

    fn parse_option(code: OptionCode, parser: &mut Parser, len: usize)
                    -> Result<Option<Self>, Self::ParseErr>;
}


//------------ CodeOptData ---------------------------------------------------

pub trait CodeOptData {
    const CODE: OptionCode;
}

impl<T: CodeOptData + ParseAll + Compose + Sized> OptData for T {
    type ParseErr = <Self as ParseAll>::Err;

    fn code(&self) -> OptionCode { Self::CODE }

    fn parse_option(code: OptionCode, parser: &mut Parser, len: usize)
                    -> Result<Option<Self>, Self::ParseErr> {
        if code == Self::CODE {
            Self::parse_all(parser, len).map(Some)
        }
        else {
            Ok(None)
        }
    }
}
