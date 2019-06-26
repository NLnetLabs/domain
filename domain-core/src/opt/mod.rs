// XXX TODO: Easier access to individual options.
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
//
// All of these are in a macro. The macro also defines `AllOptData`.

#[macro_use] mod macros;
opt_types!{
    rfc5001::{Nsid};
    rfc6975::{Dau, Dhu, N3u};
    rfc7314::{Expire};
    rfc7828::{TcpKeepalive};
    rfc7830::{Padding};
    rfc7871::{ClientSubnet};
    rfc7873::{Cookie};
    rfc7901::{Chain};
    rfc8145::{KeyTag};
}


//============ Module Content ================================================

use std::{fmt, mem, ops};
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use crate::iana::{OptionCode, OptRcode, Rtype};
use crate::compose::{Compose, Compress, Compressor};
use crate::header::Header;
use crate::name::ToDname;
use crate::parse::{Parse, ParseAll, Parser, ShortBuf};
use crate::rdata::RtypeRecordData;
use crate::record::Record;


//------------ Opt -----------------------------------------------------------

/// OPT record data.
///
/// This type wraps a bytes value containing the record data of an OPT record.
//
//  XXX Deriving PartialEq etc. might be wrong for some options. Have a look
//      at this again once we have proper option handling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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


//--- Display

impl fmt::Display for Opt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX TODO Print this properly.
        f.write_str("OPT ...")
    }
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

    pub fn set_version(&mut self, version: u8) {
        self.inner[6] = version
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


//------------ OptRecord -----------------------------------------------------

/// An entire OPT record.
#[derive(Clone, Debug)]
pub struct OptRecord {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: u16,
    data: Opt,
}

impl OptRecord {
    pub fn from_record<N: ToDname>(record: Record<N, Opt>) -> Self {
        OptRecord {
            udp_payload_size: record.class().to_int(),
            ext_rcode: (record.ttl() >> 24) as u8,
            version: (record.ttl() >> 16) as u8,
            flags: record.ttl() as u16,
            data: record.into_data()
        }
    }

    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.ext_rcode)
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn dnssec_ok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn as_opt(&self) -> &Opt {
        &self.data
    }
}


//--- From

impl<N: ToDname> From<Record<N, Opt>> for OptRecord {
    fn from(record: Record<N, Opt>) -> Self {
        Self::from_record(record)
    }
}


//--- Deref and AsRef

impl ops::Deref for OptRecord {
    type Target = Opt;

    fn deref(&self) -> &Opt {
        &self.data
    }
}

impl AsRef<Opt> for OptRecord {
    fn as_ref(&self) -> &Opt {
        &self.data
    }
}


//------------ OptionHeader --------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptionHeader {
    code: u16,
    len: u16,
}

#[allow(clippy::len_without_is_empty)]
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


//------------ UnknownOptData ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UnknownOptData {
    code: OptionCode,
    data: Bytes,
}

impl UnknownOptData {
    pub fn from_bytes(code: OptionCode, data: Bytes) -> Self {
        UnknownOptData { code, data }
    }

    pub fn code(&self) -> OptionCode {
        self.code
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }
}


//--- Compose

impl Compose for UnknownOptData {
    fn compose_len(&self) -> usize {
        self.data.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.data.as_ref())
    }
}


//--- OptData

impl OptData for UnknownOptData {
    type ParseErr = ShortBuf;

    fn code(&self) -> OptionCode {
        self.code
    }

    fn parse_option(
        code: OptionCode,
        parser: &mut Parser,
        len: usize
    ) -> Result<Option<Self>, Self::ParseErr> {
        parser.parse_bytes(len)
            .map(|data| Some(Self::from_bytes(code, data)))
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::record::ParsedRecord;

    #[test]
    fn opt_record_header() {
        let mut header = OptHeader::default();
        header.set_udp_payload_size(0x1234);
        header.set_rcode(OptRcode::BadVers);
        header.set_version(0xbd);
        header.set_dnssec_ok(true);
        let mut buf = Vec::with_capacity(11);
        header.compose(&mut buf);
        0u16.compose(&mut buf);
        let mut buf = Parser::from_bytes(buf.into());
        let record = ParsedRecord::parse(&mut buf).unwrap()
            .into_record::<Opt>().unwrap().unwrap();
        let record = OptRecord::from_record(record);
        assert_eq!(record.udp_payload_size(), 0x1234);
        assert_eq!(record.ext_rcode, OptRcode::BadVers.ext());
        assert_eq!(record.version(), 0xbd);
        assert!(record.dnssec_ok());
    }
}

