//! Record data for OPT records.
//!
//! OPT records are meta records used by EDNS to convey additional data about
//! clients, servers, and the query being performed. Because these records are
//! fundamental for modern DNS operations, they are here instead of in the
//! `rdata` module and the types defined for operating on them differ from
//! how other record types are handled.

use std::mem;
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use ::iana::{OptionCode, OptRcode, Rtype};
use super::compose::{Composable, Compressable, Compressor};
use super::error::ShortBuf;
use super::header::Header;
use super::parse::Parser;
use super::rdata::RecordData;


pub mod rfc5001;
pub mod rfc6975;
pub mod rfc7314;
pub mod rfc7828;
pub mod rfc7830;
pub mod rfc7871;
pub mod rfc7873;
pub mod rfc7901;
pub mod rfc8145;


//------------ Opt -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Opt {
    bytes: Bytes,
}

impl Opt {
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortBuf> {
        let mut parser = Parser::from_bytes(bytes);
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16()?;
            parser.advance(len as usize)?;
        }
        Ok(Opt { bytes: parser.unwrap() })
    }

    pub fn iter<D: OptData>(&self) -> OptIter<D> {
        OptIter::new(self.bytes.clone())
    }
}

impl RecordData for Opt {
    type ParseErr = ShortBuf;

    fn rtype(&self) -> Rtype {
        Rtype::Opt
    }

    fn parse(rtype: Rtype, rdlen: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if rtype != Rtype::Opt {
            return Ok(None)
        }
        Self::from_bytes(parser.parse_bytes(rdlen)?).map(Some)
    }
}

impl Composable for Opt {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.bytes.as_ref())
    }
}

impl Compressable for Opt {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
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

    pub fn rcode(&self, header: &Header) -> OptRcode {
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
        OptHeader { inner: [0, 41, 0, 0, 0, 0, 0, 0, 0] }
    }
}

impl Composable for OptHeader {
    fn compose_len(&self) -> usize {
        9
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.inner)
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
        D::parse(code, len, &mut self.parser)
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData: Composable + Sized {
    type ParseErr;

    fn code(&self) -> OptionCode;

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr>;
}


//------------ OptionParseError ---------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OptionParseError {
    InvalidLength(usize),
    ShortBuf,
}

impl From<ShortBuf> for OptionParseError {
    fn from(_: ShortBuf) -> Self {
        OptionParseError::ShortBuf
    }
}

