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
    rfc5001::{Nsid<Octets>};
    rfc6975::{Dau<Octets>, Dhu<Octets>, N3u<Octets>};
    rfc7314::{Expire};
    rfc7828::{TcpKeepalive};
    rfc7830::{Padding};
    rfc7871::{ClientSubnet};
    rfc7873::{Cookie};
    rfc7901::{Chain<Octets>};
    rfc8145::{KeyTag<Octets>};
}


//============ Module Content ================================================

use core::{hash, fmt, mem, ops};
use core::cmp::Ordering;
use core::convert::TryInto;
use core::marker::PhantomData;
use super::iana::{OptionCode, OptRcode, Rtype};
use super::header::Header;
use super::name::ToDname;
use super::octets::{
    Compose, OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use super::rdata::RtypeRecordData;
use super::record::Record;


//------------ Opt -----------------------------------------------------------

/// OPT record data.
///
/// This type wraps a bytes value containing the record data of an OPT record.
#[derive(Clone)]
pub struct Opt<Octets> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> Opt<Octets> {
    /// Creates OPT record data from the underlying bytes value.
    ///
    /// The function checks whether the bytes value contains a sequence of
    /// options. It does not check whether the options itself are valid.
    pub fn from_octets(octets: Octets) -> Result<Self, ParseError> {
        let mut parser = Parser::from_ref(octets.as_ref());
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16()?;
            parser.advance(len as usize)?;
        }
        Ok(Opt { octets })
    }

    /// Returns an iterator over options of a given type.
    ///
    /// The returned iterator will return only options represented by type
    /// `D` and quietly skip over all the others.
    pub fn iter<D: ParseOptData<Octets>>(&self) -> OptIter<Octets, D>
    where Octets: Clone {
        OptIter::new(self.octets.clone())
    }
}


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Opt<Other>> for Opt<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &Opt<Other>) -> bool {
        self.octets.as_ref().eq(other.octets.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for Opt<Octets> { }


//--- PartialOrd and Ord

impl<Octets, Other> PartialOrd<Opt<Other>> for Opt<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(&self, other: &Opt<Other>) -> Option<Ordering> {
        self.octets.as_ref().partial_cmp(other.octets.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for Opt<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.octets.as_ref().cmp(other.octets.as_ref())
    }
}


//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Opt<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.octets.as_ref().hash(state)
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Opt<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        Self::from_octets(parser.parse_octets(len)?)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Opt<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.octets.as_ref())
    }
}


impl<Octets> RtypeRecordData for Opt<Octets> {
    const RTYPE: Rtype = Rtype::Opt;
}


//--- Display

impl<Octets: AsRef<[u8]>> fmt::Display for Opt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX TODO Print this properly.
        f.write_str("OPT ...")
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for Opt<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Opt(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
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
        u16::from_be_bytes(self.inner[3..5].try_into().unwrap())
    }

    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.inner[3..5].copy_from_slice(&value.to_be_bytes())
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
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.inner)
    }
}


//------------ OptRecord -----------------------------------------------------

/// An entire OPT record.
#[derive(Clone)]
pub struct OptRecord<Octets> {
    udp_payload_size: u16,
    ext_rcode: u8,
    version: u8,
    flags: u16,
    data: Opt<Octets>,
}

impl<Octets> OptRecord<Octets> {
    pub fn from_record<N: ToDname>(record: Record<N, Opt<Octets>>) -> Self {
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

    pub fn as_opt(&self) -> &Opt<Octets> {
        &self.data
    }
}


//--- From

impl<Octets, N: ToDname> From<Record<N, Opt<Octets>>> for OptRecord<Octets> {
    fn from(record: Record<N, Opt<Octets>>) -> Self {
        Self::from_record(record)
    }
}


//--- Deref and AsRef

impl<Octets> ops::Deref for OptRecord<Octets> {
    type Target = Opt<Octets>;

    fn deref(&self) -> &Opt<Octets> {
        &self.data
    }
}

impl<Octets> AsRef<Opt<Octets>> for OptRecord<Octets> {
    fn as_ref(&self) -> &Opt<Octets> {
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

impl<Octets: AsRef<[u8]>> Parse<Octets> for OptionHeader {
    fn parse(parser: &mut Parser<Octets>) -> Result<Self, ParseError> {
        Ok(OptionHeader::new(parser.parse_u16()?, parser.parse_u16()?))
    }

    fn skip(parser: &mut Parser<Octets>) -> Result<(), ParseError> {
        parser.advance(4)
    }
}

impl Compose for OptionHeader {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.code.compose(target)?;
            self.len.compose(target)
        })
    }
}


//------------ OptIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptIter<Octets, D: ParseOptData<Octets>> { 
    parser: Parser<Octets>,
    marker: PhantomData<D>
}

impl<Octets: AsRef<[u8]>, D: ParseOptData<Octets>> OptIter<Octets, D> {
    fn new(octets: Octets) -> Self {
        OptIter { parser: Parser::from_ref(octets), marker: PhantomData }
    }
}

impl<Octets, D> Iterator for OptIter<Octets, D>
where Octets: AsRef<[u8]>, D: ParseOptData<Octets> {
    type Item = Result<D, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => { }
                Err(err) => {
                    // Advance to end so we’ll return None from now on.
                    self.parser.advance_to_end();
                    return Some(Err(err))
                }
            }
        }
        None
    }
}

impl<Octets: AsRef<[u8]>, D: ParseOptData<Octets>> OptIter<Octets, D> {
    fn next_step(&mut self) -> Result<Option<D>, ParseError> {
        let code = self.parser.parse_u16()?.into();
        let len = self.parser.parse_u16()? as usize;
        self.parser.parse_block(len, |parser| {
            D::parse_option(code, parser)
        })
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData: Compose + Sized {
    fn code(&self) -> OptionCode;
}


//------------ ParseOptData --------------------------------------------------

pub trait ParseOptData<Octets>: OptData {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError>;
}


//------------ CodeOptData ---------------------------------------------------

pub trait CodeOptData {
    const CODE: OptionCode;
}

impl<T: CodeOptData + Compose> OptData for T {
    fn code(&self) -> OptionCode {
        Self::CODE
    }
}

impl<Octets, T> ParseOptData<Octets> for T
where T: CodeOptData + Parse<Octets> + Compose + Sized {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError> {
        if code == Self::CODE {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}


//------------ UnknownOptData ------------------------------------------------

#[derive(Clone, Debug)]
pub struct UnknownOptData<Octets> {
    code: OptionCode,
    data: Octets,
}

impl<Octets> UnknownOptData<Octets> {
    pub fn from_octets(code: OptionCode, data: Octets) -> Self {
        UnknownOptData { code, data }
    }

    pub fn code(&self) -> OptionCode {
        self.code
    }

    pub fn data(&self) -> &Octets {
        &self.data
    }
}


//--- Compose

impl<Octets: AsRef<[u8]>> Compose for UnknownOptData<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.data.as_ref())
    }
}


//--- OptData

impl<Octets: AsRef<[u8]>> OptData for UnknownOptData<Octets> {
    fn code(&self) -> OptionCode {
        self.code
    }
}

impl<Octets, Ref> ParseOptData<Ref> for UnknownOptData<Octets>
where Octets: AsRef<[u8]>, Ref: OctetsRef<Range = Octets> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<Ref>,
    ) -> Result<Option<Self>, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len)
            .map(|data| Some(Self::from_octets(code, data)))
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use crate::base::record::ParsedRecord;
    use super::*;

    #[test]
    fn opt_record_header() {
        let mut header = OptHeader::default();
        header.set_udp_payload_size(0x1234);
        header.set_rcode(OptRcode::BadVers);
        header.set_version(0xbd);
        header.set_dnssec_ok(true);
        let mut buf = Vec::with_capacity(11);
        header.compose(&mut buf).unwrap();
        0u16.compose(&mut buf).unwrap();
        let mut buf = Parser::from_ref(buf.as_slice());
        let record = ParsedRecord::parse(&mut buf)
            .unwrap().into_record::<Opt<_>>().unwrap().unwrap();
        let record = OptRecord::from_record(record);
        assert_eq!(record.udp_payload_size(), 0x1234);
        assert_eq!(record.ext_rcode, OptRcode::BadVers.ext());
        assert_eq!(record.version(), 0xbd);
        assert!(record.dnssec_ok());
    }
}

