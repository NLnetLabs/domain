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
//! [rdata]: ../../rdata/index.html


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
/// This is the record data type for OPT records and can be used as the data
/// type parameter in [`Record`]. It simply wraps an octets sequence with all
/// the record data. It guarantees that the data contains a correctly
/// formatted sequence of options but doesn’t guarantee that the options
/// themselves are correct. You can iterate over options via the [`iter`]
/// method.
///
/// Since some of the information of the OPT record is transmitted in the
/// record header, a special type [`OptRecord`] exists, that contains all
/// the OPT data which is the preferred way of accessing this data.
///
/// [`iter`]: #method.iter
/// [`OptRecord`]: struct.OptRecord.html
#[derive(Clone)]
pub struct Opt<Octets> {
    octets: Octets,
}

impl<Octets: AsRef<[u8]>> Opt<Octets> {
    /// Creates OPT record data from an octets sequence.
    ///
    /// The function checks whether the octets contain a sequence of
    /// options. It does not check whether the options themselves are valid.
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
    pub fn iter<Data>(&self) -> OptIter<&Octets, Data>
    where
        for<'a> &'a Octets: OctetsRef,
        Data: for<'a> ParseOptData<&'a Octets>
    {
        OptIter::new(&self.octets)
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


//--- RtypeRecordData

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
    /// Returns a reference to an OPT header pointing into a record’s octets.
    pub fn for_record_slice(slice: &[u8]) -> &OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &*(slice.as_ptr() as *const OptHeader) }
    }

    /// Returns a mutable reference pointing into a record’s octets.
    pub fn for_record_slice_mut(slice: &mut [u8]) -> &mut OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &mut *(slice.as_ptr() as *mut OptHeader) }
    }

    /// Returns the UDP payload size.
    ///
    /// Through this field a sender of a message can signal the maximum size
    /// of UDP payload the sender is able to handle when receiving messages.
    /// This value refers to the abilities of the sender’s DNS implementation,
    /// not such things as network MTUs. Which means that the largest UDP
    /// payload that can actually be sent back to the sender may be smaller.
    pub fn udp_payload_size(&self) -> u16 {
        u16::from_be_bytes(self.inner[3..5].try_into().unwrap())
    }

    /// Sets the UDP payload size value.
    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.inner[3..5].copy_from_slice(&value.to_be_bytes())
    }

    /// Returns the extended rcode.
    ///
    /// Some of the bits of the rcode are stored in the regular message
    /// header. Such a header needs to be passed to the method.
    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.inner[5])
    }

    /// Sets the extend rcode of the OPT header.
    ///
    /// This method _only_ sets the upper bits of the rcode. The lower bits
    /// need to be set in the message header.
    pub fn set_rcode(&mut self, rcode: OptRcode) {
        self.inner[5] = rcode.ext()
    }

    /// Returns the EDNS version of the OPT header.
    ///
    /// Only EDNS version 0 is currently defined.
    pub fn version(&self) -> u8 {
        self.inner[6]
    }

    /// Sets the EDNS version of the OPT header.
    pub fn set_version(&mut self, version: u8) {
        self.inner[6] = version
    }

    /// Returns the value of the DNSSEC OK (DO) bit.
    ///
    /// By setting this bit, a resolver indicates that it is interested in
    /// also receiving the DNSSEC-related resource records necessary to
    /// validate an answer. The bit and the related procedures are defined in
    /// [RFC 3225].
    ///
    /// [RFC 3225]: https://tools.ietf.org/html/rfc3225
    pub fn dnssec_ok(&self) -> bool {
        self.inner[7] & 0x80 != 0
    }

    /// Sets the DNSSEC OK (DO) bit to the given value.
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
///
/// Because the EDNS specificiation uses parts of the header of the OPT record
/// to convey some information, a special record type is necessary for OPT
/// records. You can convert a normal record with [`Opt`] record data into
/// an `OptRecord` via the [`from_record`] function.
///
/// The type derefs to the [`Opt`] type and provides all its functionality
/// that way.
///
/// [`Opt`]: strait.Opt.html
/// [`from_record`]: #method.from_record
#[derive(Clone)]
pub struct OptRecord<Octets> {
    /// The UDP payload size field from the record header.
    udp_payload_size: u16,

    /// The extended rcode.
    ext_rcode: u8,

    /// The EDNS version.
    version: u8,

    /// The EDNS flags.
    flags: u16,

    /// The record data.
    data: Opt<Octets>,
}

impl<Octets> OptRecord<Octets> {
    /// Converts a regular record into an OPT record
    pub fn from_record<N: ToDname>(record: Record<N, Opt<Octets>>) -> Self {
        OptRecord {
            udp_payload_size: record.class().to_int(),
            ext_rcode: (record.ttl() >> 24) as u8,
            version: (record.ttl() >> 16) as u8,
            flags: record.ttl() as u16,
            data: record.into_data()
        }
    }

    /// Returns the UDP payload size.
    ///
    /// Through this field a sender of a message can signal the maximum size
    /// of UDP payload the sender is able to handle when receiving messages.
    /// This value refers to the abilities of the sender’s DNS implementation,
    /// not such things as network MTUs. Which means that the largest UDP
    /// payload that can actually be sent back to the sender may be smaller.
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// Returns the extended rcode.
    ///
    /// Some of the bits of the rcode are stored in the regular message
    /// header. Such a header needs to be passed to the method.
    pub fn rcode(&self, header: Header) -> OptRcode {
        OptRcode::from_parts(header.rcode(), self.ext_rcode)
    }

    /// Returns the EDNS version of the OPT header.
    ///
    /// Only EDNS version 0 is currently defined.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the value of the DNSSEC OK (DO) bit.
    ///
    /// By setting this bit, a resolver indicates that it is interested in
    /// also receiving the DNSSEC-related resource records necessary to
    /// validate an answer. The bit and the related procedures are defined in
    /// [RFC 3225].
    ///
    /// [RFC 3225]: https://tools.ietf.org/html/rfc3225
    pub fn dnssec_ok(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    /// Returns a reference to the raw options.
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

/// The header of an OPT option.
///
/// This header contains a 16 bit option code identifying the kind of option
/// we are dealing with and a 16 bit length describing the lenngth in octets
/// of the option data.
#[derive(Clone, Copy, Debug)]
pub struct OptionHeader {
    /// The option code.
    code: u16,

    /// The length of the option’s data in octets.
    len: u16,
}

#[allow(clippy::len_without_is_empty)]
impl OptionHeader {
    /// Creates a new option header from code and length.
    pub fn new(code: u16, len: u16) -> Self {
        OptionHeader { code, len }
    }

    /// Returns the option code.
    pub fn code(self) -> u16 {
        self.code
    }

    /// Returns the length of the option data.
    pub fn len(self) -> u16 {
        self.len
    }
}


//--- Parse and Compose

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

/// An iterator over the options of an OPT record.
///
/// The iterator is generic over a specific option type. It skips over all
/// options that this type does not want to parse. It returns a result that
/// is either a parsed option or a parse error. These errors are only for the
/// particular option. After such an error you can continue to iterate until
/// `None` indicates that you’ve reached the end of the record.
#[derive(Clone, Debug)]
pub struct OptIter<Ref: OctetsRef, D: ParseOptData<Ref>> { 
    /// A parser for the OPT record data.
    parser: Parser<Ref>,

    /// The marker to remember which record data we use.
    marker: PhantomData<D>
}

impl<Ref: OctetsRef, D: ParseOptData<Ref>> OptIter<Ref, D> {
    /// Creates an iterator from a reference to the OPT record data.
    fn new(octets: Ref) -> Self {
        OptIter { parser: Parser::from_ref(octets), marker: PhantomData }
    }

    /// Returns the next item from the parser.
    ///
    /// Expects there to be another option available and will return a
    /// parse error otherwise. Return `Ok(None)` if the option type didn’t
    /// want to parse this option.
    fn next_step(&mut self) -> Result<Option<D>, ParseError> {
        let code = self.parser.parse_u16()?.into();
        let len = self.parser.parse_u16()? as usize;
        self.parser.parse_block(len, |parser| {
            D::parse_option(code, parser)
        })
    }
}

impl<Ref, Data> Iterator for OptIter<Ref, Data>
where Ref: OctetsRef, Data: ParseOptData<Ref> {
    type Item = Result<Data, ParseError>;

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


//------------ OptData -------------------------------------------------------

/// A type representing an OPT option.
///
/// The type needs to be able to construct the encoded option data via the
/// [`Compose`] trait. In addition, it needs to be able report the option
/// code to use for the encoding via the [`code`] method.
///
/// [`code`]: #method.code
/// [`Compose`]: ../octets/trait.Compose.html
pub trait OptData: Compose + Sized {
    /// Returns the option code associated with this option.
    fn code(&self) -> OptionCode;
}


//------------ ParseOptData --------------------------------------------------

/// An OPT option that can be parsed from the record data.
pub trait ParseOptData<Octets>: OptData {
    /// Parses the option code data.
    ///
    /// The data is for an option of `code`. The function may decide whether
    /// it wants to parse data for that type. It should return `Ok(None)` if
    /// it doesn’t.
    ///
    /// The `parser` is positioned at the beginning of the option data and is
    /// is limited to the length of the data. The method only needs to parse
    /// as much data as it needs. The caller has to make sure to deal with
    /// data remaining in the parser.
    ///
    /// If the function doesn’t want to process the data, it must not touch
    /// the parser. In particual, it must not advance it.
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError>;
}


//------------ CodeOptData ---------------------------------------------------

/// A type for an OPT option for a single specific option code.
///
/// If an option can only ever process a single option, it can simply
/// implement [`Parse`] for parsing the data, [`Compose`] for composing the
/// data, and this trait to state the option code. [`OptData`] and
/// [`ParseOptData`] will then be available via blanket implementations.
///
/// [`Compose`]: ../octets/trait.Compose.html
/// [`Parse`]: ../octets/trait.Parse.html
/// [`OptData`]: trait.OptData.html
/// [`ParseOptData`]: trait.ParseOptData.html
pub trait CodeOptData {
    /// The option code for this option.
    const CODE: OptionCode;
}

impl<T: CodeOptData + Compose> OptData for T {
    fn code(&self) -> OptionCode {
        Self::CODE
    }
}

impl<Octets: AsRef<[u8]>, T> ParseOptData<Octets> for T
where T: CodeOptData + Parse<Octets> + Compose + Sized {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError> {
        if code == Self::CODE {
            Self::parse(parser).map(Some)
        }
        else {
            parser.advance_to_end();
            Ok(None)
        }
    }
}


//------------ UnknownOptData ------------------------------------------------

/// An OPT option in its raw form.
///
/// This type accepts any option type via its option code and raw data.
#[derive(Clone, Debug)]
pub struct UnknownOptData<Octets> {
    /// The option code for the option.
    code: OptionCode,

    /// The raw option data.
    data: Octets,
}

impl<Octets> UnknownOptData<Octets> {
    /// Creates a new option from the code and data.
    pub fn from_octets(code: OptionCode, data: Octets) -> Self {
        UnknownOptData { code, data }
    }

    /// Returns the option code of the option.
    pub fn code(&self) -> OptionCode {
        self.code
    }

    /// Returns a reference for to the option data.
    pub fn data(&self) -> &Octets {
        &self.data
    }

    /// Returns a mutable reference to the option data.
    pub fn data_mut(&mut self) -> &mut Octets {
        &mut self.data
    }

    /// Returns a slice of the option data.
    pub fn as_slice(&self) -> &[u8]
    where Octets: AsRef<[u8]> {
        self.data.as_ref()
    }

    /// Returns a mutable slice of the option data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where Octets: AsMut<[u8]> {
        self.data.as_mut()
    }
}


//--- Deref and DerefMut

impl<Octets> ops::Deref for UnknownOptData<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        self.data()
    }
}

impl<Octets> ops::DerefMut for UnknownOptData<Octets> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data_mut()
    }
}


//--- AsRef and AsMut

impl<Octets> AsRef<Octets> for UnknownOptData<Octets> {
    fn as_ref(&self) -> &Octets {
        self.data()
    }
}

impl<Octets> AsMut<Octets> for UnknownOptData<Octets> {
    fn as_mut(&mut self) -> &mut Octets {
        self.data_mut()
    }
}

impl<Octets: AsRef<[u8]>> AsRef<[u8]> for UnknownOptData<Octets> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octets: AsMut<[u8]>> AsMut<[u8]> for UnknownOptData<Octets> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
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
#[cfg(feature = "std")]
mod test {
    use std::vec::Vec;
    use crate::base::record::ParsedRecord;
    use super::*;
    use crate::base::{MessageBuilder, opt};

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

    #[test]
    fn opt_iter() {
        // Push two options and check that both are parseable
        let nsid = opt::Nsid::from_octets(&b"example"[..]);
        let cookie = opt::Cookie::new(1234u64.to_be_bytes());
        let msg = {
            let mut mb = MessageBuilder::new_vec().additional();
            mb.opt(|mb| {
                mb.push(&nsid)?;
                mb.push(&cookie)?;
                Ok(())
            }).unwrap();
            mb.into_message()
        };

        // Parse both into specialized types
        let opt = msg.opt().unwrap();
        assert_eq!(Some(Ok(nsid)), opt.iter::<opt::Nsid<_>>().next());
        assert_eq!(Some(Ok(cookie)), opt.iter::<opt::Cookie>().next());
    }
}

