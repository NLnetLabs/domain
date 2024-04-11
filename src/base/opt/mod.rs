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

#[macro_use]
mod macros;
opt_types! {
    algsig::{Dau<Octs>, Dhu<Octs>, N3u<Octs>};
    chain::{Chain<Name>};
    cookie::{Cookie};
    expire::{Expire};
    exterr::{ExtendedError<Octs>};
    keepalive::{TcpKeepalive};
    keytag::{KeyTag<Octs>};
    nsid::{Nsid<Octs>};
    padding::{Padding<Octs>};
    subnet::{ClientSubnet};
}

//============ Module Content ================================================

use super::cmp::CanonicalOrd;
use super::header::Header;
use super::iana::{Class, OptRcode, OptionCode, Rtype};
use super::name::{Dname, ToDname};
use super::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use super::record::{Record, Ttl};
use super::wire::{Compose, Composer, FormError, ParseError};
use crate::utils::base16;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::{fmt, hash, mem};
use octseq::builder::{EmptyBuilder, OctetsBuilder, ShortBuf};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;

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
pub struct Opt<Octs: ?Sized> {
    octets: Octs,
}

impl Opt<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::OPT;
}

impl<Octs: EmptyBuilder> Opt<Octs> {
    /// Creates empty OPT record data.
    pub fn empty() -> Self {
        Self {
            octets: Octs::empty(),
        }
    }
}

impl<Octs: AsRef<[u8]>> Opt<Octs> {
    /// Creates OPT record data from an octets sequence.
    ///
    /// The function checks whether the octets contain a sequence of
    /// options. It does not check whether the options themselves are valid.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError> {
        Opt::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates OPT record data from octets without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that the slice contains correctly encoded
    /// OPT record data. The data of the options themselves does not need to
    /// be correct.
    unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Self { octets }
    }

    /// Parses OPT record data from the beginning of a parser.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        Self::from_octets(parser.parse_octets(len)?)
    }
}

impl Opt<[u8]> {
    /// Creates OPT record data from an octets slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates OPT record data from an octets slice without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that the slice contains correctly encoded
    /// OPT record data. The data of the options themselves does not need to
    /// be correct.
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    /// Checks that the slice contains acceptable OPT record data.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        if slice.len() > usize::from(u16::MAX) {
            return Err(FormError::new("long record data").into());
        }
        let mut parser = Parser::from_ref(slice);
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16_be()?;
            parser.advance(len as usize)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Opt<Octs> {
    pub fn for_slice_ref(&self) -> Opt<&[u8]> {
        unsafe { Opt::from_octets_unchecked(self.octets.as_ref()) }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Opt<Octs> {
    /// Returns the length of the OPT record data.
    pub fn len(&self) -> usize {
        self.octets.as_ref().len()
    }

    /// Returns whether the OPT record data is empty.
    pub fn is_empty(&self) -> bool {
        self.octets.as_ref().is_empty()
    }

    /// Returns an iterator over options of a given type.
    ///
    /// The returned iterator will return only options represented by type
    /// `D` and quietly skip over all the others.
    pub fn iter<'s, Data>(&'s self) -> OptIter<'s, Octs, Data>
    where
        Octs: Octets,
        Data: ParseOptData<'s, Octs>,
    {
        OptIter::new(&self.octets)
    }

    /// Returns the first option of a given type if present.
    ///
    /// If trying to parse this first option fails, returns `None` as well.
    pub fn first<'s, Data>(&'s self) -> Option<Data>
    where
        Octs: Octets,
        Data: ParseOptData<'s, Octs>,
    {
        self.iter::<Data>().next()?.ok()
    }
}

impl<Octs: Composer> Opt<Octs> {
    /// Appends a new option to the OPT data.
    pub fn push<Opt: ComposeOptData + ?Sized>(
        &mut self,
        option: &Opt,
    ) -> Result<(), BuildDataError> {
        self.push_raw_option(option.code(), option.compose_len(), |target| {
            option.compose_option(target)
        })
    }

    /// Appends a raw option to the OPT data.
    ///
    /// The method will append an option with the given option code. The data
    /// of the option will be written via the closure `op`.
    pub fn push_raw_option<F>(
        &mut self,
        code: OptionCode,
        option_len: u16,
        op: F,
    ) -> Result<(), BuildDataError>
    where
        F: FnOnce(&mut Octs) -> Result<(), Octs::AppendError>,
    {
        LongOptData::check_len(
            self.octets
                .as_ref()
                .len()
                .saturating_add(usize::from(option_len)),
        )?;

        code.compose(&mut self.octets)?;
        option_len.compose(&mut self.octets)?;
        op(&mut self.octets)?;
        Ok(())
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Opt<SrcOcts>> for Opt<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Opt<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.octets).map(|octets| Opt { octets })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Opt<Other>> for Opt<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Opt<Other>) -> bool {
        self.octets.as_ref().eq(other.octets.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Opt<Octs> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octs, Other> PartialOrd<Opt<Other>> for Opt<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &Opt<Other>) -> Option<Ordering> {
        self.octets.as_ref().partial_cmp(other.octets.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for Opt<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.octets.as_ref().cmp(other.octets.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Opt<Other>> for Opt<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &Opt<Other>) -> Ordering {
        self.octets.as_ref().cmp(other.octets.as_ref())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for Opt<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.octets.as_ref().hash(state)
    }
}

//--- RecordData, ParseRecordData, and ComposeRecordData

impl<Octs: ?Sized> RecordData for Opt<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::OPT
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Opt<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::OPT {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ComposeRecordData for Opt<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(u16::try_from(self.octets.as_ref().len()).expect("long OPT"))
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Opt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // XXX TODO Print this properly.
        f.write_str("OPT ...")
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Opt<Octs> {
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
/// consists of the record header with the exception of the fiinal `rdlen`
/// field.
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
    #[must_use]
    pub fn for_record_slice(slice: &[u8]) -> &OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &*(slice.as_ptr() as *const OptHeader) }
    }

    /// Returns a mutable reference pointing into a record’s octets.
    pub fn for_record_slice_mut(slice: &mut [u8]) -> &mut OptHeader {
        assert!(slice.len() >= mem::size_of::<Self>());
        unsafe { &mut *(slice.as_mut_ptr() as *mut OptHeader) }
    }

    /// Returns the UDP payload size.
    ///
    /// Through this field a sender of a message can signal the maximum size
    /// of UDP payload the sender is able to handle when receiving messages.
    /// This value refers to the abilities of the sender’s DNS implementation,
    /// not such things as network MTUs. Which means that the largest UDP
    /// payload that can actually be sent back to the sender may be smaller.
    #[must_use]
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
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn dnssec_ok(&self) -> bool {
        self.inner[7] & 0x80 != 0
    }

    /// Sets the DNSSEC OK (DO) bit to the given value.
    pub fn set_dnssec_ok(&mut self, value: bool) {
        if value {
            self.inner[7] |= 0x80
        } else {
            self.inner[7] &= 0x7F
        }
    }

    pub fn compose<Target: OctetsBuilder + ?Sized>(
        self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.inner)
    }
}

impl Default for OptHeader {
    fn default() -> Self {
        OptHeader {
            inner: [0, 0, 41, 0, 0, 0, 0, 0, 0],
        }
    }
}

//------------ OptRecord -----------------------------------------------------

/// An entire OPT record.
///
/// Because the EDNS specificiation uses parts of the header of the OPT record
/// to convey some information, a special record type is necessary for OPT
/// records. You can convert a normal record with [`Opt`] record data into
/// an `OptRecord` via the [`from_record`][OptRecord::from_record] function.
#[derive(Clone)]
pub struct OptRecord<Octs> {
    /// The UDP payload size field from the record header.
    udp_payload_size: u16,

    /// The extended rcode.
    ext_rcode: u8,

    /// The EDNS version.
    version: u8,

    /// The EDNS flags.
    flags: u16,

    /// The record data.
    data: Opt<Octs>,
}

impl<Octs> OptRecord<Octs> {
    /// Converts a regular record into an OPT record
    pub fn from_record<N: ToDname>(record: Record<N, Opt<Octs>>) -> Self {
        OptRecord {
            udp_payload_size: record.class().to_int(),
            ext_rcode: (record.ttl().as_secs() >> 24) as u8,
            version: (record.ttl().as_secs() >> 16) as u8,
            flags: record.ttl().as_secs() as u16,
            data: record.into_data(),
        }
    }

    /// Converts the OPT record into a regular record.
    pub fn as_record(&self) -> Record<&'static Dname<[u8]>, Opt<&[u8]>>
    where
        Octs: AsRef<[u8]>,
    {
        Record::new(
            Dname::root_slice(),
            Class::from_int(self.udp_payload_size),
            Ttl::from_secs(
                u32::from(self.ext_rcode) << 24
                    | u32::from(self.version) << 16
                    | u32::from(self.flags),
            ),
            self.data.for_slice_ref(),
        )
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

    /// Sets the UDP payload size.
    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.udp_payload_size = value
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

    pub fn set_dnssec_ok(&mut self, value: bool) {
        if value {
            self.flags |= 0x8000;
        } else {
            self.flags &= !0x8000;
        }
    }

    /// Returns a reference to the raw options.
    pub fn opt(&self) -> &Opt<Octs> {
        &self.data
    }
}

impl<Octs: Composer> OptRecord<Octs> {
    /// Appends a new option to the OPT data.
    pub fn push<Opt: ComposeOptData + ?Sized>(
        &mut self,
        option: &Opt,
    ) -> Result<(), BuildDataError> {
        self.data.push(option)
    }

    /// Appends a raw option to the OPT data.
    ///
    /// The method will append an option with the given option code. The data
    /// of the option will be written via the closure `op`.
    pub fn push_raw_option<F>(
        &mut self,
        code: OptionCode,
        option_len: u16,
        op: F,
    ) -> Result<(), BuildDataError>
    where
        F: FnOnce(&mut Octs) -> Result<(), Octs::AppendError>,
    {
        self.data.push_raw_option(code, option_len, op)
    }
}

impl<Octs: EmptyBuilder> Default for OptRecord<Octs> {
    fn default() -> Self {
        Self {
            udp_payload_size: 0,
            ext_rcode: 0,
            version: 0,
            flags: 0,
            data: Opt::empty(),
        }
    }
}

//--- From

impl<Octs, N: ToDname> From<Record<N, Opt<Octs>>> for OptRecord<Octs> {
    fn from(record: Record<N, Opt<Octs>>) -> Self {
        Self::from_record(record)
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<OptRecord<SrcOcts>> for OptRecord<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: OptRecord<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Ok(OptRecord {
            udp_payload_size: source.udp_payload_size,
            ext_rcode: source.ext_rcode,
            version: source.version,
            flags: source.flags,
            data: Opt::try_octets_from(source.data)?,
        })
    }
}

//--- AsRef

impl<Octs> AsRef<Opt<Octs>> for OptRecord<Octs> {
    fn as_ref(&self) -> &Opt<Octs> {
        &self.data
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for OptRecord<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OptRecord")
            .field("udp_payload_size", &self.udp_payload_size)
            .field("ext_rcord", &self.ext_rcode)
            .field("version", &self.version)
            .field("flags", &self.flags)
            .field("data", &self.data)
            .finish()
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
    #[must_use]
    pub fn new(code: u16, len: u16) -> Self {
        OptionHeader { code, len }
    }

    /// Returns the option code.
    #[must_use]
    pub fn code(self) -> u16 {
        self.code
    }

    /// Returns the length of the option data.
    #[must_use]
    pub fn len(self) -> u16 {
        self.len
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        Ok(OptionHeader::new(
            parser.parse_u16_be()?,
            parser.parse_u16_be()?,
        ))
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
pub struct OptIter<'a, Octs: ?Sized, D> {
    /// A parser for the OPT record data.
    parser: Parser<'a, Octs>,

    /// The marker to remember which record data we use.
    marker: PhantomData<D>,
}

impl<'a, Octs, D> OptIter<'a, Octs, D>
where
    Octs: Octets + ?Sized,
    D: ParseOptData<'a, Octs>,
{
    /// Creates an iterator from a reference to the OPT record data.
    fn new(octets: &'a Octs) -> Self {
        OptIter {
            parser: Parser::from_ref(octets),
            marker: PhantomData,
        }
    }

    /// Returns the next item from the parser.
    ///
    /// Expects there to be another option available and will return a
    /// parse error otherwise. Return `Ok(None)` if the option type didn’t
    /// want to parse this option.
    fn next_step(&mut self) -> Result<Option<D>, ParseError> {
        let code = self.parser.parse_u16_be()?.into();
        let len = self.parser.parse_u16_be()? as usize;
        let mut parser = self.parser.parse_parser(len)?;
        let res = D::parse_option(code, &mut parser)?;
        if res.is_some() && parser.remaining() > 0 {
            return Err(ParseError::Form(FormError::new(
                "trailing data in option",
            )));
        }
        Ok(res)
    }
}

impl<'a, Octs, Data> Iterator for OptIter<'a, Octs, Data>
where
    Octs: Octets + ?Sized,
    Data: ParseOptData<'a, Octs>,
{
    type Item = Result<Data, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => {}
                Err(err) => {
                    // Advance to end so we’ll return None from now on.
                    self.parser.advance_to_end();
                    return Some(Err(err));
                }
            }
        }
        None
    }
}

//------------ OptData -------------------------------------------------------

/// A type representing an OPT option.
///
/// The type needs to be able to report the option code to use for the
/// encoding via the [`code`][Self::code] method.
pub trait OptData {
    /// Returns the option code associated with this option.
    fn code(&self) -> OptionCode;
}

//------------ ParseOptData --------------------------------------------------

/// An OPT option that can be parsed from the record data.
pub trait ParseOptData<'a, Octs: ?Sized>: OptData + Sized {
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
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError>;
}

//------------ ComposeOptData ------------------------------------------------

/// An OPT option that can be written to wire format.
pub trait ComposeOptData: OptData {
    fn compose_len(&self) -> u16;

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

//------------ UnknownOptData ------------------------------------------------

/// An OPT option in its raw form.
///
/// This type accepts any option type via its option code and raw data.
#[derive(Clone)]
pub struct UnknownOptData<Octs> {
    /// The option code for the option.
    code: OptionCode,

    /// The raw option data.
    data: Octs,
}

impl<Octs> UnknownOptData<Octs> {
    /// Creates a new option from the code and data.
    ///
    /// The function returns an error if `data` is longer than 65,535 octets.
    pub fn new(code: OptionCode, data: Octs) -> Result<Self, LongOptData>
    where
        Octs: AsRef<[u8]>,
    {
        LongOptData::check_len(data.as_ref().len())?;
        Ok(unsafe { Self::new_unchecked(code, data) })
    }

    /// Creates a new option data value without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that `data` is not longer than 65,535
    /// octets.
    pub unsafe fn new_unchecked(code: OptionCode, data: Octs) -> Self {
        Self { code, data }
    }

    /// Returns the option code of the option.
    pub fn code(&self) -> OptionCode {
        self.code
    }

    /// Returns a reference for to the option data.
    pub fn data(&self) -> &Octs {
        &self.data
    }

    /// Returns a slice of the option data.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.data.as_ref()
    }

    /// Returns a mutable slice of the option data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octs: AsMut<[u8]>,
    {
        self.data.as_mut()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<UnknownOptData<SrcOcts>>
    for UnknownOptData<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        src: UnknownOptData<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Self::new_unchecked(src.code, Octs::try_octets_from(src.data)?)
        })
    }
}
//--- AsRef and AsMut

impl<Octs> AsRef<Octs> for UnknownOptData<Octs> {
    fn as_ref(&self) -> &Octs {
        self.data()
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for UnknownOptData<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]>> AsMut<[u8]> for UnknownOptData<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- OptData etc.

impl<Octs: AsRef<[u8]>> OptData for UnknownOptData<Octs> {
    fn code(&self) -> OptionCode {
        self.code
    }
}

impl<'a, Octs> ParseOptData<'a, Octs> for UnknownOptData<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        Self::new(code, parser.parse_octets(parser.remaining())?)
            .map(Some)
            .map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]>> ComposeOptData for UnknownOptData<Octs> {
    fn compose_len(&self) -> u16 {
        self.data
            .as_ref()
            .len()
            .try_into()
            .expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.data.as_ref())
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for UnknownOptData<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        base16::display(self.data.as_ref(), f)
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for UnknownOptData<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("UnknownOptData")
            .field("code", &self.code)
            .field("data", &format_args!("{}", self))
            .finish()
    }
}

//============ Error Types ===================================================

//------------ LongOptData ---------------------------------------------------

/// The octets sequence to be used for option data is too long.
#[derive(Clone, Copy, Debug)]
pub struct LongOptData(());

impl LongOptData {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        "option data too long"
    }

    pub fn check_len(len: usize) -> Result<(), Self> {
        if len > usize::from(u16::MAX) {
            Err(Self(()))
        } else {
            Ok(())
        }
    }
}

impl From<LongOptData> for ParseError {
    fn from(src: LongOptData) -> Self {
        ParseError::form_error(src.as_str())
    }
}

impl fmt::Display for LongOptData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongOptData {}

//------------ BuildDataError ------------------------------------------------

/// An error happened while constructing an SVCB value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildDataError {
    /// The value would exceed the allowed length of a value.
    LongOptData,

    /// The underlying octets builder ran out of buffer space.
    ShortBuf,
}

impl BuildDataError {
    /// Converts the error into a `LongOptData` error for ‘endless’ buffers.
    ///
    /// # Panics
    ///
    /// This method will panic if the error is of the `ShortBuf` variant.
    pub fn unlimited_buf(self) -> LongOptData {
        match self {
            Self::LongOptData => LongOptData(()),
            Self::ShortBuf => panic!("ShortBuf on unlimited buffer"),
        }
    }
}

impl From<LongOptData> for BuildDataError {
    fn from(_: LongOptData) -> Self {
        Self::LongOptData
    }
}

impl<T: Into<ShortBuf>> From<T> for BuildDataError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for BuildDataError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::LongOptData => f.write_str("long option data"),
            Self::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildDataError {}

//============ Tests =========================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
pub(super) mod test {
    use super::*;
    use crate::base::rdata::test::{test_compose_parse, test_rdlen};
    use crate::base::record::ParsedRecord;
    use crate::base::{opt, MessageBuilder};
    use bytes::{Bytes, BytesMut};
    use core::fmt::Debug;
    use octseq::builder::infallible;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn opt_compose_parse_scan() {
        let rdata = Opt::from_octets("fo\x00\x03foo").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Opt::parse(parser));
    }

    #[test]
    fn opt_record_header() {
        let mut header = OptHeader::default();
        header.set_udp_payload_size(0x1234);
        header.set_rcode(OptRcode::BADVERS);
        header.set_version(0xbd);
        header.set_dnssec_ok(true);
        let mut buf = Vec::with_capacity(11);
        infallible(header.compose(&mut buf));
        infallible(0u16.compose(&mut buf));
        let mut buf = Parser::from_ref(buf.as_slice());
        let record = ParsedRecord::parse(&mut buf)
            .unwrap()
            .into_record::<Opt<_>>()
            .unwrap()
            .unwrap();
        let record = OptRecord::from_record(record);
        assert_eq!(record.udp_payload_size(), 0x1234);
        assert_eq!(record.ext_rcode, OptRcode::BADVERS.ext());
        assert_eq!(record.version(), 0xbd);
        assert!(record.dnssec_ok());
    }

    #[test]
    fn opt_iter() {
        use self::opt::cookie::{ClientCookie, Cookie};

        // Push two options and check that both are parseable
        let nsid = opt::Nsid::from_octets(&b"example"[..]).unwrap();
        let cookie = Cookie::new(
            ClientCookie::from_octets(1234u64.to_be_bytes()),
            None,
        );
        let msg = {
            let mut mb = MessageBuilder::new_vec().additional();
            mb.opt(|mb| {
                mb.push(&nsid)?;
                mb.push(&cookie)?;
                Ok(())
            })
            .unwrap();
            mb.into_message()
        };

        // Parse both into specialized types
        let opt = msg.opt().unwrap();
        assert_eq!(Some(Ok(nsid)), opt.opt().iter::<opt::Nsid<_>>().next());
        assert_eq!(Some(Ok(cookie)), opt.opt().iter::<opt::Cookie>().next());
    }

    pub fn test_option_compose_parse<In, F, Out>(data: &In, parse: F)
    where
        In: ComposeOptData + PartialEq<Out> + Debug,
        F: FnOnce(&mut Parser<Bytes>) -> Result<Out, ParseError>,
        Out: Debug,
    {
        let mut buf = BytesMut::new();
        infallible(data.compose_option(&mut buf));
        let buf = buf.freeze();
        assert_eq!(buf.len(), usize::from(data.compose_len()));
        let mut parser = Parser::from_ref(&buf);
        let parsed = (parse)(&mut parser).unwrap();
        assert_eq!(parser.remaining(), 0);
        assert_eq!(*data, parsed);
    }
}
