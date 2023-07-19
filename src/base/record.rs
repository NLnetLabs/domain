//! Resource Records.
//!
//! This module defines types and traits related to DNS resource records. The
//! most complete type is [`Record`] which contains a complete record for a
//! certain record type. [`RecordHeader`] contains the data from a record’s
//! header, the first couple of octets common to all records. Finally,
//! [`ParsedRecord`] is similar to [`Record`] but contains the record data
//! in its raw, encoded form.
//!
//! The [`AsRecord`] trait is used by the message builder to consider
//! different representations of records.
//!
//! [`AsRecord`]: trait.AsRecord.html
//! [`Record`]: struct.Record.html
//! [`RecordHeader`]: struct.RecordHeader.html
//! [`ParsedRecord`]: struct.ParsedRecord.html

use super::cmp::CanonicalOrd;
use super::iana::{Class, Rtype};
use super::name::{ParsedDname, ToDname};
use super::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use super::wire::{Compose, Composer, FormError, Parse, ParseError};
use core::cmp::Ordering;
use core::time::Duration;
use core::{fmt, hash};
use octseq::builder::ShortBuf;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use octseq::OctetsBuilder;

//------------ Record --------------------------------------------------------

/// A DNS resource record.
///
/// All information available through the DNS is stored in resource records.
/// They have a three part key of a domain name, resource record type, and
/// class. Data is arranged in a tree which is navigated using the domain
/// name. Each node in the tree carries a label, starting with the root
/// label as the top-most node. The tree is traversed by stepping through the
/// name from right to left, finding a child node carring the label of each
/// step. The domain name resulting from this traversal is part of the
/// record itself. It is called the *owner* of the record.
///
/// The record type describes the kind of data the record holds, such as IP
/// addresses. The class, finally, describes which sort of network the
/// information is for. The DNS was originally intended to be used for
/// networks other than the Internet as well. In practice, the only relevant
/// class is IN, the Internet. Note that each class has its own tree of nodes.
///
/// The payload of a resource record is its data. Its purpose, meaning, and
/// format is determined by the record type (technically, also its class).
/// For each unique three-part key there can be multiple resource records.
/// All these records for the same key are called *resource record sets,*
/// most often shortened to ‘RRset.’
///
/// There is one more piece of data: the TTL or time to live. This value
/// says how long a record remains valid before it should be refreshed from
/// its original source. The TTL is used to add caching
/// facilities to the DNS.
///
/// Values of the `Record` type represent one single resource record. Since
/// there are currently more than eighty record types—see [`Rtype`] for a
/// complete list—, the type is generic over a trait for record data. This
/// trait holds both the record type value and the record data as they are
/// inseparably entwined.
///
/// Because a record’s owner is a domain name, the `Record` type is
/// additionally generic over the domain name type is for it.
///
/// There is three ways to create a record value. First, you can make one
/// yourself using the [`new`] function. It will neatly take care of all
/// the generics through type inference. Secondly, you can parse a record
/// from an existing message. [`Message`] and its friends provide a way to
/// do that; see there for all the details. Finally, you can scan a record
/// from zone file format. See the crate’s
#[cfg_attr(feature = "zonefile", doc = "[zonefile][crate::zonefile]")]
#[cfg_attr(not(feature = "zonefile"), doc = "zonefile")]
/// module for that.
///
/// [`new`]: #method.new
/// [`Message`]: ../message/struct.Message.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
/// [`Rtype`]: ../../iana/enum.Rtype.html
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Record<Name, Data> {
    /// The owner of the record.
    owner: Name,

    /// The class of the record.
    class: Class,

    /// The time-to-live value of the record.
    ttl: Ttl,

    /// The record data. The value also specifies the record’s type.
    data: Data,
}

/// # Creation and Element Access
///
impl<Name, Data> Record<Name, Data> {
    /// Creates a new record from its parts.
    pub fn new(owner: Name, class: Class, ttl: Ttl, data: Data) -> Self {
        Record {
            owner,
            class,
            ttl,
            data,
        }
    }

    /// Creates a new record from a compatible record.
    ///
    /// This function only exists because the equivalent `From` implementation
    /// is currently not possible,
    pub fn from_record<NN, DD>(record: Record<NN, DD>) -> Self
    where
        Name: From<NN>,
        Data: From<DD>,
    {
        Self::new(
            record.owner.into(),
            record.class,
            record.ttl,
            record.data.into(),
        )
    }

    /// Returns a reference to the owner domain name.
    ///
    /// The owner of a record is the domain name that specifies the node in
    /// the DNS tree this record belongs to.
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Rtype
    where
        Data: RecordData,
    {
        self.data.rtype()
    }

    /// Returns the record class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Sets the record’s class.
    pub fn set_class(&mut self, class: Class) {
        self.class = class
    }

    /// Returns the record’s time-to-live.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Sets the record’s time-to-live.
    pub fn set_ttl(&mut self, ttl: Ttl) {
        self.ttl = ttl
    }

    /// Return a reference to the record data.
    pub fn data(&self) -> &Data {
        &self.data
    }

    /// Returns a mutable reference to the record data.
    pub fn data_mut(&mut self) -> &mut Data {
        &mut self.data
    }

    /// Trades the record for its record data.
    pub fn into_data(self) -> Data {
        self.data
    }

    /// Trades the record for its owner name and data.
    pub fn into_owner_and_data(self) -> (Name, Data) {
        (self.owner, self.data)
    }
}

/// Parsing and Composing
///
impl<Octs, Data> Record<ParsedDname<Octs>, Data> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Option<Self>, ParseError>
    where
        Data: ParseRecordData<'a, Src>,
    {
        let header = RecordHeader::parse(parser)?;
        header.parse_into_record(parser)
    }
}

impl<N: ToDname, D: RecordData + ComposeRecordData> Record<N, D> {
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_compressed_dname(&self.owner)?;
        self.data.rtype().compose(target)?;
        self.class.compose(target)?;
        self.ttl.compose(target)?;
        self.data.compose_len_rdata(target)
    }

    pub fn compose_canonical<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.owner.compose_canonical(target)?;
        self.data.rtype().compose(target)?;
        self.class.compose(target)?;
        self.ttl.compose(target)?;
        self.data.compose_canonical_len_rdata(target)
    }
}

//--- From

impl<N, D> From<(N, Class, u32, D)> for Record<N, D> {
    fn from((owner, class, ttl, data): (N, Class, u32, D)) -> Self {
        Self::new(owner, class, Ttl::from_secs(ttl), data)
    }
}

impl<N, D> From<(N, Class, Ttl, D)> for Record<N, D> {
    fn from((owner, class, ttl, data): (N, Class, Ttl, D)) -> Self {
        Self::new(owner, class, ttl, data)
    }
}

impl<N, D> From<(N, u32, D)> for Record<N, D> {
    fn from((owner, ttl, data): (N, u32, D)) -> Self {
        Self::new(owner, Class::In, Ttl::from_secs(ttl), data)
    }
}

//--- OctetsFrom
//
// XXX We don’t have blanket FromOctets for a type T into itself, so this may
//     not always work as expected. Not sure what we can do about it?

impl<Name, Data, SrcName, SrcData> OctetsFrom<Record<SrcName, SrcData>>
    for Record<Name, Data>
where
    Name: OctetsFrom<SrcName>,
    Data: OctetsFrom<SrcData>,
    Data::Error: From<Name::Error>,
{
    type Error = Data::Error;

    fn try_octets_from(
        source: Record<SrcName, SrcData>,
    ) -> Result<Self, Self::Error> {
        Ok(Record {
            owner: Name::try_octets_from(source.owner)?,
            class: source.class,
            ttl: source.ttl,
            data: Data::try_octets_from(source.data)?,
        })
    }
}

//--- PartialEq and Eq

impl<N, NN, D, DD> PartialEq<Record<NN, DD>> for Record<N, D>
where
    N: PartialEq<NN>,
    D: RecordData + PartialEq<DD>,
    DD: RecordData,
{
    fn eq(&self, other: &Record<NN, DD>) -> bool {
        self.owner == other.owner
            && self.class == other.class
            && self.data == other.data
    }
}

impl<N: Eq, D: RecordData + Eq> Eq for Record<N, D> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN, D, DD> PartialOrd<Record<NN, DD>> for Record<N, D>
where
    N: PartialOrd<NN>,
    D: RecordData + PartialOrd<DD>,
    DD: RecordData,
{
    fn partial_cmp(&self, other: &Record<NN, DD>) -> Option<Ordering> {
        match self.owner.partial_cmp(&other.owner) {
            Some(Ordering::Equal) => {}
            res => return res,
        }
        match self.class.partial_cmp(&other.class) {
            Some(Ordering::Equal) => {}
            res => return res,
        }
        self.data.partial_cmp(&other.data)
    }
}

impl<N, D> Ord for Record<N, D>
where
    N: Ord,
    D: RecordData + Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.owner.cmp(&other.owner) {
            Ordering::Equal => {}
            res => return res,
        }
        match self.class.cmp(&other.class) {
            Ordering::Equal => {}
            res => return res,
        }
        self.data.cmp(&other.data)
    }
}

impl<N, NN, D, DD> CanonicalOrd<Record<NN, DD>> for Record<N, D>
where
    N: ToDname,
    NN: ToDname,
    D: RecordData + CanonicalOrd<DD>,
    DD: RecordData,
{
    fn canonical_cmp(&self, other: &Record<NN, DD>) -> Ordering {
        // This sort order will keep all records of a zone together. Ie.,
        // all the records with the same zone and ending in a given name
        // form one sequence.
        match self.class.cmp(&other.class) {
            Ordering::Equal => {}
            res => return res,
        }
        match self.owner.name_cmp(&other.owner) {
            Ordering::Equal => {}
            res => return res,
        }
        match self.rtype().cmp(&other.rtype()) {
            Ordering::Equal => {}
            res => return res,
        }
        self.data.canonical_cmp(&other.data)
    }
}

//--- Hash

impl<Name, Data> hash::Hash for Record<Name, Data>
where
    Name: hash::Hash,
    Data: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.class.hash(state);
        self.ttl.hash(state);
        self.data.hash(state);
    }
}

//--- Display and Debug

impl<Name, Data> fmt::Display for Record<Name, Data>
where
    Name: fmt::Display,
    Data: RecordData + fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}. {} {} {} {}",
            self.owner,
            self.ttl.as_secs(),
            self.class,
            self.data.rtype(),
            self.data
        )
    }
}

impl<Name, Data> fmt::Debug for Record<Name, Data>
where
    Name: fmt::Debug,
    Data: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Record")
            .field("owner", &self.owner)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("data", &self.data)
            .finish()
    }
}

//------------ ComposeRecord -------------------------------------------------

/// A helper trait allowing construction of records on the fly.
///
/// The trait’s primary users arer the three record section buider type of
/// the [message builder] system. Their `push` methods accept anything that
/// implements this trait.
///
/// Implementations are provided for [`Record`] values and references. In
/// addition, a tuple of a domain name, class, TTL, and record data can be
/// used as this trait, saving the detour of constructing a record first.
/// Since the class is pretty much always `Class::In`, it can be left out in
/// this case.
///
/// [`Class::In`]: ../iana/class/enum.Class.html#variant.In
/// [`Record`]: struct.Record.html
pub trait ComposeRecord {
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

impl<'a, T: ComposeRecord> ComposeRecord for &'a T {
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        (*self).compose_record(target)
    }
}

impl<Name, Data> ComposeRecord for Record<Name, Data>
where
    Name: ToDname,
    Data: RecordData + ComposeRecordData,
{
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose(target)
    }
}

impl<Name, Data> ComposeRecord for (Name, Class, u32, Data)
where
    Name: ToDname,
    Data: RecordData + ComposeRecordData,
{
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Record::new(&self.0, self.1, Ttl::from_secs(self.2), &self.3)
            .compose(target)
    }
}

impl<Name, Data> ComposeRecord for (Name, Class, Ttl, Data)
where
    Name: ToDname,
    Data: RecordData + ComposeRecordData,
{
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Record::new(&self.0, self.1, self.2, &self.3).compose(target)
    }
}

impl<Name, Data> ComposeRecord for (Name, u32, Data)
where
    Name: ToDname,
    Data: RecordData + ComposeRecordData,
{
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Record::new(&self.0, Class::In, Ttl::from_secs(self.1), &self.2)
            .compose(target)
    }
}

impl<Name, Data> ComposeRecord for (Name, Ttl, Data)
where
    Name: ToDname,
    Data: RecordData + ComposeRecordData,
{
    fn compose_record<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Record::new(&self.0, Class::In, self.1, &self.2).compose(target)
    }
}

//------------ RecordHeader --------------------------------------------------

/// The header of a resource record.
///
/// This type encapsulates the common header of a resource record. It consists
/// of the owner, record type, class, TTL, and the length of the record data.
/// It is effectively a helper type for dealing with resource records encoded
/// in a DNS message.
///
/// See [`Record`] for more details about resource records.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordHeader<Name> {
    owner: Name,
    rtype: Rtype,
    class: Class,
    ttl: Ttl,
    rdlen: u16,
}

impl<Name> RecordHeader<Name> {
    /// Creates a new record header from its components.
    pub fn new(
        owner: Name,
        rtype: Rtype,
        class: Class,
        ttl: Ttl,
        rdlen: u16,
    ) -> Self {
        RecordHeader {
            owner,
            rtype,
            class,
            ttl,
            rdlen,
        }
    }
}

impl<'a, Octs: Octets + ?Sized> RecordHeader<ParsedDname<&'a Octs>> {
    fn deref_owner(&self) -> RecordHeader<ParsedDname<Octs::Range<'a>>> {
        RecordHeader {
            owner: self.owner.deref_octets(),
            rtype: self.rtype,
            class: self.class,
            ttl: self.ttl,
            rdlen: self.rdlen,
        }
    }
}

impl<Name> RecordHeader<Name> {
    /// Returns a reference to the owner of the record.
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// Returns the record type of the record.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Returns the class of the record.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Returns the TTL of the record.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Returns the data length of the record.
    pub fn rdlen(&self) -> u16 {
        self.rdlen
    }

    /// Converts the header into an actual record.
    pub fn into_record<Data>(self, data: Data) -> Record<Name, Data> {
        Record::new(self.owner, self.class, self.ttl, data)
    }
}

/// # Parsing and Composing
///
impl<Octs> RecordHeader<ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs>>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        RecordHeader::parse_ref(parser).map(|res| res.deref_owner())
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> RecordHeader<ParsedDname<&'a Octs>> {
    pub fn parse_ref(
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Self, ParseError> {
        Ok(RecordHeader::new(
            ParsedDname::parse_ref(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?,
            Ttl::parse(parser)?,
            parser.parse_u16_be()?,
        ))
    }
}

impl<Name> RecordHeader<Name> {
    /// Parses a record header and then skips over the data.
    ///
    /// If the function succeeds, the parser will be positioned right behind
    /// the end of the record.
    pub fn parse_and_skip<'a, Octs>(
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Self, ParseError>
    where
        Self: Parse<'a, Octs>,
        Octs: Octets,
    {
        let header = Self::parse(parser)?;
        match parser.advance(header.rdlen() as usize) {
            Ok(()) => Ok(header),
            Err(_) => Err(ParseError::ShortInput),
        }
    }
}

impl RecordHeader<()> {
    /// Parses only the record length and skips over all the other fields.
    fn parse_rdlen<Octs: Octets + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<u16, ParseError> {
        ParsedDname::skip(parser)?;
        parser.advance(
            (Rtype::COMPOSE_LEN + Class::COMPOSE_LEN + u32::COMPOSE_LEN)
                .into(),
        )?;
        u16::parse(parser)
    }
}

impl<Octs> RecordHeader<ParsedDname<Octs>> {
    /// Parses the remainder of the record and returns it.
    ///
    /// The method assumes that the parsers is currently positioned right
    /// after the end of the record header. If the record data type `D`
    /// feels capable of parsing a record with a header of `self`, the
    /// method will parse the data and return a full `Record<D>`. Otherwise,
    /// it skips over the record data.
    pub fn parse_into_record<'a, Src, Data>(
        self,
        parser: &mut Parser<'a, Src>,
    ) -> Result<Option<Record<ParsedDname<Octs>, Data>>, ParseError>
    where
        Src: AsRef<[u8]> + ?Sized,
        Data: ParseRecordData<'a, Src>,
    {
        let mut parser = parser.parse_parser(self.rdlen as usize)?;
        let res = Data::parse_rdata(self.rtype, &mut parser)?
            .map(|data| Record::new(self.owner, self.class, self.ttl, data));
        if res.is_some() && parser.remaining() > 0 {
            return Err(ParseError::Form(FormError::new(
                "trailing data in option",
            )));
        }
        Ok(res)
    }
}

impl<Name: ToDname> RecordHeader<Name> {
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        buf: &mut Target,
    ) -> Result<(), Target::AppendError> {
        buf.append_compressed_dname(&self.owner)?;
        self.rtype.compose(buf)?;
        self.class.compose(buf)?;
        self.ttl.compose(buf)?;
        self.rdlen.compose(buf)
    }

    pub fn compose_canonical<Target: Composer + ?Sized>(
        &self,
        buf: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.owner.compose_canonical(buf)?;
        self.rtype.compose(buf)?;
        self.class.compose(buf)?;
        self.ttl.compose(buf)?;
        self.rdlen.compose(buf)
    }
}

//--- PartialEq and Eq

impl<Name, NName> PartialEq<RecordHeader<NName>> for RecordHeader<Name>
where
    Name: ToDname,
    NName: ToDname,
{
    fn eq(&self, other: &RecordHeader<NName>) -> bool {
        self.owner.name_eq(&other.owner)
            && self.rtype == other.rtype
            && self.class == other.class
            && self.ttl == other.ttl
            && self.rdlen == other.rdlen
    }
}

impl<Name: ToDname> Eq for RecordHeader<Name> {}

//--- PartialOrd and Ord
//
// No CanonicalOrd because that doesn’t really make sense.

impl<Name, NName> PartialOrd<RecordHeader<NName>> for RecordHeader<Name>
where
    Name: ToDname,
    NName: ToDname,
{
    fn partial_cmp(&self, other: &RecordHeader<NName>) -> Option<Ordering> {
        match self.owner.name_cmp(&other.owner) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match self.rtype.partial_cmp(&other.rtype) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.class.partial_cmp(&other.class) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.ttl.partial_cmp(&other.ttl) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.rdlen.partial_cmp(&other.rdlen)
    }
}

impl<Name: ToDname> Ord for RecordHeader<Name> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.owner.name_cmp(&other.owner) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.rtype.cmp(&other.rtype) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.class.cmp(&other.class) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.ttl.cmp(&other.ttl) {
            Ordering::Equal => {}
            other => return other,
        }
        self.rdlen.cmp(&other.rdlen)
    }
}

//--- Hash

impl<Name: hash::Hash> hash::Hash for RecordHeader<Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.owner.hash(state);
        self.rtype.hash(state);
        self.class.hash(state);
        self.ttl.hash(state);
        self.rdlen.hash(state);
    }
}

//--- Debug

impl<Name: fmt::Debug> fmt::Debug for RecordHeader<Name> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RecordHeader")
            .field("owner", &self.owner)
            .field("rtype", &self.rtype)
            .field("class", &self.class)
            .field("ttl", &self.ttl)
            .field("rdlen", &self.rdlen)
            .finish()
    }
}

//------------ ParsedRecord --------------------------------------------------

/// A raw record parsed from a message.
///
/// A value of this type contains the record header and the raw record data.
/// It is mainly used as an intermediary type when turning raw message data
/// into [`Record`]s.
///
/// It allows access to the header only but can be traded for a real record
/// of a specific type of [`ParseRecordData`] (i.e., some type that knowns
/// how to parse record data) via the [`to_record`] and [`into_record`]
/// methods.
///
/// [`Record`]: struct.Record.html
/// [`ParseRecordData`]: trait.ParseRecordData.html
/// [`to_record`]: #method.to_record
/// [`into_record`]: #method.into_record
#[derive(Clone)]
pub struct ParsedRecord<'a, Octs: Octets + ?Sized> {
    /// The record’s header.
    header: RecordHeader<ParsedDname<&'a Octs>>,

    /// A parser positioned at the beginning of the record’s data.
    data: Parser<'a, Octs>,
}

impl<'a, Octs: Octets + ?Sized> ParsedRecord<'a, Octs> {
    /// Creates a new parsed record from a header and the record data.
    ///
    /// The record data is provided via a parser that is positioned at the
    /// first byte of the record data.
    pub fn new(
        header: RecordHeader<ParsedDname<&'a Octs>>,
        data: Parser<'a, Octs>,
    ) -> Self {
        ParsedRecord { header, data }
    }

    /// Returns a reference to the owner of the record.
    pub fn owner(&self) -> ParsedDname<&'a Octs> {
        *self.header.owner()
    }

    /// Returns the record type of the record.
    pub fn rtype(&self) -> Rtype {
        self.header.rtype()
    }

    /// Returns the class of the record.
    pub fn class(&self) -> Class {
        self.header.class()
    }

    /// Returns the TTL of the record.
    pub fn ttl(&self) -> Ttl {
        self.header.ttl()
    }

    /// Returns the data length of the record.
    pub fn rdlen(&self) -> u16 {
        self.header.rdlen()
    }
}

impl<'a, Octs: Octets + ?Sized> ParsedRecord<'a, Octs> {
    /// Creates a real resource record from the parsed record.
    ///
    /// The method is generic over a type that knows how to parse record
    /// data via the [`ParseRecordData`] trait. The record data is given to
    /// this trait for parsing. If the trait feels capable of parsing this
    /// type of record (as indicated by the record type) and parsing succeeds,
    /// the method returns `Ok(Some(_))`. It returns `Ok(None)` if the trait
    /// doesn’t know how to parse this particular record type. It returns
    /// an error if parsing fails.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    #[allow(clippy::type_complexity)]
    pub fn to_record<Data>(
        &self,
    ) -> Result<Option<Record<ParsedDname<Octs::Range<'_>>, Data>>, ParseError>
    where
        Data: ParseRecordData<'a, Octs>,
    {
        self.header
            .deref_owner()
            .parse_into_record(&mut self.data.clone())
    }

    /// Trades the parsed record for a real resource record.
    ///
    /// The method is generic over a type that knows how to parse record
    /// data via the [`ParseRecordData`] trait. The record data is given to
    /// this trait for parsing. If the trait feels capable of parsing this
    /// type of record (as indicated by the record type) and parsing succeeds,
    /// the method returns `Ok(Some(_))`. It returns `Ok(None)` if the trait
    /// doesn’t know how to parse this particular record type. It returns
    /// an error if parsing fails.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    #[allow(clippy::type_complexity)]
    pub fn into_record<Data>(
        mut self,
    ) -> Result<Option<Record<ParsedDname<Octs::Range<'a>>, Data>>, ParseError>
    where
        Data: ParseRecordData<'a, Octs>,
    {
        self.header.deref_owner().parse_into_record(&mut self.data)
    }
}

impl<'a, Octs: Octets + ?Sized> ParsedRecord<'a, Octs> {
    pub fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let header = RecordHeader::parse_ref(parser)?;
        let data = *parser;
        parser.advance(header.rdlen() as usize)?;
        Ok(Self::new(header, data))
    }

    pub fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        let rdlen = RecordHeader::parse_rdlen(parser)?;
        //let rdlen = RecordHeader::parse(parser)?.rdlen();
        parser.advance(rdlen as usize)?;
        Ok(())
    }

    // No compose because the data may contain compressed domain
    // names.
}

//--- PartialEq and Eq

impl<'a, 'o, Octs, Other> PartialEq<ParsedRecord<'o, Other>>
    for ParsedRecord<'a, Octs>
where
    Octs: Octets + ?Sized,
    Other: Octets + ?Sized,
{
    fn eq(&self, other: &ParsedRecord<'o, Other>) -> bool {
        self.header == other.header
            && self
                .data
                .peek(self.header.rdlen() as usize)
                .eq(&other.data.peek(other.header.rdlen() as usize))
    }
}

impl<'a, Octs: Octets + ?Sized> Eq for ParsedRecord<'a, Octs> {}

//------------ RecordParseError ----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordParseError<N, D> {
    Name(N),
    Data(D),
    ShortBuf,
}

impl<N, D> fmt::Display for RecordParseError<N, D>
where
    N: fmt::Display,
    D: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecordParseError::Name(ref name) => name.fmt(f),
            RecordParseError::Data(ref data) => data.fmt(f),
            RecordParseError::ShortBuf => {
                f.write_str("unexpected end of buffer")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<N, D> std::error::Error for RecordParseError<N, D>
where
    N: std::error::Error,
    D: std::error::Error,
{
}

impl<N, D> From<ShortBuf> for RecordParseError<N, D> {
    fn from(_: ShortBuf) -> Self {
        RecordParseError::ShortBuf
    }
}

//------------ Ttl ----------------------------------------------

const SECS_PER_MINUTE: u32 = 60;
const SECS_PER_HOUR: u32 = 3600;
const SECS_PER_DAY: u32 = 86400;

/// A span of time, typically used to describe the time a given DNS record is valid.
///
/// `Ttl` implements many common traits, including [`core::ops::Add`], [`core::ops::Sub`], and other [`core::ops`] traits. It implements Default by returning a zero-length `Ttl`.
///
/// # Why not [`std::time::Duration`]?
///
/// Two reasons make [`std::time::Duration`] not suited for representing DNS TTL values:
/// 1. According to [RFC 2181](https://datatracker.ietf.org/doc/html/rfc2181#section-8) TTL values have second-level precision while [`std::time::Duration`] can represent time down to the nanosecond level.
///     This amount of precision is simply not needed and might cause confusion when sending `Duration`s over the network.
/// 2. When working with DNS TTL values it's common to want to know a time to live in minutes or hours. [`std::time::Duration`] does not expose easy to use methods for this purpose, while `Ttl` does.
///
/// `Ttl` provides two methods [`Ttl::from_duration_lossy`] and [`Ttl::into_duration`] to convert between `Duration` and `Ttl`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ttl(u32);

impl Ttl {
    /// A time-to-live of one second.
    pub const SECOND: Ttl = Ttl::from_secs(1);

    /// A time-to-live of one minute.
    pub const MINUTE: Ttl = Ttl::from_mins(1);

    /// A time-to-live of one hour.
    pub const HOUR: Ttl = Ttl::from_hours(1);

    /// A time-to-live of one day.
    pub const DAY: Ttl = Ttl::from_days(1);

    /// A duration of zero time.
    pub const ZERO: Ttl = Ttl::from_secs(0);

    /// The maximum theoretical time to live.
    pub const MAX: Ttl = Ttl::from_secs(u32::MAX);

    /// The practical maximum time to live as recommended by [RFC 8767](https://datatracker.ietf.org/doc/html/rfc8767#section-4).
    pub const CAP: Ttl = Ttl::from_secs(604_800);

    /// The maximum number of minutes that a `Ttl` can represent.
    pub const MAX_MINUTES: u32 = 71582788;

    /// The maximum number of hours that a `Ttl` can represent.
    pub const MAX_HOURS: u32 = 1193046;

    /// The maximum number of days that a `Ttl` can represent.
    pub const MAX_DAYS: u16 = 49710;

    pub const COMPOSE_LEN: u16 = 4;

    /// Returns the total time to live in seconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// let ttl = Ttl::from_secs(120);
    /// assert_eq!(ttl.as_secs(), 120);
    /// ```
    #[must_use]
    #[inline]
    pub const fn as_secs(&self) -> u32 {
        self.0
    }

    /// Returns the total time to live in minutes.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// let ttl = Ttl::from_secs(120);
    /// assert_eq!(ttl.as_minutes(), 2);
    /// ```
    #[must_use]
    #[inline]
    pub const fn as_minutes(&self) -> u32 {
        self.0 / SECS_PER_MINUTE
    }

    /// Returns the total time to live in hours.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// let ttl = Ttl::from_secs(7200);
    /// assert_eq!(ttl.as_hours(), 2);
    /// ```
    #[must_use]
    #[inline]
    pub const fn as_hours(&self) -> u32 {
        self.0 / SECS_PER_HOUR
    }

    /// Returns the total time to live in days.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// let ttl = Ttl::from_secs(172800);
    /// assert_eq!(ttl.as_days(), 2);
    /// ```
    #[must_use]
    #[inline]
    pub const fn as_days(&self) -> u16 {
        (self.0 / SECS_PER_DAY) as u16
    }

    /// Converts a `Ttl` into a [`std::time::Duration`].
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    /// use std::time::Duration;
    ///
    /// let ttl = Ttl::from_mins(2);
    /// let duration = ttl.into_duration();
    /// assert_eq!(duration.as_secs(), 120);
    /// ```
    #[must_use]
    #[inline]
    pub const fn into_duration(&self) -> Duration {
        Duration::from_secs(self.0 as u64)
    }

    /// Creates a new `Ttl` from the specified number of seconds.
    #[must_use]
    #[inline]
    pub const fn from_secs(secs: u32) -> Self {
        Self(secs)
    }

    /// Creates a new `Ttl` from the specified number of minutes.
    ///
    /// # Panics
    ///
    /// The maximum number of days that a `Ttl` can represent is `71582788`.
    /// This method will panic if it is being called with a value greater than that.
    #[must_use]
    #[inline]
    pub const fn from_mins(minutes: u32) -> Self {
        assert!(minutes <= 71582788);
        Self(minutes * SECS_PER_MINUTE)
    }

    /// Creates a new `Ttl` from the specified number of hours.
    ///
    /// # Panics
    ///
    /// The maximum number of hours that a `Ttl` can represent is `1193046`.
    /// This method will panic if it is being called with a value greater than that.
    #[must_use]
    #[inline]
    pub const fn from_hours(hours: u32) -> Self {
        assert!(hours <= 1193046);
        Self(hours * SECS_PER_HOUR)
    }

    /// Creates a new `Ttl` from the specified number of days.
    ///
    /// # Panics
    ///
    /// The maximum number of days that a `Ttl` can represent is `49710`.
    /// This method will panic if it is being called with a value greater than that.
    #[must_use]
    #[inline]
    pub const fn from_days(days: u16) -> Self {
        assert!(days <= 49710);
        Self(days as u32 * SECS_PER_DAY)
    }

    /// Creates a new `Ttl` from a [`std::time::Duration`].
    ///
    /// This operation is lossy as [`Duration`] stores seconds as `u64`, while `Ttl` stores seconds as `u32` to comply with the DNS specifications.
    /// [`Duration`] also represents time using sub-second precision, which is not kept when converting into a `Ttl`.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    /// use std::time::Duration;
    ///
    /// assert_eq!(Ttl::from_duration_lossy(Duration::new(1, 0)), Ttl::from_secs(1));
    /// assert_eq!(Ttl::from_duration_lossy(Duration::new(1, 6000)), Ttl::from_secs(1));
    /// ```
    #[must_use]
    #[inline]
    pub const fn from_duration_lossy(duration: Duration) -> Self {
        Self(duration.as_secs() as u32)
    }

    /// Returns true if this `Tll` spans no time.
    ///
    /// This usually indicates a given record should not be cached.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert!(Ttl::ZERO.is_zero());
    /// assert!(Ttl::from_secs(0).is_zero());
    /// assert!(Ttl::from_mins(0).is_zero());
    /// assert!(Ttl::from_hours(0).is_zero());
    /// assert!(Ttl::from_days(0).is_zero());
    /// ```
    #[must_use]
    #[inline]
    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Checked `Ttl` addition. Computes `self + other`, returning [`None`]
    /// if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(0).checked_add(Ttl::from_secs(1)), Some(Ttl::from_secs(1)));
    /// assert_eq!(Ttl::from_secs(1).checked_add(Ttl::MAX), None);
    /// ```
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn checked_add(self, rhs: Ttl) -> Option<Ttl> {
        if let Some(secs) = self.0.checked_add(rhs.0) {
            Some(Ttl(secs))
        } else {
            None
        }
    }

    /// Saturating `Ttl` addition. Computes `self + other`, returning [`Ttl::MAX`]
    /// if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(0).saturating_add(Ttl::from_secs(1)), Ttl::from_secs(1));
    /// assert_eq!(Ttl::from_secs(1).saturating_add(Ttl::MAX), Ttl::MAX);
    /// ```
    #[must_use = "this returns the result of the operation, \
    without modifying the original"]
    #[inline]
    pub const fn saturating_add(self, rhs: Ttl) -> Ttl {
        match self.0.checked_add(rhs.0) {
            Some(secs) => Ttl(secs),
            None => Ttl::MAX,
        }
    }

    /// Checked `Ttl` subtraction. Computes `self - other`, returning [`None`]
    /// if the result would be negative or if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(1).checked_sub(Ttl::from_secs(0)), Some(Ttl::from_secs(1)));
    /// assert_eq!(Ttl::from_secs(0).checked_sub(Ttl::from_secs(1)), None);
    /// ```
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn checked_sub(self, rhs: Ttl) -> Option<Ttl> {
        if let Some(secs) = self.0.checked_sub(rhs.0) {
            Some(Ttl(secs))
        } else {
            None
        }
    }

    /// Saturating `Ttl` subtraction. Computes `self - other`, returning [`Ttl::ZERO`]
    /// if the result would be negative or if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(1).saturating_sub(Ttl::from_secs(0)), Ttl::from_secs(1));
    /// assert_eq!(Ttl::from_secs(0).saturating_sub(Ttl::from_secs(1)), Ttl::ZERO);
    /// ```
    #[must_use = "this returns the result of the operation, \
    without modifying the original"]
    #[inline]
    pub const fn saturating_sub(self, rhs: Ttl) -> Ttl {
        match self.0.checked_sub(rhs.0) {
            Some(secs) => Ttl(secs),
            None => Ttl::ZERO,
        }
    }

    /// Checked `Ttl` multiplication. Computes `self * other`, returning
    /// [`None`] if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(5).checked_mul(2), Some(Ttl::from_secs(10)));
    /// assert_eq!(Ttl::from_secs(u32::MAX - 1).checked_mul(2), None);
    /// ```
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub const fn checked_mul(self, rhs: u32) -> Option<Ttl> {
        if let Some(secs) = self.0.checked_mul(rhs) {
            Some(Ttl(secs))
        } else {
            None
        }
    }

    /// Saturating `Duration` multiplication. Computes `self * other`, returning
    /// [`Duration::MAX`] if overflow occurred.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(5).saturating_mul(2), Ttl::from_secs(10));
    /// assert_eq!(Ttl::from_secs(u32::MAX - 1).saturating_mul(2), Ttl::MAX);
    /// ```
    #[must_use = "this returns the result of the operation, \
    without modifying the original"]
    #[inline]
    pub const fn saturating_mul(self, rhs: u32) -> Ttl {
        match self.0.checked_mul(rhs) {
            Some(secs) => Ttl(secs),
            None => Ttl::MAX,
        }
    }

    /// Checked `Duration` division. Computes `self / other`, returning [`None`]
    /// if `other == 0`.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_secs(10).checked_div(2), Some(Ttl::from_secs(5)));
    /// assert_eq!(Ttl::from_mins(1).checked_div(2), Some(Ttl::from_secs(30)));
    /// assert_eq!(Ttl::from_secs(2).checked_div(0), None);
    /// ```
    #[must_use = "this returns the result of the operation, \
    without modifying the original"]
    #[inline]
    pub const fn checked_div(self, rhs: u32) -> Option<Ttl> {
        if rhs != 0 {
            Some(Ttl(self.0 / rhs))
        } else {
            None
        }
    }

    /// Caps the value of `Ttl` at 7 days (604800 seconds) as recommended by [RFC 8767](https://datatracker.ietf.org/doc/html/rfc8767#name-standards-action).
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::Ttl;
    ///
    /// assert_eq!(Ttl::from_mins(5).cap(), Ttl::from_mins(5));
    /// assert_eq!(Ttl::from_days(50).cap(), Ttl::from_days(7));
    /// ```
    #[must_use = "this returns the result of the operation, \
    without modifying the original"]
    #[inline]
    pub const fn cap(self) -> Ttl {
        if self.0 > Self::CAP.0 {
            Self::CAP
        } else {
            self
        }
    }

    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&(self.as_secs()).to_be_bytes())
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<'_, Octs>,
    ) -> Result<Self, ParseError> {
        parser
            .parse_u32_be()
            .map(Ttl::from_secs)
            .map_err(Into::into)
    }
}

impl core::ops::Add for Ttl {
    type Output = Ttl;

    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs)
            .expect("overflow when adding durations")
    }
}

impl core::ops::AddAssign for Ttl {
    fn add_assign(&mut self, rhs: Ttl) {
        *self = *self + rhs;
    }
}

impl core::ops::Sub for Ttl {
    type Output = Ttl;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs)
            .expect("overflow when subtracting durations")
    }
}

impl core::ops::SubAssign for Ttl {
    fn sub_assign(&mut self, rhs: Ttl) {
        *self = *self - rhs;
    }
}

impl core::ops::Mul<u32> for Ttl {
    type Output = Ttl;

    fn mul(self, rhs: u32) -> Self::Output {
        self.checked_mul(rhs)
            .expect("overflow when multiplying duration by scalar")
    }
}

impl core::ops::MulAssign<u32> for Ttl {
    fn mul_assign(&mut self, rhs: u32) {
        *self = *self * rhs;
    }
}

impl core::ops::Div<u32> for Ttl {
    type Output = Ttl;

    fn div(self, rhs: u32) -> Ttl {
        self.checked_div(rhs)
            .expect("divide by zero error when dividing duration by scalar")
    }
}

impl core::ops::DivAssign<u32> for Ttl {
    fn div_assign(&mut self, rhs: u32) {
        *self = *self / rhs;
    }
}

macro_rules! sum_durations {
    ($iter:expr) => {{
        let mut total_secs: u32 = 0;

        for entry in $iter {
            total_secs = total_secs
                .checked_add(entry.0)
                .expect("overflow in iter::sum over durations");
        }

        Ttl(total_secs)
    }};
}

impl core::iter::Sum for Ttl {
    fn sum<I: Iterator<Item = Ttl>>(iter: I) -> Ttl {
        sum_durations!(iter)
    }
}

impl<'a> core::iter::Sum<&'a Ttl> for Ttl {
    fn sum<I: Iterator<Item = &'a Ttl>>(iter: I) -> Ttl {
        sum_durations!(iter)
    }
}

// No From impl because conversion is lossy
#[allow(clippy::from_over_into)]
impl Into<Duration> for Ttl {
    fn into(self) -> Duration {
        Duration::from_secs(u64::from(self.0))
    }
}

//============ Testing ======================================================

#[cfg(test)]
mod test {
    #[test]
    #[cfg(features = "bytes")]
    fn ds_octets_into() {
        use crate::base::iana::{DigestAlg, Rtype, SecAlg};
        use crate::name::Dname;
        use crate::octets::OctetsInto;
        use crate::rdata::Ds;

        let ds: Record<Dname<&[u8]>, Ds<&[u8]>> = Record::new(
            "a.example".parse().unwrap(),
            Class::In,
            86400,
            Ds::new(12, SecAlg::RsaSha256, b"something"),
        );
        let ds_bytes: Record<Dname<Bytes>, Ds<Bytes>> =
            ds.octets_into().unwrap();
        assert_eq!(ds.owner(), ds_bytes.owner());
        asswer_eq!(ds.data().digest(), ds_bytes.data().digest());
    }
}
