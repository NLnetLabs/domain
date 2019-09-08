//! Accessing exisiting DNS messages.
//!
//! This module defines a number of types for disecting the content of a
//! DNS message in wire format. Because many of the components of the message
//! are of varying length, this can only be done iteratively. You start out
//! with a value of type [`Message`] that wraps the data of a complete
//! message and progressively trade it in for values of other types
//! representing other sections of the message.
//!
//! For all details, see the [`Message`] type.
//!
//! [`Message`]: struct.Message.html

use core::{mem, ops};
use core::marker::PhantomData;
use crate::compose::{ComposeTarget, TryCompose};
use crate::header::{Header, HeaderCounts, HeaderSection};
use crate::iana::{Rcode, Rtype};
use crate::message_builder::{
    AdditionalBuilder, AnswerBuilder, RecordSectionBuilder
};
use crate::name::{ParsedDname, ParsedDnameError, ToDname};
use crate::opt::{Opt, OptRecord};
use crate::parse::{Parse, Parser, ParseSource, ShortBuf};
use crate::question::Question;
use crate::rdata::{Cname, ParseRecordData, RecordData};
use crate::record::{ParsedRecord, Record, RecordParseError};


//------------ Message -------------------------------------------------------

/// A DNS message.
///
/// This type wraps a bytes value with the wire-format content of a DNS
/// message and allows parsing the content for further processing.
///
/// Typically, you create a message by passing a bytes value with data you
/// received from the network to the [`from_bytes`] function. This function
/// does a quick sanity check if the data can be a DNS message at all
/// before returning a message value. All further parsing happens lazily when
/// you access more of the message.
///
/// Section 4 of [RFC 1035] defines DNS messages as being divded into five
/// sections named header, question, answer, authority, and additional.
///
/// The header section is of a fixed sized and can be accessed at any time
/// through the methods given under [Header Section]. Most likely, you will
/// be interested in the first part of the header for which references 
/// are returned by the [`header`] method.  The second part of the header
/// section contains the number of entries in the following four sections
/// and is of less interest as there are more sophisticated ways of accessing
/// these sections. If you do care, you can get a reference through
/// [`counts`].
///
/// The question section contains what was asked of the DNS by a request.
/// These questions consist of a domain name, a record type, and class. With
/// normal queries, a requests asks for all records of the given record type
/// that are owned by the domain name within the class. There will normally
/// be exactly one question for normal queries. With other query operations,
/// the questions may refer to different things.
///
/// You can get access to the question section through the [`question`]
/// method. It returns a [`QuestionSection`] value that is an iterator over
/// questions. Since a single question is a very common case, there is a 
/// convenience method [`first_question`] that simple returns the first
/// question if there is any.
///
/// The following three section all contain DNS resource records. In normal
/// queries, they are empty in a request and may or may not contain records
/// in a response. The *answer* section contains all the records that answer
/// the given question. The *authority* section contains records declaring
/// which name server provided authoritative information for the question,
/// and the *additional* section can contain records that the name server
/// thought might be useful for processing the question. For instance, if you
/// trying to find out the mail server of a domain by asking for MX records,
/// you likely also want the IP addresses for the server, so the name server
/// may include these right away and free of charge.
///
/// There are functions to access all three sections directly: [`answer`],
/// [`authority`], and [`additional`]. However, since there are no
/// pointers to where the later sections start, accessing them directly
/// means iterating over the previous sections. This is why it is more
/// efficitent to call [`next_section`] on the returned value and process
/// them in order. Alternatively, you can use the [`sections`] function
/// that gives you all four sections at once with the minimal amount of
/// iterating necessary.
///
/// Each record in the record sections is of a specific type. Each type has
/// its specific record data. Because there are so many types, we decided
/// against having only one giant enum. Instead, invidual types can either
/// implement the record data for one single record type or there can be
/// compound types covering multiple record types. An example of the latter
/// is [`AllRecordData`] from the [rdata] module that does indeed provide
/// this one giant enum if you insist on using it.
/// 
/// Consequently, the typ representing a record section of a message,
/// somewhat obviously named [`RecordSection`], iterates over a stand-in type,
/// [`ParseRecord`], that gives you access to all information of the record
/// except for its data.
///
/// There are two ways to convert that value into a [`Record`] with actual
/// data. [`ParseRecord::into_record`] takes a record data type as a type
/// argument—turbo-fish style—and tries to reparse the record as a record
/// with that data. Alternatively, you can switch the entire record section
/// to inly iterate over such records via the [`limit_to`] method.
///
/// So, if you want to iterate over the MX records in the answer section, you
/// would do something like this:
///
/// ```
/// # use domain_core::message::Message;
/// use domain_core::rdata::parsed::Mx;
///
/// # let octets = vec![0; 12]; let octets = octets.as_slice();
/// let msg = Message::from_octets(octets).unwrap();
/// for record in msg.answer().unwrap().limit_to::<Mx<_>>() {
///     if let Ok(record) = record {
///         // Do something with the record ...
///     }
/// }
/// ```
///
/// The code inside the for loop deals with the fact that iterator actually
/// returns a `Result<T, E>`. An error signals that something went wrong while
/// parsing. If only the record data is broken, the message remains useful and
/// parsing can continue with the next record. If the message is fully
/// broken, the next iteration will return `None` to signal that.
///
/// [`additional`]: #method.additional
/// [`answer`]: #method.answer
/// [`authority`]: #method.authority
/// [`counts`]: #method.counts
/// [`first_question`]: #method.first_question
/// [`from_bytes`]: #method.from_bytes
/// [`header`]: #method.header
/// [`limit_to`]: ../struct.RecordSection.html#method.limit_to
/// [`next_section`]: ../struct.RecordSection.html#method.next_section
/// [`question`]: #method.question
/// [`sections`]: #method.sections
/// [`AllRecordData`]: ../../rdata/enum.AllRecordData.html
/// [`QuestionSection`]: struct.QuestionSection.html
/// [`ParseRecord`]: ../record/struct.ParseRecord.html
/// [`ParseRecord::into_record`]: ../record/struct.ParseRecord.html#method.into_record
/// [`RecordSection`]: struct.RecordSection.html
/// [Header Section]: #header-section
/// [rdata]: ../../rdata/index.html
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone, Copy)]
pub struct Message<Octets> {
    octets: Octets
}

/// # Creation and Conversion
///
impl<Octets> Message<Octets> {
    /// Creates a message from a bytes value.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns `Ok`, the message may still be broken with other
    /// methods returning `Err(_)`.
    pub fn from_octets(octets: Octets) -> Result<Self, ShortBuf>
    where Octets: AsRef<[u8]> {
        if octets.as_ref().len() < mem::size_of::<HeaderSection>() {
            Err(ShortBuf)
        }
        else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a message from a bytes value without checking.
    pub(super) unsafe fn from_octets_unchecked(octets: Octets) -> Self {
        Message { octets }
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_octets(&self) -> &Octets {
        &self.octets
    }

    /// Converts the message into the underlying octets sequence.
    pub fn into_octets(self) -> Octets {
        self.octets
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8]
    where Octets: AsRef<[u8]> {
        self.octets.as_ref()
    }

    /// Returns a mutable reference to the underlying octets.
    ///
    /// Because it is possible to utterly break the message using this slice,
    /// the method is private.
    fn as_slice_mut(&mut self) -> &mut [u8]
    where Octets: AsMut<[u8]> {
        self.octets.as_mut()
    }
}


/// # Header Section
///
impl<Octets: AsRef<[u8]>> Message<Octets> {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(self.as_slice())
    }
    
    /// Returns a mutable reference to the message header.
    pub fn header_mut(&mut self) -> &mut Header
    where Octets: AsMut<[u8]> {
        Header::for_message_slice_mut(self.as_slice_mut())
    }

    /// Returns a reference the header counts of the message.
    pub fn header_counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.as_slice())
    }

    /// Returns a mutable reference to the header counts.
    ///
    /// Since you can quite effectively break the message with this, it is
    /// private.
    pub fn header_counts_mut(&mut self) -> &mut HeaderCounts
    where Octets: AsMut<[u8]> {
        HeaderCounts::for_message_slice_mut(self.as_slice_mut())
    }

    /// Returns whether the rcode is NoError.
    pub fn no_error(&self) -> bool {
        self.header().rcode() == Rcode::NoError
    }

    /// Returns whether the rcode is one of the error values.
    pub fn is_error(&self) -> bool {
        self.header().rcode() != Rcode::NoError
    }
}


/// # Sections
///
impl<Octets: ParseSource> Message<Octets> {
    /// Returns the question section.
    pub fn question(&self) -> QuestionSection<Octets> {
        QuestionSection::new(self.octets.clone())
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection<Octets> { self.question() }

    /// Returns the answer section.
    pub fn answer(&self) -> Result<RecordSection<Octets>, ParsedDnameError> {
        Ok(self.question().next_section()?)
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(
        &self
    ) -> Result<RecordSection<Octets>, ParsedDnameError> {
        self.answer()
    }

    /// Returns the authority section.
    pub fn authority(
        &self
    ) -> Result<RecordSection<Octets>, ParsedDnameError> {
        Ok(self.answer()?.next_section()?.unwrap())
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> Result<RecordSection<Octets>, ParsedDnameError> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(
        &self
    ) -> Result<RecordSection<Octets>, ParsedDnameError> {
        Ok(self.authority()?.next_section()?.unwrap())
    }

    /// Returns all four sections in one fell swoop.
    #[allow(clippy::type_complexity)]
    pub fn sections(
        &self
    ) -> Result<
        (
            QuestionSection<Octets>, RecordSection<Octets>,
            RecordSection<Octets>, RecordSection<Octets>
        ),
        ParsedDnameError
    >
    where Octets: Clone {
        let question = self.clone().question();
        let answer = question.clone().next_section()?;
        let authority = answer.clone().next_section()?.unwrap();
        let additional = authority.clone().next_section()?.unwrap();
        Ok((question, answer, authority, additional))
    }

    pub fn iter(&self) -> MessageIter<Octets> {
        self.clone().into_iter()
    }

    /// Copy records from message into the target message builder.
    ///
    /// The method uses `op` to process records from all record sections
    /// before inserting, caller can use this closure to filter or manipulate
    /// records before inserting.
    pub fn copy_records<N, D, R, F, T, O>(
        &self,
        target: T,
        mut op: F
    ) -> Result<AdditionalBuilder<O>, ParsedDnameError>
    where
        N: ToDname,
        D: RecordData,
        R: Into<Record<N, D>>,
        F: FnMut(
            Result<ParsedRecord<Octets>, ParsedDnameError>
        ) -> Option<R>,
        T: Into<AnswerBuilder<O>>,
        O: TryCompose + ComposeTarget
    {
        let mut target = target.into();

        // Copy answer, authority, and additional records.
        for rr in self.answer()?.filter_map(&mut op) {
            target.push(rr)?;
        }

        let mut target = target.authority();
        for rr in self.authority()?.filter_map(&mut op) {
            target.push(rr)?;
        }

        let mut target = target.additional();
        for rr in self.additional()?.filter_map(&mut op) {
            target.push(rr)?;
        }

        Ok(target)
    }
}

/// # Helpers for Common Tasks
///
impl<Octets: ParseSource> Message<Octets> {
    /// Returns whether this is the answer to some other message.
    ///
    /// The method checks whether the ID fields of the headers are the same,
    /// whether the QR flag is set in this message, and whether the questions
    /// are the same.
    pub fn is_answer<Other>(&self, query: &Message<Other>) -> bool
    where Other: ParseSource {
        if !self.header().qr()
                || self.header().id() != query.header().id()
                || self.header_counts().qdcount()
                        != query.header_counts().qdcount() {
            false
        }
        else { self.clone().question().eq(query.clone().question()) }
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(&self) -> Option<Question<ParsedDname<Octets>>> {
        match self.clone().question().next() {
            None | Some(Err(..)) => None,
            Some(Ok(question)) => Some(question)
        }
    }

    /// Returns the query type of the first question, if any.
    pub fn qtype(&self) -> Option<Rtype> {
        self.first_question().map(|x| x.qtype())
    }

    /// Returns whether the message contains answers of a given type.
    pub fn contains_answer<D: ParseRecordData<Octets>>(&self) -> bool {
        let answer = match self.clone().answer() {
            Ok(answer) => answer,
            Err(..) => return false
        };
        answer.limit_to::<D>().next().is_some()
    }

    /// Resolves the canonical name of the answer.
    ///
    /// Returns `None` if either the message doesn’t have a question or there
    /// was a parse error. Otherwise starts with the question’s name,
    /// follows any CNAME trail and returns the name answers should be for.
    pub fn canonical_name(&self) -> Option<ParsedDname<Octets>> {
        let question = match self.first_question() {
            None => return None,
            Some(question) => question
        };
        let mut name = question.qname().clone();
        let answer = match self.answer() {
            Ok(answer) => answer.limit_to::<Cname<ParsedDname<Octets>>>(),
            Err(_) => return None,
        };

        loop {
            let mut found = false;
            for record in answer.clone() {
                let record = match record {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                if *record.owner() == name {
                    name = record.data().cname().clone();
                    found = true;
                    break;
                }
            }
            if !found {
                break
            }
        }
        
        Some(name)
    }

    /// Get the OPT record from the message, if there is one.
    pub fn opt(&self) -> Option<OptRecord<Octets>> {
        match self.additional() {
            Ok(section) => match section.limit_to::<Opt<Octets>>().next() {
                Some(Ok(rr)) => Some(OptRecord::from(rr)),
                _ => None,
            }
            Err(_) => None,
        }
    }

    /// Removes and returns the last additional record from the message.
    ///
    /// The method tries to parse the last record of the additional section
    /// as the provided record type. If that succeeds, it returns that
    /// parsed record and removes it from the message.
    ///
    /// If the last record is of the wrong type or parsing fails, returns
    /// `None` and leaves the message untouched.
    pub fn extract_last<D: ParseRecordData<Octets>>(
        &mut self
    ) -> Option<Record<ParsedDname<Octets>, D>>
    where Octets: AsMut<[u8]> {
        let mut section = match self.additional() {
            Ok(section) => section,
            Err(_) => return None
        };
        loop {
            match section.count {
                Err(_) => return None,
                Ok(0) => return None,
                Ok(1) => break,
                _ => { }
            }
            let _ = section.next();
        }
        let record = match ParsedRecord::parse(&mut section.parser) {
            Ok(record) => record,
            Err(_) => return None,
        };
        let record = match record.into_record() {
            Ok(Some(record)) => record,
            _ => return None
        };
        self.header_counts_mut().dec_arcount();
        Some(record)
    }
}


//--- Deref and AsRef

impl<Octets> ops::Deref for Message<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        self.as_octets()
    }
}

impl<T, Octets: AsRef<T>> AsRef<T> for Message<Octets> {
    fn as_ref(&self) -> &T {
        self.as_octets().as_ref()
    }
}


//--- IntoIterator

impl<Octets: ParseSource> IntoIterator for Message<Octets> {
    type Item = Result<(ParsedRecord<Octets>, Section), ParsedDnameError>;
    type IntoIter = MessageIter<Octets>;

    fn into_iter(self) -> Self::IntoIter {
        match self.answer() {
            Ok(section) => MessageIter { inner: Some(section) },
            Err(_) => MessageIter { inner: None },
        }
    }
}


//------------ QuestionSection ----------------------------------------------

/// An iterator over the question section of a DNS message.
///
/// The iterator’s item is the result of trying to parse the questions. In
/// case of a parse error, `next()` will return an error once and
/// `None` after that.
///
/// You can create a value of this type through the [`Message::section`]
/// method. Use the [`answer`] or [`next_section`] methods to proceed
/// to an iterator over the answer section.
///
/// [`Message::section`]: struct.Message.html#method.section
/// [`answer`]: #method.answer
/// [`next_section`]: #method.next_section
#[derive(Clone)]
pub struct QuestionSection<Octets> {
    /// The parser for generating the questions.
    parser: Parser<Octets>,

    /// The remaining number of questions.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParsedDnameError>
}

impl<Octets> QuestionSection<Octets> {
    /// Creates a new question section from a bytes value.
    fn new(octets: Octets) -> Self
    where Octets: AsRef<[u8]> {
        let mut parser = Parser::from_octets(octets);
        parser.advance(mem::size_of::<HeaderSection>()).unwrap();
        QuestionSection {
            count: Ok(HeaderCounts::for_message_slice(
                parser.as_slice()).qdcount()
            ),
            parser,
        }
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into
    /// the first [`RecordSection`].
    ///
    /// [`RecordSection`]: struct.RecordSection.html
    pub fn answer(
        mut self
    ) -> Result<RecordSection<Octets>, ParsedDnameError>
    where Octets: ParseSource {
        // XXX Use Parser::skip here.
        for question in &mut self {
            let _ = question?;
        }
        match self.count {
            Ok(..) => Ok(RecordSection::new(self.parser, Section::first())),
            Err(err) => Err(err)
        }
    }

    /// Proceeds to the answer section.
    ///
    /// This is an alias for the [`answer`] method.
    ///
    /// [`answer`]: #method.answer
    pub fn next_section(
        self
    ) -> Result<RecordSection<Octets>, ParsedDnameError>
    where Octets: ParseSource {
        self.answer()
    }

    fn eq<Other>(mut self, mut other: QuestionSection<Other>) -> bool
    where Octets: ParseSource, Other: ParseSource {
        loop {
            match (self.next(), other.next()) {
                (Some(Ok(left)), Some(Ok(right))) => {
                    if left != right {
                        return false
                    }
                }
                (None, None) => return true,
                _ => return false
            }
        }
    }
}


//--- Iterator

impl<Octets: ParseSource> Iterator for QuestionSection<Octets> {
    type Item = Result<Question<ParsedDname<Octets>>, ParsedDnameError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match Question::parse(&mut self.parser) {
                    Ok(question) => {
                        self.count = Ok(count - 1);
                        Some(Ok(question))
                    }
                    Err(err) => {
                        self.count = Err(err);
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//------------ Section -------------------------------------------------------

/// A helper type enumerating which section a `RecordSection` is currently in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum Section {
    Answer,
    Authority,
    Additional
}


impl Section {
    /// Returns the first section.
    pub fn first() -> Self { Section::Answer }

    /// Returns the correct record count for this section.
    fn count(self, counts: HeaderCounts) -> u16 {
        match self {
            Section::Answer => counts.ancount(),
            Section::Authority => counts.nscount(),
            Section::Additional => counts.arcount()
        }
    }

    /// Returns the value for the following section or `None` if this is last.
    pub(crate) fn next_section(self) -> Option<Self> {
        match self {
            Section::Answer => Some(Section::Authority),
            Section::Authority => Some(Section::Additional),
            Section::Additional => None
        }
    }
}


//------------ RecordSection -----------------------------------------------

/// An iterator over one of the three record sections of a DNS message.
/// 
/// The iterator’s item is the result of parsing a raw record represented by
/// [`ParsedRecord`]. This type will allow access to a record’s header
/// only. It can, however, be converted into a concrete [`Record`] via its
/// [`into_record`] method. If parsing the raw record fails, the iterator
/// will return an error once and `None` after that.
///
/// Alternatively, you can trade in a value of this type into a
/// [`RecordIter`] that iterates over [`Record`]s of a specific type by
/// calling the [`limit_to`] method. In particular, you can use this together
/// with [`AllRecordData`] to acquire an iterator that parses all known
/// record types. If you are only interested in a subset of records, it may
/// be more efficient to create a similar enum with only the types you need.
///
/// `RecordSection` values cannot be created directly. You can get one either
/// by calling the method for the section in question of a [`Message`] value
/// or by proceeding from another section via its `next_section` method.
///
/// [`limit_to`]: #method.limit_to
/// [`AllRecordData`]: ../../rdata/enum.AllRecordData.html
/// [`Message`]: struct.Message.html
/// [`ParseRecord`]: ../record/struct.ParsedRecord.html
/// [`Record`]: ../record/struct.Record.html
/// [`RecordIter`]: struct.RecordIter.html
/// [`into_record`]: ../record/struct.ParsedRecord.html#method.into_record
#[derive(Clone, Debug)]
pub struct RecordSection<Octets> {
    /// The parser for generating the records.
    parser: Parser<Octets>,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of records.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParsedDnameError>
}


impl<Octets> RecordSection<Octets> {
    /// Creates a new section from a parser.
    ///
    /// The parser must only wrap the bytes of the message and it must be
    /// positioned at the beginning of the section.
    fn new(parser: Parser<Octets>, section: Section) ->  Self
    where Octets: AsRef<[u8]> {
        RecordSection {
            count: Ok(section.count(
                *HeaderCounts::for_message_slice(parser.as_slice())
            )),
            section,
            parser,
        }
    }

    /// Trades `self` in for an iterator limited to a concrete record type.
    ///
    /// The record type is given through its record data type. Since the data
    /// is being parsed, this type must implement [`ParseRecordData`]. For
    /// record data types that are generic over domain name types, this is
    /// normally achieved by giving them a [`ParsedDname`]. As a convenience,
    /// type aliases for all the fundamental record data types exist in the
    /// [domain::rdata::parsed] module.
    ///
    /// The returned limited iterator will continue at the current position
    /// of `self`. It will *not* start from the beginning of the section.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    /// [`ParsedDname`]: ../name/struct.ParsedDname.html
    /// [domain::rdata::parsed]: ../../rdata/parsed/index.html
    pub fn limit_to<D: ParseRecordData<Octets>>(self) -> RecordIter<Octets, D> {
        RecordIter::new(self)
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unsable
    /// now.
    pub fn next_section(
        mut self
    ) -> Result<Option<Self>, ParsedDnameError>
    where Octets: ParseSource {
        let section = match self.section.next_section() {
            Some(section) => section,
            None => return Ok(None)
        };
        // XXX Use Parser::skip here.
        for record in &mut self {
            let _ = record?;
        }
        match self.count {
            Ok(..) => Ok(Some(RecordSection::new(self.parser, section))),
            Err(err) => Err(err)
        }
    }
}


//--- Iterator

impl<Octets: ParseSource> Iterator for RecordSection<Octets> {
    type Item = Result<ParsedRecord<Octets>, ParsedDnameError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match ParsedRecord::parse(&mut self.parser) {
                    Ok(record) => {
                        self.count = Ok(count - 1);
                        Some(Ok(record))
                    }
                    Err(err) => {
                        self.count = Err(err);
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}



//------------ MessageIter ---------------------------------------------------

pub struct MessageIter<Octets> {
    inner: Option<RecordSection<Octets>>,
}

impl<Octets: ParseSource> Iterator for MessageIter<Octets> {
    type Item = Result<(ParsedRecord<Octets>, Section), ParsedDnameError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get next record from current section
        match self.inner {
            Some(ref mut inner) => {
                let item = inner.next();
                if let Some(item) = item {
                    return Some(item.map(|item| (item, inner.section)));
                }
            },
            None => return None,
        }

        // Advance to next section if possible, and retry
        let inner = self.inner.take()?;
        match inner.next_section() {
            Ok(section) => {
                self.inner = section;
                self.next()
            }
            Err(err) => Some(Err(err))
        }
    }
}


//------------ RecordIter ----------------------------------------------------

/// An iterator over specific records of a record section of a DNS message.
///
/// The iterator’s item type is the result of trying to parse a record.
/// It silently skips over all records that `D` cannot or does not want to
/// parse. If parsing the record data fails, the iterator will return an
/// error but can continue with the next record. If parsing the entire record
/// fails (and the message thus becomes unusable) or if the end of the
/// section is reached, the iterator produces `None`. The latter case can be
/// distinguished by [`next_section`] returning an error.
///
/// You can create a value of this type through the
/// [`RecordSection::limit_to`] method.
///
/// [`next_section`]: #method.next_section
/// [`RecordSection::limit_to`]: struct.RecordSection.html#method.limit_to
#[derive(Clone, Debug)]
pub struct RecordIter<Octets, D: ParseRecordData<Octets>> {
    section: RecordSection<Octets>,
    marker: PhantomData<D>
}

impl<Octets, D: ParseRecordData<Octets>> RecordIter<Octets, D> {
    /// Creates a new limited record iterator from the given section.
    fn new(section: RecordSection<Octets>) -> Self {
        RecordIter { section, marker: PhantomData }
    }

    /// Trades in the limited iterator for the complete iterator.
    ///
    /// The complete iterator will continue right after the last record
    /// returned by `self`. It will *not* restart from the beginning of the
    /// section.
    pub fn unwrap(self) -> RecordSection<Octets> {
        self.section
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unusable
    /// now.
    pub fn next_section(
        self
    ) -> Result<Option<RecordSection<Octets>>, ParsedDnameError>
    where Octets: ParseSource {
        self.section.next_section()
    }
}


//--- Iterator

impl<Octets, D> Iterator for RecordIter<Octets, D>
where Octets: ParseSource, D: ParseRecordData<Octets> {
    type Item = Result<Record<ParsedDname<Octets>, D>,
                       RecordParseError<ParsedDnameError, D::Err>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = match self.section.next() {
                Some(Ok(record)) => record,
                Some(Err(err)) => {
                    return Some(Err(RecordParseError::Name(err)))
                }
                None => return None,
            };
            match record.into_record() {
                Ok(Some(record)) => return Some(Ok(record)),
                Err(err) => return Some(Err(err)),
                Ok(None) => { }
            }
        }
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use bytes::Bytes;
    use unwrap::unwrap;
    use crate::message_builder::MessageBuilder;
    use crate::name::Dname;
    use crate::rdata::{Ns, AllRecordData};
    use super::*;

    // Helper for test cases
    fn get_test_message() -> Message<Bytes> {
        let msg = MessageBuilder::new_dgram_bytes();
        let mut msg = msg.answer();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("foo.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        let mut msg = msg.authority();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("bar.example.com.")),
            86000,
            Ns::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        msg.into_message()
    }

    #[test]
    fn short_message() {
        assert!(Message::from_octets(&[0u8; 11]).is_err());
        assert!(Message::from_octets(&[0u8; 12]).is_ok());
    }

    #[test]
    fn canonical_name() {
        // Message without CNAMEs.
        let mut msg = MessageBuilder::new_dgram_vec().question();
        unwrap!(
            msg.push((unwrap!(Dname::vec_from_str("example.com.")), Rtype::A))
        );
        let msg_ref = msg.as_message_ref();
        assert_eq!(
            unwrap!(Dname::vec_from_str("example.com.")),
            unwrap!(msg_ref.canonical_name())
        );

        // Message with CNAMEs.
        let mut msg = msg.answer();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("bar.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("foo.example.com.")))
        )));
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("foo.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("bar.example.com.")))
        )));
        let msg_ref = msg.as_message_ref();
        println!("{:02x?}", msg_ref.as_slice());
        assert_eq!(
            unwrap!(Dname::vec_from_str("baz.example.com.")),
            unwrap!(msg_ref.canonical_name())
        );
    }

    #[test]
    fn message_iterator() {
        let msg = get_test_message();
        let mut iter = msg.iter();

        // Check that it returns a record from first section
        let (_rr, section) = unwrap!(unwrap!(iter.next()));
        assert_eq!(Section::Answer, section);

        // Check that it advances to next section
        let (_rr, section) = unwrap!(unwrap!(iter.next()));
        assert_eq!(Section::Authority, section);
    }

    #[test]
    fn copy_records() {
        let msg = get_test_message();
        let target = MessageBuilder::new_dgram_vec().question();
        let res = msg.copy_records(target.answer(), |rec| {
            if let Ok(rr) = rec {
                if let Ok(Some(rr)) =
                        rr.into_record::<AllRecordData<_, ParsedDname<_>>>() {
                    if rr.rtype() == Rtype::Cname {
                        return Some(rr);
                    }
                }
            }
            return None;
        });

        assert!(res.is_ok());
        if let Ok(target) = res {
            let msg = target.into_message();
            assert_eq!(1, msg.header_counts().ancount());
            assert_eq!(0, msg.header_counts().arcount());
        }
    }
}

