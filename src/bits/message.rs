//! Accessing exisiting DNS messages.
//!
//! This module defines a number of types for disecting the content of a
//! DNS message in wire format. There are two basic types that wrap the bytes
//! of such a message: [`Message`] for a unsized bytes slice and
//! [`MessageBuf`] for an owned message.
//!
//! Detailed information on the structure of messages and how they are
//! accessed can be found with the [`Message`] type.
//!
//!
//! [`Message`]: struct.Message.html
//! [`MessageBuf`]: struct.MessageBuf.html

use std::{mem, ops};
//use std::collections::HashMap;
use std::marker::PhantomData;
use bytes::Bytes;
use ::iana::{Rcode, Rtype};
//use ::rdata::Cname;
use super::header::{Header, HeaderCounts, HeaderSection};
use super::name::{ParsedDname, ParsedDnameError};
use super::parse::{Parseable, Parser, ShortParser};
use super::question::{Question, QuestionParseError};
use super::rdata::RecordData;
use super::record::{Record, RecordHeader, RecordHeaderParseError,
                    RecordParseError};


//------------ Message -------------------------------------------------------

/// A slice of a DNS message.
///
/// This types wraps a bytes slice with the binary content of a DNS message
/// and allows parsing the content for further processing.
///
/// Typically, you create a message slice by passing a slice with its raw
/// bytes to the [`from_bytes()`] function. This function only does a quick
/// if there are enough bytes for the minimum message size. All further
/// parsing happens lazily when you access more of the message.
///
/// Section 4 of [RFC 1035] defines DNS messages as being divded into five
/// sections named header, question, answer, authority, and additional.
///
/// The header section is of a fixed sized and can be accessed without
/// further checks through the methods given under [Header Section]. Most
/// likely, you will be interested in the first part of the header references 
/// to which are returned by the [`header()`] and [`header_mut()`] methods.
/// The second part of the header section contains the number of entries
/// in the following four sections and is of less interest as there are
/// more sophisticated ways of accessing these sections. If you do care,
/// you can get a reference through [`counts()`].
///
/// The question section contains what was asked of the DNS by a request.
/// These questions consist of a domain name, a record type and class. With
/// normal queries, a requests asks for all records of the given record type
/// that are owned by the domain name within the class. There will normally
/// be exactly one question for normal queries. With other query operations,
/// the questions may refer to different things.
///
/// You can get access to the question section through the [`question()`]
/// method. It returns a [`QuestionSection`] value that is an iterator over
/// questions. Since a single question is a very common case, there is a 
/// convenience method [`first_question()`] that simple returns the first
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
/// There are functions to access all three sections directly: [`answer()`],
/// [`authority()`], and [`additional()`]. However, since there are no
/// pointers to where the later sections start, accessing them directly
/// means iterating over the previous sections. This is why it is more
/// efficitent to call [`next_section()`] on the returned value and process
/// them in order. Alternatively, you can use the [`sections()`] function
/// that gives you all four sections at once with the minimal amount of
/// iterating necessary.
///
/// Each record in the record sections is of a specific type. Each type has
/// its specific record data. Because there are so many types, we decided
/// against having a giant enum. Instead, the type representing a record
/// section, somewhat obviously named [`RecordSection`], iterates over
/// [`GenericRecord`]s with limited options on what you can do with the data.
/// If you are looking for a specific record type, you can get an iterator
/// limited to records of that type through the `limit_to()` method. This
/// method is generic over a record data type fit for parsing (typically
/// meaning that it is taken from the [domain::rdata::parsed] module). So,
/// if you want to iterate over the MX records in the answer section, you
/// would do something like this:
///
/// ```
/// # use domain::bits::message::Message;
/// use domain::rdata::parsed::Mx;
///
/// # let bytes = &vec![0; 12];
/// let msg = Message::from_bytes(bytes).unwrap();
/// for record in msg.answer().unwrap().limit_to::<Mx>() {
///     // Do something with the record ...
/// }
/// ```
///
/// Note that because of lazy parsing, the iterator actually returns a
/// [`ParseResult<_>`]. One quick application of `try!()` fixes this:
///
/// ```
/// use domain::bits::{Message, ParseResult};
/// use domain::rdata::parsed::Mx;
///
/// fn process_mx(msg: &Message) -> ParseResult<()> {
///     for record in msg.answer().unwrap().limit_to::<Mx>() {
///         let record = try!(record);
///         // Do something with the record ...
///     }
///     Ok(())
/// }
/// ```
///
/// [`additional()`]: #method.additional
/// [`answer()`]: #method.answer
/// [`authority()`]: #method.authority
/// [`counts()`]: #method.counts
/// [`first_question()`]: #method.first_question
/// [`from_bytes()`]: #method.from_bytes
/// [`header()`]: #method.header
/// [`header_mut()`]: #method.header_mut
/// [`limit_to()`]: ../struct.RecordSection.html#method.limit_to
/// [`next_section()`]: ../struct.RecordSection.html#method.next_section
/// [`question()`]: #method.question
/// [`sections()`]: #method.sections
/// [`ParseResult<_>`]: ../parse/type.ParseResult.html
/// [`GenericRecord`]: ../../record/type.GenericRecord.html
/// [`QuestionSection`]: ../struct.QuestionSection.html
/// [`RecordSection`]: ../struct.RecordSection.html
/// [domain::rdata::parsed]: ../../rdata/parsed/index.html
/// [Header Section]: #header-section
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone, Debug)]
pub struct Message {
    bytes:Bytes,
}

/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes slice.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns `Ok`, the message may still be broken with methods
    /// returning `Err(_)`.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortParser> {
        if bytes.len() < mem::size_of::<HeaderSection>() {
            Err(ShortParser)
        }
        else {
            Ok(Message { bytes })
        }
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


/// # Header Section
///
impl Message {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(self.as_slice())
    }

    /// Returns a refernce the header counts of the message.
    pub fn header_counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.as_slice())
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
impl Message {
    /// Returns the question section.
    pub fn question(&self) -> QuestionSection {
        QuestionSection::new(self.bytes.clone())
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection { self.question() }

    /// Returns the answer section.
    pub fn answer(&self) -> Result<RecordSection, MessageParseError> {
        Ok(self.question().next_section()?)
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(&self) -> Result<RecordSection, MessageParseError> {
        self.answer()
    }

    /// Returns the authority section.
    pub fn authority(&self) -> Result<RecordSection, MessageParseError> {
        Ok(self.answer()?.next_section()?.unwrap())
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> Result<RecordSection, MessageParseError> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(&self) -> Result<RecordSection, MessageParseError> {
        Ok(self.authority()?.next_section()?.unwrap())
    }

    /// Returns all four sections in one fell swoop.
    pub fn sections(&self) -> Result<(QuestionSection, RecordSection,
                                      RecordSection, RecordSection),
                                     MessageParseError> {
        let question = self.question();
        let answer = question.clone().next_section()?;
        let authority = answer.clone().next_section()?.unwrap();
        let additional = authority.clone().next_section()?.unwrap();
        Ok((question, answer, authority, additional))
    }
}


/// # Helpers for Common Tasks
///
impl Message {
    /// Returns whether this is the answer to some other message.
    ///
    /// The method checks whether the ID fields of the headers are the same,
    /// whether the QR flag is set in this message, and whether the questions
    /// are the same.
    pub fn is_answer(&self, query: &Message) -> bool {
        if !self.header().qr()
                || self.header_counts().qdcount()
                        != query.header_counts().qdcount() {
            false
        }
        else { self.question().eq(query.question()) }
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(&self) -> Option<Question<ParsedDname>> {
        match self.question().next() {
            None | Some(Err(..)) => None,
            Some(Ok(question)) => Some(question)
        }
    }

    /// Returns the query type of the first question, if any.
    pub fn qtype(&self) -> Option<Rtype> {
        self.first_question().map(|x| x.qtype())
    }

    /// Returns whether the message contains answers of a given type.
    pub fn contains_answer<D: RecordData>(&self) -> bool {
        let answer = match self.answer() {
            Ok(answer) => answer,
            Err(..) => return false
        };
        answer.limit_to::<D>().next().is_some()
    }

    /*
    /// Resolves the canonical name of the answer.
    ///
    /// Returns `None` if either the message doesn’t have a question or there
    /// was a parse error. Otherwise starts with the question’s name,
    /// follows any CNAME trail and returns the name answers should be for.
    pub fn canonical_name(&self) -> Option<ParsedDName> {
        // XXX There may be cheaper ways to do this ...
        let question = match self.first_question() {
            None => return None,
            Some(question) => question
        };
        let mut name = question.qname().clone();
        let mut map = HashMap::new();
        let answer = match self.answer() {
            Err(..) => return None,
            Ok(answer) => answer
        };
        for record in answer.limit_to::<Cname<ParsedDName>>() {
            let record = match record {
                Err(..) => return None,
                Ok(record) => record
            };
            map.insert(record.name().clone(), record.data().cname().clone());
        }
        loop {
            match map.remove(&name) {
                None => return Some(name),
                Some(new_name) => name = new_name
            }
        }
    }
    */
}


//--- Deref, Borrow, and AsRef

impl ops::Deref for Message {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<Message> for Message {
    fn as_ref(&self) -> &Message {
        self
    }
}

impl AsRef<Bytes> for Message {
    fn as_ref(&self) -> &Bytes {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}


//------------ QuestionSection ----------------------------------------------

/// An iterator over the question section of a DNS message.
///
/// The iterator’s item is `ParseResult<Question<PackedDName>>`. In case of
/// a parse error, `next()` will return with `Some<ParserError<_>>` once and
/// `None` after that.
///
/// You can create a value of this type through the [`Message::section()`]
/// method. Use the [`answer()`] or [`next_section()`] methods to proceed
/// to an iterator over the answer section.
///
/// [`Message::section()`]: struct.Message.html#method.section
/// [`answer()`]: #method.answer
/// [`next_section()`]: #method.next_section
#[derive(Clone, Debug)]
pub struct QuestionSection {
    /// The parser for generating the questions.
    parser: Parser,

    /// The remaining number of questions.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, QuestionParseError>
}

impl QuestionSection {
    /// Creates a new question section from a parser.
    fn new(bytes: Bytes) -> Self {
        let mut parser = Parser::from_bytes(bytes);
        parser.advance(mem::size_of::<HeaderSection>()).unwrap();
        QuestionSection {
            count: Ok(HeaderCounts::for_message_slice(
                                                parser.as_slice()).qdcount()),
            parser: parser,
        }
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into
    /// the first [`RecordSection`].
    ///
    /// [`RecordSection`]: ../struct.RecordSection.html
    pub fn answer(mut self) -> Result<RecordSection, QuestionParseError> {
        for question in &mut self {
            let _ = try!(question);
        }
        match self.count {
            Ok(..) => Ok(RecordSection::new(self.parser, Section::first())),
            Err(err) => Err(err)
        }
    }

    /// Proceeds to the answer section.
    ///
    /// This is an alias for the [`answer()`] method.
    pub fn next_section(self) -> Result<RecordSection, QuestionParseError> {
        self.answer()
    }
}


//--- Iterator

impl Iterator for QuestionSection {
    type Item = Result<Question, QuestionParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match Question::parse(&mut self.parser) {
                    Ok(question) => {
                        self.count = Ok(count - 1);
                        Some(Ok(question))
                    }
                    Err(err) => {
                        self.count = Err(err.clone());
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional
}


impl Section {
    /// Returns the first section.
    fn first() -> Self { Section::Answer }

    /// Returns the correct record count for this section.
    fn count(&self, counts: &HeaderCounts) -> u16 {
        match *self {
            Section::Answer => counts.ancount(),
            Section::Authority => counts.nscount(),
            Section::Additional => counts.arcount()
        }
    }

    /// Returns the value for the following section or `None` if this is last.
    fn next_section(self) -> Option<Self> {
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
/// The iterator’s item is `ParseResult<GenericRecord>`. A [`GenericRecord`]
/// is a record with [`GenericRecordData`] as its data, meaning that access
/// to data is somewhat limited. You can, however, trade this type in for
/// a [`RecordIter`] that iterates over records of a specific type through
/// the [`limit_to::<D>()`] method.
///
/// `RecordSection` values cannot be created directly. You can get one either
/// by calling the method for the section in question of a [`Message`] value
/// or by proceeding from another section via its `next_section()` method.
///
/// [`GenericRecord`]: ../record/type.GenericRecord.html
/// [`GenericRecordData`]: ../rdata/struct.GenericRecordData.html
/// [`RecordIter`]: struct.RecordIter.html
/// [`limit_to::<D>()`]: #method.limit_to
/// [`Message`]: struct.Message.html
#[derive(Clone, Debug)]
pub struct RecordSection {
    /// The parser for generating the questions.
    parser: Parser,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of questions.
    ///
    /// The `ParseResult` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, RecordHeaderParseError>
}


impl RecordSection {
    /// Creates a new section from a parser positioned at the section start.
    fn new(parser: Parser, section: Section) ->  Self {
        RecordSection {
            count: Ok(section.count(
                        HeaderCounts::for_message_slice(parser.as_slice()))),
            section: section,
            parser: parser
        }
    }

    /// Trades `self` in for an iterator limited to a concrete record type.
    ///
    /// The record type is given through its record data type. If this type
    /// is generic, it must be the variant for parsed data. Type aliases for
    /// all record data types implemented by this crate can be found in
    /// the [domain::rdata::parsed] module.
    ///
    /// The returned limited iterator will continue at the current position
    /// of `self`. It will *not* start from the beginning of the section.
    pub fn limit_to<D: RecordData>(self) -> RecordIter<D> {
        RecordIter::new(self)
    }

    /// Returns the next section if there is one.
    pub fn next_section(mut self)
                        -> Result<Option<Self>, RecordHeaderParseError> {
        let section = match self.section.next_section() {
            Some(section) => section,
            None => return Ok(None)
        };
        for record in &mut self {
            let _ = try!(record);
        }
        match self.count {
            Ok(..) => Ok(Some(RecordSection::new(self.parser, section))),
            Err(err) => Err(err)
        }
    }
}


//--- Iterator

impl Iterator for RecordSection {
    type Item = Result<RecordHeader, RecordHeaderParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match RecordHeader::parse_and_skip(&mut self.parser) {
                    Ok(record) => {
                        self.count = Ok(count - 1);
                        Some(Ok(record))
                    }
                    Err(err) => {
                        self.count = Err(err.clone());
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//------------ RecordIter ----------------------------------------------------

/// An iterator over specific records of a record section of a DNS message.
///
/// The iterator’s item type is `ParseResult<Record<ParsedDName, D>>`. It
/// silently skips over all records that `D` cannot or does not want to
/// parse.
///
/// You can create a value of this type through the
/// [`RecordSection::limit_to::<D>()`] method.
///
/// [`RecordSection::limit_to::<D>()`]: struct.RecordSection.html#method.limit_to
#[derive(Clone, Debug)]
pub struct RecordIter<D: RecordData> {
    parser: Parser,
    section: Section,
    count: Result<u16, RecordParseError<ParsedDnameError, D::ParseErr>>,
    marker: PhantomData<D>
}

impl<D: RecordData> RecordIter<D> {
    /// Creates a new limited record iterator from the given section.
    fn new(section: RecordSection) -> Self {
        RecordIter {
            parser: section.parser,
            section: section.section,
            count: Ok(section.count.unwrap()),
            marker: PhantomData
        }
    }

    /// Trades in the limited iterator for the complete iterator.
    ///
    /// The complete iterator will continue right after the last record
    /// returned by `self`. It will *not* restart from the beginning of the
    /// section.
    pub fn unwrap(self)
                  -> Result<RecordSection,
                            RecordParseError<ParsedDnameError, D::ParseErr>> {
        Ok(RecordSection {
            parser: self.parser,
            section: self.section,
            count: Ok(self.count?)
        })
    }

    /// Returns the next section if there is one.
    pub fn next_section(self)
                        -> Result<Option<RecordSection>,
                                  RecordParseError<ParsedDnameError,
                                                   D::ParseErr>> {
        Ok(self.unwrap()?.next_section()?)
    }
}


//--- Iterator

impl<D: RecordData> Iterator for RecordIter<D> {
    type Item = Result<Record<ParsedDname, D>,
                       RecordParseError<ParsedDnameError, D::ParseErr>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.count {
                Ok(count) if count > 0 => {
                    let header = match RecordHeader::parse(&mut self.parser) {
                        Ok(header) => header,
                        Err(err) => {
                            let err = RecordParseError::from(err);
                            self.count = Err(err.clone());
                            return Some(Err(err))
                        }
                    };
                    match header.parse_into_record(&mut self.parser) {
                        Ok(data) => {
                            self.count = Ok(count - 1);
                            if let Some(record) = data {
                                return Some(Ok(record))
                            }
                        }
                        Err(err) => {
                            self.count = Err(err.clone());
                            return Some(Err(err))
                        }
                    }
                }
                _ => return None
            }
        }
    }
}


//------------ MessageParseError ---------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum MessageParseError {
    Name(ParsedDnameError),
    ShortParser,
}

impl From<ParsedDnameError> for MessageParseError {
    fn from(err: ParsedDnameError) -> Self {
        MessageParseError::Name(err)
    }
}

impl From<QuestionParseError<ParsedDnameError>> for MessageParseError {
    fn from(err: QuestionParseError<ParsedDnameError>) -> Self {
        match err {
            QuestionParseError::Name(err) => MessageParseError::Name(err),
            QuestionParseError::ShortParser => MessageParseError::ShortParser,
        }
    }
}

impl From<RecordHeaderParseError<ParsedDnameError>> for MessageParseError {
    fn from(err: RecordHeaderParseError<ParsedDnameError>) -> Self {
        match err {
            RecordHeaderParseError::Name(err) => MessageParseError::Name(err),
            RecordHeaderParseError::ShortParser
                => MessageParseError::ShortParser
        }
    }
}

impl From<ShortParser> for MessageParseError {
    fn from(_: ShortParser) -> Self {
        MessageParseError::ShortParser
    }
}


/*
//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use bits::compose::ComposeMode;
    use bits::message_builder::MessageBuilder;
    use bits::name::DNameBuf;
    use iana::Rtype;
    use rdata::owned::Cname;
    use super::*;

    #[test]
    fn short_message() {
        assert!(Message::from_bytes(&[0u8; 11]).is_err());
        assert!(MessageBuf::from_vec(vec![0u8; 11]).is_err());
    }

    #[test]
    fn canonical_name() {
        // Message without CNAMEs.
        let mut msg = MessageBuilder::new(ComposeMode::Unlimited,
                                          true).unwrap();
        msg.push((DNameBuf::from_str("example.com.").unwrap(),
                  Rtype::A)).unwrap();
        let msg = MessageBuf::from_vec(msg.finish()).unwrap();
        assert_eq!(DNameBuf::from_str("example.com.").unwrap(),
                   msg.canonical_name().unwrap());
                   
        // Message with CNAMEs.
        let mut msg = MessageBuilder::new(ComposeMode::Unlimited,
                                          true).unwrap();
        msg.push((DNameBuf::from_str("example.com.").unwrap(),
                  Rtype::A)).unwrap();
        let mut answer = msg.answer();
        answer.push((DNameBuf::from_str("bar.example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("baz.example.com.")
                                         .unwrap())))
              .unwrap();
        answer.push((DNameBuf::from_str("example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("foo.example.com.")
                                         .unwrap())))
              .unwrap();
        answer.push((DNameBuf::from_str("foo.example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("bar.example.com.")
                                         .unwrap())))
              .unwrap();
        let msg = MessageBuf::from_vec(answer.finish()).unwrap();
        assert_eq!(DNameBuf::from_str("baz.example.com.").unwrap(),
                   msg.canonical_name().unwrap());
    }
}
*/
