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


use std::collections::HashMap;
use std::{borrow, mem, ops};
use std::marker::PhantomData;
use ::iana::{Rcode, Rtype};
use ::rdata::Cname;
use super::{HeaderSection, GenericRecord, Header, HeaderCounts, ParsedDName,
            ParsedRecordData, Parser, ParseError, ParseResult, Question,
            Record};

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
pub struct Message {
    inner: [u8]
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
    pub fn from_bytes(bytes: &[u8]) -> ParseResult<&Self> {
        if bytes.len() < mem::size_of::<HeaderSection>() {
            Err(ParseError::UnexpectedEnd)
        }
        else {
            Ok(unsafe { Self::from_bytes_unsafe(bytes) })
        }
    }

    /// Creates a message from a bytes slice without further checks.
    ///
    /// You need to make sure that the slice is at least the length of a
    /// full message header.
    pub unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    /// Creates a mutable message from a bytes slice unsafely.
    ///
    /// You need to make sure that the slice is at least the length of a
    /// full message header.
    unsafe fn from_bytes_unsafe_mut(bytes: &mut [u8]) ->&mut Self {
        mem::transmute(bytes)
    }

    /// Returns an owned copy of this message.
    pub fn to_owned(&self) -> MessageBuf {
        unsafe { MessageBuf::from_bytes_unsafe(&self.inner) }
    }

    /// Returns a reference to the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}


/// # Header Section
///
impl Message {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        Header::from_message(&self.inner)
    }

    /// Returns a mutable reference to the message header.
    ///
    /// The header is the only part of an already constructed message that
    /// can be safely manipulated without extra ado, so this is the only
    /// mutable method.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::from_message_mut(&mut self.inner)
    }

    /// Returns a reference to the header counts of the message.
    pub fn counts(&self) -> &HeaderCounts {
        HeaderCounts::from_message(&self.inner)
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
        let mut parser = Parser::new(&self.inner);
        parser.skip(mem::size_of::<HeaderSection>()).unwrap();
        QuestionSection::new(parser)
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection { self.question() }

    /// Returns the answer section.
    pub fn answer(&self) -> ParseResult<RecordSection> {
        self.question().next_section()
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(&self) -> ParseResult<RecordSection> {
        self.answer()
    }

    /// Returns the authority section.
    pub fn authority(&self) -> ParseResult<RecordSection> {
        try!(self.answer()).next_section().map(Option::unwrap)
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> ParseResult<RecordSection> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(&self) -> ParseResult<RecordSection> {
        try!(self.authority()).next_section().map(Option::unwrap)
    }

    /// Returns all four sections in one fell swoop.
    pub fn sections(&self) -> ParseResult<(QuestionSection, RecordSection,
                                           RecordSection, RecordSection)> {
        let question = self.question();
        let answer = try!(question.clone().next_section());
        let authority = try!(answer.clone().next_section()
                                                .map(Option::unwrap));
        let additional = try!(authority.clone().next_section()
                                               .map(Option::unwrap));
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
    pub fn is_answer<M: AsRef<Message>>(&self, query: M) -> bool {
        let query = query.as_ref();
        if !self.header().qr()
                || self.counts().qdcount() != query.counts().qdcount() {
            false
        }
        else { self.question().eq(query.question()) }
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(&self) -> Option<Question<ParsedDName>> {
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
    pub fn contains_answer<'a, D: ParsedRecordData<'a>>(&'a self) -> bool {
        let answer = match self.answer() {
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
}


//--- Deref, Borrow, and AsRef

impl ops::Deref for Message {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl borrow::Borrow<[u8]> for Message {
    fn borrow(&self) -> &[u8] { self }
}

impl AsRef<Message> for Message {
    fn as_ref(&self) -> &Message { self }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] { self }
}


//--- ToOwned

impl ToOwned for Message {
    type Owned = MessageBuf;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}


//------------ MessageBuf ---------------------------------------------------

/// An owned DNS message.
///
/// This type owns the underlying bytes of the message and derefs into a
/// [`Message`] for all processing. For more information on DNS messages
/// and how they can be accessed, please refer to the documentation of
/// the [`Message`] type.
///
/// This is, however, not the type for building messages. Use
/// [`MessageBuilder`] instead.
///
/// [`Message`]: struct.Message.html
/// [`MessageBuider`]: ../message_builder/struct.MessageBuilder.html
#[derive(Clone, Debug)]
pub struct MessageBuf {
    /// The underlying bytes vector.
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl MessageBuf {
    /// Creates a new owned message using the given vector.
    ///
    /// If the content of the vector is too short to even contain a full
    /// header, the function fails.
    pub fn from_vec(vec: Vec<u8>) -> ParseResult<Self> {
        let _ = try!(Message::from_bytes(&vec));
        Ok(MessageBuf { inner: vec })
    }

    /// Creates a new owned message cloning the data from the bytes slice.
    ///
    /// If the slice is too short to even contain a full header section,
    /// the function fails.
    pub fn from_bytes(slice: &[u8]) -> ParseResult<Self> {
        let msg = try!(Message::from_bytes(slice));
        Ok(MessageBuf { inner: Vec::from(&msg.inner) })
    }

    /// Creates a new owned message from the bytes slice unsafely.
    ///
    /// This does not check whether the slice is long enough.
    unsafe fn from_bytes_unsafe(slice: &[u8]) -> Self {
        MessageBuf { inner: Vec::from(slice) }
    }

    /// Returns a reference to the message slice.
    pub fn as_slice(&self) -> &Message {
        self
    }
}


//--- Deref, DerefMut, Borrow, AsRef, AsMut

impl ops::Deref for MessageBuf {
    type Target = Message;

    fn deref(&self) -> &Message {
        unsafe { Message::from_bytes_unsafe(&self.inner) }
    }
}

impl ops::DerefMut for MessageBuf {
    fn deref_mut(&mut self) -> &mut Message {
        unsafe { Message::from_bytes_unsafe_mut(&mut self.inner) }
    }
}

impl borrow::Borrow<Message> for MessageBuf {
    fn borrow(&self) -> &Message {
        self
    }
}

impl AsRef<Message> for MessageBuf {
    fn as_ref(&self) -> &Message {
        self
    }
}

impl AsRef<[u8]> for MessageBuf {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<Message> for MessageBuf {
    fn as_mut(&mut self) -> &mut Message {
        self
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
pub struct QuestionSection<'a> {
    /// The parser for generating the questions.
    parser: Parser<'a>,

    /// The remaining number of questions.
    ///
    /// The `ParseResult` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: ParseResult<u16>
}

impl<'a> QuestionSection<'a> {
    /// Creates a new question section from a parser.
    fn new(parser: Parser<'a>) -> Self {
        QuestionSection {
            count: Ok(HeaderCounts::from_message(parser.bytes()).qdcount()),
            parser: parser,
        }
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into
    /// the first [`RecordSection`].
    ///
    /// [`RecordSection`]: ../struct.RecordSection.html
    pub fn answer(mut self) -> ParseResult<RecordSection<'a>> {
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
    pub fn next_section(self) -> ParseResult<RecordSection<'a>> {
        self.answer()
    }
}


//--- Iterator

impl<'a> Iterator for QuestionSection<'a> {
    type Item = ParseResult<Question<ParsedDName<'a>>>;

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
pub struct RecordSection<'a> {
    /// The parser for generating the questions.
    parser: Parser<'a>,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of questions.
    ///
    /// The `ParseResult` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: ParseResult<u16>
}


impl<'a> RecordSection<'a> {
    /// Creates a new section from a parser positioned at the section start.
    fn new(parser: Parser<'a>, section: Section) ->  Self {
        RecordSection {
            count: Ok(section.count(
                           HeaderCounts::from_message(parser.bytes()))),
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
    pub fn limit_to<D: ParsedRecordData<'a>>(self) -> RecordIter<'a, D> {
        RecordIter::new(self)
    }

    /// Returns the next section if there is one.
    pub fn next_section(mut self) -> ParseResult<Option<Self>> {
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

impl<'a> Iterator for RecordSection<'a> {
    type Item = ParseResult<GenericRecord<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match Record::parse_generic(&mut self.parser) {
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
pub struct RecordIter<'a, D: ParsedRecordData<'a>> {
    section: RecordSection<'a>,
    marker: PhantomData<D>
}

impl<'a, D: ParsedRecordData<'a>> RecordIter<'a, D> {
    /// Creates a new limited record iterator from the given section.
    fn new(section: RecordSection<'a>) -> Self {
        RecordIter{section: section, marker: PhantomData}
    }

    /// Trades in the limited iterator for the complete iterator.
    ///
    /// The complete iterator will continue right after the last record
    /// returned by `self`. It will *not* restart from the beginning of the
    /// section.
    pub fn into_inner(self) -> RecordSection<'a> {
        self.section
    }

    /// Returns the next section if there is one.
    pub fn next_section(self) -> ParseResult<Option<RecordSection<'a>>> {
        self.section.next_section()
    }
}


//--- Iterator

impl<'a, D: ParsedRecordData<'a>> Iterator for RecordIter<'a, D> {
    type Item = ParseResult<Record<ParsedDName<'a>, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.section.count {
                Ok(count) if count > 0 => {
                    match Record::parse(&mut self.section.parser) {
                        Ok(record) => {
                            self.section.count = Ok(count - 1);
                            if let Some(record) = record {
                                return Some(Ok(record))
                            }
                        }
                        Err(err) => {
                            self.section.count = Err(err.clone());
                            return Some(Err(err))
                        }
                    }
                }
                _ => return None
            }
        }
    }
}


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
