//! Accessing exisiting DNS messages.

use std::collections::HashMap;
use std::{borrow, mem, ops};
use std::marker::PhantomData;
use ::iana::{Rcode, Rtype};
use ::rdata::Cname;
use super::{FullHeader, GenericRecord, Header, HeaderCounts, ParsedDName,
            ParsedRecordData, Parser, ParseError, ParseResult, Question,
            Record};

//------------ Message -------------------------------------------------------

pub struct Message {
    inner: [u8]
}

/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes slice.
    ///
    /// This fails if the slice is too short to even contain the full header.
    /// No further checks are done, though, so if this function returns `Ok`,
    /// the message may still be broken.
    pub fn from_bytes(bytes: &[u8]) -> ParseResult<&Self> {
        if bytes.len() < mem::size_of::<FullHeader>() {
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
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
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

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}


/// # Header Access
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
        parser.skip(mem::size_of::<FullHeader>()).unwrap();
        QuestionSection::new(parser)
    }

    /// Returns the zone section of a UPDATE message.
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
    ///
    /// This is the most effective way if you need more than one of the
    /// record sections.
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
    /// This checks whether the ID fields of the header are the same,
    /// whether the QR flag is set and whether the questions are the same.
    pub fn is_answer(&self, query: &Message) -> bool {
        if !self.header().qr()
                || self.counts().qdcount() != query.counts().qdcount() {
            false
        }
        else { self.question().eq(query.question()) }
    }

    /// Returns the first question, if there is any.
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
/// Contains the underlying bytes of the message as a vector. Derefs to
/// `Message` for all actual functionality.
///
/// This is not the type for building messages. Use `MessageBuilder` instead.
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

    /// Creates a new owned message with the data from the given bytes slice.
    ///
    /// If the content of the vector is to short to even contain a full
    /// header, the function fails.
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

    /// Returns a message slice.
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
    /// Skips the remaining questions, if any, and then converts `self` into
    /// the first `RecordSection`.
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

#[derive(Clone, Debug)]
pub struct RecordIter<'a, D: ParsedRecordData<'a>> {
    section: RecordSection<'a>,
    marker: PhantomData<D>
}

impl<'a, D: ParsedRecordData<'a>> RecordIter<'a, D> {
    fn new(section: RecordSection<'a>) -> Self {
        RecordIter{section: section, marker: PhantomData}
    }

    /// Trades in the iterator for the underlying section.
    pub fn into_inner(self) -> RecordSection<'a> {
        self.section
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

