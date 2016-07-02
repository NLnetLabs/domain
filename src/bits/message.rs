//! DNS messages.
//!
//! This module defines types for both looking into existing messages as
//! well as building new ones. For looking into messages there are two base
//! types, `Message` and `MessageBuf` for message slices and owned messages
//! respectively. For building messages, there is only one type
//! `MessageBuilder` that is generic over an underlying composer.

use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use iana::{Class, Rcode, RRType};
use rdata::Cname;
use super::compose::{ComposeBytes, ComposeBuf};
use super::error::{ComposeError, ComposeResult, ParseError, ParseResult};
use super::header::{Header, HeaderCounts, FullHeader};
use super::name::{AsDName, DNameSlice};
use super::parse::{ContextParser, ParseBytes};
use super::question::{Question, QuestionTarget};
use super::rdata::{GenericRecordData, RecordData};
use super::record::{Record, RecordTarget};


//============ Disecting Existing Messages ==================================

//------------ Message ------------------------------------------------------

/// A bytes slice containing a DNS message.
///
/// You can acccess the header and each of the sections through dedicated
/// methods. Access to the three resource record sections happens lazily.
/// That is, each of those methods iterates over the previous sections to
/// find where the respective section starts. Because of this, it will be
/// more efficient to either use the `next_section()` method on the section
/// or get all sections at once with `Message`’s `sections()` method.
///
/// In addition, since the type is a thin wrapper around the underlying
/// bytes slice, it deref to `[u8]`, so you get to play with all of slice’s
/// methods.
#[derive(Debug)]
pub struct Message {
    /// The underlying bytes slice.
    slice: [u8]
}

/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes slice.
    ///
    /// This fails if the slice is too short to even contain the full header.
    /// No further checks are done, though, so if this function returns `Ok`,
    /// the message may still be broken.
    pub fn from_bytes(slice: &[u8]) -> ParseResult<&Self> {
        if slice.len() < mem::size_of::<FullHeader>() {
            Err(ParseError::UnexpectedEnd)
        }
        else {
            Ok(unsafe { Message::from_bytes_unsafe(slice) })
        }
    }

    /// Creates a message from a bytes slice without further checks.
    ///
    /// You need to make sure that the slice is at least the length of a
    /// full message header.
    unsafe fn from_bytes_unsafe(slice: &[u8]) -> &Self {
        mem::transmute(slice)
    }

    /// Creates a mutable message from a bytes slice unsafely.
    ///
    /// You need to make sure that the slice is at least the length of a
    /// full message header.
    unsafe fn from_bytes_unsafe_mut(slice: &mut [u8]) ->&mut Self {
        mem::transmute(slice)
    }

    /// Returns an owned copy of this message.
    pub fn to_owned(&self) -> MessageBuf {
        unsafe { MessageBuf::from_bytes_unsafe(&self.slice) }
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.slice
    }
}


/// # Header Access
///
impl Message {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        unsafe { Header::from_message(&self.slice) }
    }

    /// Returns a mutable reference to the message header.
    ///
    /// The header is the only part of an already constructed message that
    /// can be safely manipulated without extra ado, so this is the only
    /// mutable method.
    pub fn header_mut(&mut self) -> &mut Header {
        unsafe { Header::from_message_mut(&mut self.slice) }
    }

    /// Returns a reference to the header counts of the message.
    pub fn counts(&self) -> &HeaderCounts {
        unsafe { HeaderCounts::from_message(&self.slice) }
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
        let mut parser = ContextParser::new(&self.slice);
        parser.skip(mem::size_of::<FullHeader>()).unwrap();
        QuestionSection::new(parser, self.counts())
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
        try!(self.answer()).next_section().unwrap()
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> ParseResult<RecordSection> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(&self) -> ParseResult<RecordSection> {
        try!(self.authority()).next_section().unwrap()
    }

    /// Returns all four sections in one fell swoop.
    ///
    /// This is the most effective way if you need more than one of the
    /// record sections.
    pub fn sections(&self) -> ParseResult<(QuestionSection, RecordSection,
                                           RecordSection, RecordSection)> {
        let question = self.question();
        let answer = try!(question.clone().next_section());
        let authority = try!(answer.next_section().unwrap());
        let additional = try!(authority.next_section().unwrap());
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
        if !self.header().qr() { false }
        else if self.counts().qdcount() != query.counts().qdcount() { false }
        else { self.question().eq(query.question()) }
    }

    /// Returns the first question, if there is any.
    pub fn first_question(&self) -> Option<Question> {
        match self.question().next() {
            None | Some(Err(..)) => None,
            Some(Ok(question)) => Some(question)
        }
    }

    /// Returns the query type of the first question, if any.
    pub fn qtype(&self) -> Option<RRType> {
        self.first_question().map(|x| x.qtype())
    }

    /// Returns whether the message contains answers of a given type.
    pub fn contains_answer<'a, D: RecordData<'a>>(&'a self) -> bool {
        let answer = match self.answer() {
            Ok(answer) => answer,
            Err(..) => return false
        };
        answer.iter::<D>().next().is_some()
    }

    /// Resolves the canonical name of the answer.
    ///
    /// Returns `None` if either the message doesn’t have a question or there
    /// was a parse error. Otherwise starts with the question’s name,
    /// follows any CNAME trail and returns the name answers should be for.
    pub fn canonical_name<'a>(&self) -> Option<Cow<DNameSlice>> {
        // XXX There may be cheaper ways to do this ...
        let question = match self.first_question() {
            None => return None,
            Some(question) => question
        };
        let mut name = match question.qname().clone().into_cow() {
            Err(..) => return None,
            Ok(qname) => qname
        };
        let mut map = HashMap::new();
        let answer = match self.answer() {
            Err(..) => return None,
            Ok(answer) => answer
        };
        for record in answer.iter::<Cname>() {
            let record = match record {
                Err(..) => break,
                Ok(record) => record
            };
            let from = match record.name().clone().into_cow() {
                Err(..) => continue,
                Ok(from) => from
            };
            let to = match record.rdata().cname().clone().into_cow() {
                Err(..) => continue,
                Ok(to) => to
            };
            map.insert(from, to);
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

impl Deref for Message {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.slice
    }
}

impl Borrow<[u8]> for Message {
    fn borrow(&self) -> &[u8] { self.deref() }
}

impl AsRef<Message> for Message {
    fn as_ref(&self) -> &Message { self }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] { self.deref() }
}


//--- ToOwned

impl ToOwned for Message {
    type Owned = MessageBuf;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}


//--- PartialEq
//
// Note: We can’t be Eq because anything with parse errors always is unequal.

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        if self.header() != other.header()
                || self.counts() != other.counts() {
            return false
        }

        let mut me = self.question();
        let mut you = other.question();
        loop {
            match (me.next(), you.next()) {
                (None, None) => break,
                (_, None) | (None, _) => return false,
                (Some(me), Some(you)) => if me != you { return false }
            }
        }

        let mut me = match me.answer() {
            Err(..) => return false,
            Ok(me) => me
        };
        let mut you = match you.answer() {
            Err(..) => return false,
            Ok(you) => you
        };
        loop {
            if me != you { return false }
            me = match me.next_section() {
                None => break,
                Some(Err(..)) => return false,
                Some(Ok(me)) => me
            };
            you = match you.next_section() {
                None => break, // XXX Wait a second!
                Some(Err(..)) => return false,
                Some(Ok(you)) => you
            };
        }
        true
    }
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
    /// If the content of the vector is to short to even contain a full
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
        Ok(MessageBuf { inner: Vec::from(&msg.slice) })
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

    /// Creates an owned message as a query for the given question.
    ///
    /// The resulting query will have the RD bit set and will contain exactly
    /// one entry in the question section with the given question.
    pub fn query_from_question<N: AsDName>(qname: &N, qtype: RRType,
                                           qclass: Class)
                                           -> ComposeResult<MessageBuf> {
        let mut msg = try!(MessageBuilder::new(Some(512), true));
        msg.header_mut().set_rd(true);
        try!(Question::push(&mut msg, qname, qtype, qclass));
        Ok(try!(MessageBuf::from_vec(try!(msg.finish()).finish())))
    }
}


//--- Deref, DerefMut, Borrow, and AsRef

impl Deref for MessageBuf {
    type Target = Message;

    fn deref(&self) -> &Message {
        unsafe { Message::from_bytes_unsafe(&self.inner) }
    }
}

impl DerefMut for MessageBuf {
    fn deref_mut(&mut self) -> &mut Message {
        unsafe { Message::from_bytes_unsafe_mut(&mut self.inner) }
    }
}

impl Borrow<Message> for MessageBuf {
    fn borrow(&self) -> &Message {
        self.deref()
    }
}

impl AsRef<Message> for MessageBuf {
    fn as_ref(&self) -> &Message {
        self
    }
}


//------------ QuestionSection ----------------------------------------------

/// The question section of a `Message`.
///
/// This type is an iterator over the questions. Since parsing questions can
/// fail, it actually iterates over `ParseResult<Question>`. If a parse error
/// is encountered, iteration will return that error and then stop. In other
/// words, the end of iteration (or a for loop) does not mean the section
/// was successfully parsed. Ideally, you bail out of iteration like so:
///
/// ```no_run
/// use domain::bits::ParseResult;
/// use domain::bits::message::QuestionSection;
///
/// fn print_questions(section: QuestionSection) -> ParseResult<()> {
///     for question in section {
///         let question = try!(question);
///         println!("{}", question);
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct QuestionSection<'a> {
    /// The parser for generating the questions.
    parser: ContextParser<'a>,

    /// A reference to the section counts in the underlying message.
    ///
    /// We need to keep this to pass on to the next section iterators.
    counts: &'a HeaderCounts,

    /// The remaining number of questions.
    ///
    /// The `ParseResult` is here to monitor an error during iteration.
    /// This error will be returned when encountered and by `answer()`
    /// should that be called after an error.
    count: ParseResult<u16>
}

impl<'a> QuestionSection<'a> {
    /// Creates a new question section from a parser and the section count.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        let count = Ok(counts.qdcount());
        QuestionSection { parser: parser, counts: counts, count: count }
    }

    /// Returns an iterator.
    ///
    /// Use this method with a for loop to avoid the section being consumed.
    pub fn iter(&mut self) -> &mut Self {
        self
    }

    /// Proceeds to the answer section.
    ///
    /// Skips the remaining questions, if any, and then converts `self` into
    /// the first `RecordSection`.
    pub fn answer(mut self) -> ParseResult<RecordSection<'a>> {
        for question in self.iter() {
            let _ = try!(question);
        }
        match self.count {
            Ok(..) => Ok(RecordSection::new(self.parser, self.counts,
                                            Section::first())),
            Err(err) => Err(err)
        }
    }

    /// Proceeds to the answer section.
    ///
    /// This is the same as `self.answer()`.
    pub fn next_section(self) -> ParseResult<RecordSection<'a>> {
        self.answer()
    }
}

impl<'a> Iterator for QuestionSection<'a> {
    type Item = ParseResult<Question<'a>>;

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


//------------ Section ------------------------------------------------------

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

/// One of the three sections containing resource records.
///
/// Since resource records are generic over the `RecordData` trait, this type
/// isn’t an iterator over the records. Instead, the method `iter()` can be
/// used to request an iterator for a specific implementation. For instance,
/// the following function prints all the A records:
///
/// ```no_run
/// use domain::bits::ParseResult;
/// use domain::bits::message::RecordSection;
/// use domain::rdata::A;
///
/// fn print_a(section: &RecordSection) -> ParseResult<()> {
///     for record in section.iter::<A>() {
///         let record = try!(record);
///         println!("{}", record);
///     }
///     Ok(())
/// }
/// ```
#[derive(Clone, Debug)]
pub struct RecordSection<'a> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// A reference to the message’s section counts.
    counts: &'a HeaderCounts,

    /// Which section are we, actually?
    section: Section
}

impl<'a> RecordSection<'a> {
    /// Creates a new section from its components.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts,
           section: Section) -> Self {
        RecordSection { parser: parser, counts: counts, section: section }
    }

    /// Returns an iterator over records of a record data implementation. 
    ///
    /// In most cases, you will have to call this function with the record
    /// data implementation as a type parameter, such as
    /// `section.iter::<A>()` for A records.
    ///
    /// The returned value will be an iterator over all records the
    /// record data implementation feels responsible for. You can use
    /// `GenericRecordData` if you want all records or use the
    /// `generic_iter()` convenience method.
    pub fn iter<D: RecordData<'a>>(&self) -> RecordIter<'a, D> {
        RecordIter::new(self.parser.clone(),
                        self.section.count(&self.counts))
    }

    /// Returns an iterator over all records in the section.
    ///
    /// The records will be represented using the `GenericRecordData` type
    /// for the record data.
    pub fn generic_iter(&self) -> RecordIter<'a, GenericRecordData<'a>> {
        self.iter()
    }

    /// Returns the next section if there is one.
    pub fn next_section(&self) -> Option<ParseResult<Self>> {
        self.section.next_section().map(|section| {
            let mut iter = self.iter::<GenericRecordData<'a>>();
            try!(iter.exhaust());
            Ok(RecordSection::new(iter.parser, self.counts, section))
        })
    }
}


//--- PartialEq

impl<'a> PartialEq for RecordSection<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.iter::<GenericRecordData<'a>>().eq(
            other.iter::<GenericRecordData<'a>>())
    }
}


//------------ RecordIter ---------------------------------------------------

/// An iterator over the records in one of a record section.
///
/// The type is generic over a a record data implementation and iterates over
/// all records in the section this implementation feels responsible for.
/// Since parsing resource records can fail, the type iterates over
/// `ParseResult`s. If an error is encountered, the error is the last step
/// in the iteration.
#[derive(Clone, Debug)]
pub struct RecordIter<'a, D: RecordData<'a>> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// The number of records remaining in the section.
    count: ParseResult<u16>,

    /// A phantom.
    marker: PhantomData<D>
}

impl<'a, D: RecordData<'a>> RecordIter<'a, D> {
    /// Creates a new iterator using the given parser and record count.
    fn new(parser: ContextParser<'a>, count: u16) -> Self {
        RecordIter { parser: parser, count: Ok(count), marker: PhantomData }
    }

    /// Returns an iterator.
    ///
    /// Use this method with a for loop to avoid the section being consumed.
    pub fn iter(&mut self) -> &mut Self {
        self
    }

    /// Walks over all the records in the iterator.
    fn exhaust(&mut self) -> ParseResult<()> {
        for record in self.iter() {
            let _ = try!(record);
        }
        Ok(())
    }
}


//--- Iterator

impl<'a, D: RecordData<'a>> Iterator for RecordIter<'a, D> {
    type Item = ParseResult<Record<'a, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.count {
                Ok(count) if count > 0 => {
                    match Record::parse(&mut self.parser) {
                        Ok(result) => {
                            self.count = Ok(count - 1);
                            if let Some(record) = result {
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


//============ Building a New Message =======================================

//------------ MessageBuilder -----------------------------------------------

/// A builder for constructing a DNS message.
///
/// Message are being built in place. This requires that they are being
/// assembled section by section. To make sure this is done correctly, each
/// section has its own type that allows you to either add elements to its
/// section, progress to the next one, or finish up, leaving the following
/// sections empty.
///
/// Adding elements happens in one of two ways. The types all have a `push()`
/// method that takes a reference to a value of the element type—either
/// `Question` or `Record`. Alternatively, there is a shortcut through the
/// `QuestionTarget` and `RecordTarget` traits one of which is implemented
/// by the section types. These traits are used by `Question::push()` and
/// various `push()` functions of concrete record data types (such as
/// `A::push()`) to allow you to build elements on the fly without building
/// element values first.
///
/// Since the header is of fixed size and at the beginning of the assembled
/// message, there is no need to have a separate section type for it. Instead,
/// each section types allows access to it through the `header()` and
/// `header_mut()` methods.
///
/// The `MessageBuilder` type also represents the first section, the
/// question section. You can add questions as described above. Once you
/// are done with the question section, you either call the `answer()` method
/// to proceed to the answer section or `finish()` to finalize the message
/// and retrieve the underlying data.
///
/// This underlying data alway is a value of a type implementing the
/// `ComposeBytes` trait. The default type is `ComposeBuf` which becomes a
/// simple bytes vector.
///
/// If you call `answer()` to progress to building the answer section, you
/// trace the `MessageBuilder` for an `AnswerBuilder`. This new value
/// behaves similarly. You can access the header via `header()` and
/// `header_mut()`, add resource records through the `push()` method or
/// the `RecordTarget` shortcut, and finalize message building via `finish()`.
/// Additionally, you can call `authority()` to trade once more for the next
/// section and an `AuthorityBuilder`. Same deal except that `additional()`
/// takes you to the additional section and a `AdditionalBuilder`. This is
/// the final section so once you added all records, you call `finsih()` to
/// trade the builder for the final message.
///
///
/// # Example
///
/// To summarize building of messages, here is an example that builds a
/// response to an A query for example.com that contains two A records and
/// nothing else.
///
/// ```
/// use std::str::FromStr;
/// use domain::bits::{DNameBuf, MessageBuilder, Question};
/// use domain::rdata::A;
///
/// let name = DNameBuf::from_str("example.com.").unwrap();
/// let mut msg = MessageBuilder::new(Some(512), true).unwrap();
/// msg.header_mut().set_rd(true);
/// Question::push_in(&mut msg, &name, A::rtype()).unwrap();
/// let mut msg = msg.answer();
/// A::push_from_octets(&mut msg, &name, 86400, 192, 0, 2, 1).unwrap();
/// A::push_from_octets(&mut msg, &name, 86400, 192, 0, 2, 2).unwrap();
/// let _ = msg.finish().unwrap().finish(); // get the Vec<u8>
/// ```
///
/// ```
#[derive(Clone, Debug)]
pub struct MessageBuilder<C: ComposeBytes=ComposeBuf> {
    /// The actual message being built.
    target: MessageTarget<C>
}

/// # Creation
///
impl<C: ComposeBytes> MessageBuilder<C> {
    /// Creates a new message builder using the given target.
    pub fn from_target(target: C) -> ComposeResult<Self> {
        MessageTarget::new(target)
                      .map(|target| MessageBuilder { target: target })
    }
}

/// # Creation for ComposeBuf-backed builder.
///
impl MessageBuilder<ComposeBuf> {
    /// Creates a new message builder using a new `ComposeBuf` as target.
    ///
    /// If `maxlen` is not `None`, the resulting message’s length will never
    /// exceed the given amount of bytes. If too much data is being added,
    /// the message will be cut back a quesiton or record boundary and the
    /// TC flag will be set.
    ///
    /// If `compress` is `true`, domain name compression will be activated
    /// for the resulting message. Not all domain names are compressed,
    /// though, only the question names, record names, and names embedded
    /// in resource data of well-known record types (those defined in RFC
    /// 1035).
    ///
    /// This function can fail if `maxlen` is chosen too small to even
    /// accomodate the full header, ie., it is less than 12.
    pub fn new(maxlen: Option<usize>, compress: bool) -> ComposeResult<Self> {
        MessageBuilder::from_target(ComposeBuf::new(maxlen, compress))
    }
}

/// # Building
///
impl<C: ComposeBytes> MessageBuilder<C> {
    /// Returns a reference to the message’s header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the message’s header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Appends a new question to the message.
    pub fn push(&mut self, question: &Question) -> ComposeResult<()> {
        self.target.push(|target| question.compose(target),
                         |counts| counts.inc_qdcount(1))
    }

    /// Proceeds to building the answer section.
    pub fn answer(self) -> AnswerBuilder<C> {
        AnswerBuilder::new(self.target)
    }

    /// Finishes the message and returns the underlying target.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


//--- QuestionTarget

impl<C: ComposeBytes> QuestionTarget<C> for MessageBuilder<C> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()> {
        self.target.push(push, |counts| counts.inc_qdcount(1))
    }
}


//------------ AnswerBuilder ------------------------------------------------

/// A builder for the answer section of a message.
///
/// See `MessageBuilder` for more information.
#[derive(Clone, Debug)]
pub struct AnswerBuilder<C: ComposeBytes> {
    /// The actual message being built.
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AnswerBuilder<C> {
    /// Creates a new answer builder from the message target.
    fn new(target: MessageTarget<C>) -> Self {
        AnswerBuilder { target: target }
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Appends a new resource record to the answer section.
    pub fn push<'a, D: RecordData<'a>>(&mut self, record: &Record<'a, D>)
                                       -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Proceeds to building the authority section.
    pub fn authority(self) -> AuthorityBuilder<C> {
        AuthorityBuilder::new(self.target)
    }

    /// Finishes the message.
    ///
    /// The resulting message will have empty authority and additional
    /// sections.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


impl<C: ComposeBytes> RecordTarget<C> for AnswerBuilder<C> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()> {
        self.target.push(push, |counts| counts.inc_ancount(1))
    }
}



//------------ AuthorityBuilder ---------------------------------------------

/// A builder for the authority section of a message.
///
/// See `MessageBuilder` for more information.
#[derive(Clone, Debug)]
pub struct AuthorityBuilder<C: ComposeBytes> {
    /// The actual message being built.
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AuthorityBuilder<C> {
    /// Creates a new authority builder from the message target.
    fn new(target: MessageTarget<C>) -> Self {
        AuthorityBuilder { target: target }
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Appends a new resource record to the answer section.
    pub fn push<'a, D: RecordData<'a>>(&mut self, record: &Record<'a, D>)
                                       -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Proceeds to building the additional section.
    pub fn additional(self) -> AdditionalBuilder<C> {
        AdditionalBuilder::new(self.target)
    }

    /// Finishes the message.
    ///
    /// The resulting message will have an empty additional section.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


impl<C: ComposeBytes> RecordTarget<C> for AuthorityBuilder<C> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()> {
        self.target.push(push, |counts| counts.inc_nscount(1))
    }
}


//------------ AdditionalBuilder --------------------------------------------

/// A builder for the additional section of a message.
///
/// See `MessageBuilder` for more information.
#[derive(Clone, Debug)]
pub struct AdditionalBuilder<C: ComposeBytes> {
    /// The actual message being built.
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AdditionalBuilder<C> {
    /// Creates a new additional builder from the message target.
    fn new(target: MessageTarget<C>) -> Self {
        AdditionalBuilder { target: target }
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Appends a new resource record to the answer section.
    pub fn push<'a, D: RecordData<'a>>(&mut self, record: &Record<'a, D>)
                                       -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Finishes the message.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


impl<C: ComposeBytes> RecordTarget<C> for AdditionalBuilder<C> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()> {
        self.target.push(push, |counts| counts.inc_arcount(1))
    }
}


//------------ MessageTarget ------------------------------------------------

/// Underlying data for constructing a DNS message.
///
/// This private type does all the heavy lifting for constructing messages.
#[derive(Clone, Debug)]
struct MessageTarget<C: ComposeBytes> {
    /// The underlying bytes target.
    target: C,

    /// The message’s header.
    header: FullHeader,

    /// Position in build where the message starts.
    start: C::Pos,
}


impl<C: ComposeBytes> MessageTarget<C> {
    /// Creates a new message target atop a given target.
    fn new(mut target: C) -> ComposeResult<Self> {
        let start = target.pos();
        try!(target.push_empty(mem::size_of::<FullHeader>()));
        Ok(MessageTarget {
            target: target,
            header: FullHeader::new(),
            start: start
        })
    }

    /// Returns a reference to the message’s header.
    fn header(&self) -> &Header {
        self.header.header()
    }

    /// Returns a mutable reference to the message’s header.
    fn header_mut(&mut self) -> &mut Header {
        self.header.header_mut()
    }

    /// Pushes something to the end of the message.
    ///
    /// There’s two closures here. The first one, `composeop` actually
    /// writes the data. The second, `incop` increments the counter in the
    /// messages header to reflect the new element.
    fn push<O, I>(&mut self, composeop: O, incop: I) -> ComposeResult<()>
            where O: FnOnce(&mut C) -> ComposeResult<()>,
                  I: FnOnce(&mut HeaderCounts) -> ComposeResult<()> {
        if !self.target.truncated() {
            self.target.truncation_point();
            match composeop(&mut self.target) {
                Ok(()) => {
                    try!(incop(self.header.counts_mut()));
                    Ok(())
                }
                Err(ComposeError::SizeExceeded) => Ok(()),
                Err(error) => Err(error)
            }
        }
        else { Ok(()) }
    }

    /// Finishes the message building and extracts the underlying target.
    fn finish(mut self) -> ComposeResult<C> {
        self.header.header_mut().set_tc(self.target.truncated());
        try!(self.target.update_bytes(self.start, self.header.as_bytes()));
        Ok(self.target)
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use bits::name::DName;
    use bits::question::Question;
    use bits::record::Record;
    use iana::{Class, RRType};
    use rdata::{A, Cname};
    use super::*;

    struct ExampleMessage<'a> {
        bytes: Vec<u8>,
        question: Question<'a>,
        rec1: Record<'a, A>,
        rec2: Record<'a, A>,
        rec3: Record<'a, A>
    }

    impl<'a> ExampleMessage<'a> {
        fn new() -> Self {
            let name = DName::from_str("example.com.").unwrap();
            let question = Question::new(name.clone(), RRType::A, Class::In);
            let rec1 = Record::new(name.clone(), Class::In, 86400,
                                   A::from_octets(192, 0, 2, 1));
            let rec2 = Record::new(name.clone(), Class::In, 86400,
                                   A::from_octets(192, 0, 2, 2));
            let rec3 = Record::new(name.clone(), Class::In, 86400,
                                   A::from_octets(192, 0, 2, 3));
            
            let mut msg = MessageBuilder::new(None, true).unwrap();
            msg.header_mut().set_qr(true);
            msg.push(&question).unwrap();
            let mut msg = msg.answer();
            msg.push(&rec1).unwrap();
            msg.push(&rec2).unwrap();
            let mut msg = msg.authority().additional();
            msg.push(&rec3).unwrap();
            let bytes = msg.finish().unwrap().finish();

            ExampleMessage { bytes: bytes, question: question,
                             rec1: rec1, rec2: rec2, rec3: rec3 }
        }
    }

    #[test]
    fn short_message() {
        assert!(Message::from_bytes(&[0u8; 11]).is_err());
        assert!(MessageBuf::from_vec(vec![0u8; 11]).is_err());
    }

    #[test]
    fn build_and_parse() {
        let x = ExampleMessage::new();

        let msg = Message::from_bytes(&x.bytes).unwrap();
        assert!(msg.header().qr());
        assert!(!msg.header().ad());

        let mut q = msg.question();
        let item = q.next().unwrap().unwrap();
        assert_eq!(item, x.question);
        assert!(q.next().is_none());

        let s = q.answer().unwrap();
        let mut iter = s.iter::<A>();
        let item = iter.next().unwrap().unwrap();
        assert_eq!(item, x.rec1);
        let item = iter.next().unwrap().unwrap();
        assert_eq!(item, x.rec2);
        let item = iter.next().unwrap().unwrap();
        assert_eq!(item, x.rec3);
        assert!(iter.next().is_none())
    }

    #[test]
    fn canonical_name() {
        // Message without CNAMEs.
        let mut msg = MessageBuilder::new(None, true).unwrap();
        Question::push_in(&mut msg, &DName::from_str("example.com.").unwrap(),
                                    RRType::A).unwrap();
        let msg = MessageBuf::from_vec(msg.finish().unwrap().finish())
                             .unwrap();
        assert_eq!(DName::from_str("example.com.").unwrap(),
                   msg.canonical_name().unwrap());
                   
        // Message with CNAMEs.
        let mut msg = MessageBuilder::new(None, true).unwrap();
        Question::push_in(&mut msg, &DName::from_str("example.com.").unwrap(),
                                    RRType::A).unwrap();
        let mut answer = msg.answer();
        Cname::push(&mut answer, &DName::from_str("bar.example.com.").unwrap(),
                    Class::In, 86400,
                    &DName::from_str("baz.example.com.").unwrap()).unwrap();
        Cname::push(&mut answer, &DName::from_str("example.com.").unwrap(),
                    Class::In, 86400,
                    &DName::from_str("foo.example.com.").unwrap()).unwrap();
        Cname::push(&mut answer, &DName::from_str("foo.example.com.").unwrap(),
                    Class::In, 86400,
                    &DName::from_str("bar.example.com.").unwrap()).unwrap();
        let msg = MessageBuf::from_vec(answer.finish().unwrap().finish())
                             .unwrap();
        assert_eq!(DName::from_str("baz.example.com.").unwrap(),
                   msg.canonical_name().unwrap());
                   
    }
}

