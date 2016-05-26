//! DNS messages.
//!
//! This module defines types for both looking into existing messages as
//! well as building new ones. For looking into messages there are two base
//! types, `Message` and `MessageBuf` for message slices and owned messages
//! respectively. For building messages, there is only one type
//! `MessageBuilder` that is generic over an underlying composer.
//!
//! # Parsing Messages
//!
//! Once you obtained the wire-representation of a message you can parse its
//! content with the `Message` or `MessageBuf` types. The difference is that
//! the former operates on a bytes slice while the latter owns that slice
//! through a bytes vector and then derefs into the former.
//!
//! Each DNS message consists of a header and four sections. In order to
//! allow the parser to be lazy, you will have to iterate over the sections
//! in their order. That is, to get to the answer section, you first have to
//! walk over all the questions. The header is an exception. Since it is of
//! a fixed length and placed at the beginning of the message, it is always
//! accessible through the message type.
//!
//! While iterating over the questions is trivial, things are a little more
//! difficult for the record sections. Here the iterators are generic over
//! the `FlatRecordData` trait. You can either look for records of a certain
//! type or use the LazyGenericRecordData type for all the records. Or, if
//! you are looking for a specific set of types, define an enum for them and
//! implement `FlatRecordData` for it.
//!
//! # Building Messages
//!
//! Building messages is relatively straightforward. You create a message
//! builder either by supplying a target or, if using a byte vector as the
//! ultimate target sounds good enough, with the size and whether you want
//! compression.
//!
//! Then you can go from section to section and append items. At each step
//! you can finalize the message, leaving the following sections empty.
//!
//! # Example
//!
//! As an example, let’s put together a message and then parse it.
//!
//! ```
//! use domain::bits::message::{MessageBuilder, Message};
//! use domain::bits::name::OwnedDName;
//! use domain::bits::iana::{Class, RRType};
//! use domain::bits::rdata::A;
//! use domain::bits::record::RecordRef;
//!
//! let mut msg = MessageBuilder::new(Some(512), true).unwrap();
//! let name = OwnedDName::from_str("example.com.").unwrap();
//! msg.header_mut().set_qr(true);
//! let mut q = msg.question();
//! q.push(&(&name, RRType::A)).unwrap();
//! let mut a = q.answer(); 
//! a.push(&RecordRef::new(name.as_ref(), Class::IN, 86400,
//!                        A::from_octets(192, 0, 2, 1)))
//!  .unwrap();
//! a.push(&RecordRef::new(name.as_ref(), Class::IN, 86400,
//!                        A::from_octets(192, 0, 2, 2)))
//!  .unwrap();
//! let bytes = a.finish().unwrap();
//!
//! let msg = Message::from_bytes(&bytes).unwrap();
//! let mut q = msg.question();
//! for item in q.iter() {
//!     println!("Question: {}", item.unwrap());
//! }
//! let a = q.answer().unwrap();
//! for item in a.iter::<A>() {
//!     println!("Answer: {}", item.unwrap());
//! }
//! ```

use std::borrow::Borrow;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use super::compose::{ComposeBytes, ComposeVec};
use super::error::{ComposeError, ComposeResult, ParseError, ParseResult};
use super::flavor;
use super::header::{Header, HeaderCounts, FullHeader};
use super::parse::{ContextParser, ParseBytes};
use super::question::{ComposeQuestion, LazyQuestion};
use super::rdata::{GenericRecordData, FlatRecordData};
use super::record::{ComposeRecord, LazyRecord};


//============ Disecting Existing Messages ==================================

//------------ Message ------------------------------------------------------

/// A bytes slice containing a DNS message.
///
/// This type allows access to the header of the message directly. To start
/// looking at the content of the message, you acquire a `QuestionSection`
/// by calling the `question()` method. The question section can then be
/// converted further into the three record sections.
///
/// Everything parsed out of a message will be of the lazy flavor.
///
/// This is an unsized type.
#[derive(Debug)]
pub struct Message {
    /// The underlying bytes slice.
    slice: [u8]
}

/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes slice.
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

    /// Returns the length of the underlying bytes slice.
    pub fn len(&self) -> usize {
        self.slice.len()
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

    /// Returns an iterator over the question section
    pub fn question(&self) -> QuestionSection {
        let mut parser = ContextParser::new(&self.slice, &self.slice);
        parser.skip(mem::size_of::<FullHeader>()).unwrap();
        QuestionSection::new(parser, self.counts())
    }
}


/// # Miscellaneous
///
impl Message {
    /// Returns whether this is the answer to some other message.
    pub fn is_answer(&self, query: &Message) -> bool {
        if !self.header().qr() { false }
        else if self.counts().qdcount() != query.counts().qdcount() { false }
        else { self.question().eq(query.question()) }
    }
}


//--- AsRef

impl AsRef<Message> for Message {
    fn as_ref(&self) -> &Message { self }
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
/// `Message` for all actual work.
#[derive(Clone, Debug)]
pub struct MessageBuf {
    /// The underlying bytes vector.
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl MessageBuf {
    /// Creates a new owned message using the given vec.
    pub fn from_vec(vec: Vec<u8>) -> ParseResult<Self> {
        let _ = try!(Message::from_bytes(&vec));
        Ok(MessageBuf { inner: vec })
    }

    /// Creates a new owned message with the data from the given bytes slice.
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
    ///
    /// The method is generic over the `ComposeQuestion` trait which is
    /// implemented by the question types as well as a tuple of name, class,
    /// and type. In the latter case, note that the method takes a reference,
    /// so you have to add the `&` in front of the tuple for this to work.
    pub fn query_from_question<C: ComposeQuestion>(question: &C)
            -> ComposeResult<MessageBuf> {
        let mut msg = try!(MessageBuilder::new(Some(512), true));
        msg.header_mut().set_rd(true);
        let mut q = msg.question();
        try!(q.push(question));
        Ok(try!(MessageBuf::from_vec(try!(q.finish()).finish())))
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

/// An iterator over the questions in a `Message`.
/// 
/// You can iterate over the questions in the usual way. At any point, you
/// can call `answer()` to proceed to the answer section of the message.
#[derive(Clone, Debug)]
pub struct QuestionSection<'a> {
    /// The parser for generating the questions.
    parser: ContextParser<'a>,

    /// A reference to the section counts in the underlying message.
    ///
    /// We need to keep this to pass on to the next section iterators.
    counts: &'a HeaderCounts,

    /// The remaining number of questions.
    count: u16
}

impl<'a> QuestionSection<'a> {
    /// Creates a new question section from a parser and the section count.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        let count = counts.qdcount();
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
    /// an `AnswerSection`.
    pub fn answer(mut self) -> ParseResult<AnswerSection<'a>> {
        for question in self.iter() {
            if let Err(e) = question {
                return Err(e)
            }
        }
        Ok(AnswerSection::new(self.parser, self.counts))
    }
}

impl<'a> Iterator for QuestionSection<'a> {
    type Item = ParseResult<LazyQuestion<'a>>;

    /// Returns the next question if there are any left.
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        Some(LazyQuestion::parse(&mut self.parser)
                      .map(|res| { self.count -= 1; res }))
    }
}


//------------ AnswerSection ------------------------------------------------

/// The answer section of a message.
///
/// This type isn’t an interator itself but the `iter()` method can be used
/// to fetch an iterator for a specific record type, ie., anything that
/// implements the `FlatRecordData` trait.
#[derive(Clone, Debug)]
pub struct AnswerSection<'a> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// A reference to the message’s section counts.
    counts: &'a HeaderCounts,
}

impl<'a> AnswerSection<'a> {
    /// Creates a new answer section from parser and counts.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AnswerSection { parser: parser, counts: counts }
    }

    /// Returns an iterator over records covered by `D`.
    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.ancount())
    }

    /// Proceeds to the authority section of the message.
    pub fn authority(self) -> ParseResult<AuthoritySection<'a>> {
        let mut iter = self.iter::<GenericRecordData<'a, flavor::Lazy<'a>>>();
        try!(iter.exhaust());
        Ok(AuthoritySection::new(iter.parser, self.counts))
    }
}


//------------ AuthoritySection ---------------------------------------------

/// The authority section of a message.
///
/// This is mostly identical to `AnswerSection`, see there for more details.
#[derive(Clone, Debug)]
pub struct AuthoritySection<'a> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// A reference to the message’s section counts.
    counts: &'a HeaderCounts,
}

impl<'a> AuthoritySection<'a> {
    /// Creates a new answer section from parser and counts.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AuthoritySection { parser: parser, counts: counts }
    }

    /// Returns an iterator over records covered by `D`.
    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.nscount())
    }

    /// Proceeds to the additional section of the message.
    pub fn additional(self) -> ParseResult<AdditionalSection<'a>> {
        let mut iter = self.iter::<GenericRecordData<'a, flavor::Lazy<'a>>>();
        try!(iter.exhaust());
        Ok(AdditionalSection::new(iter.parser, self.counts))
    }
}


//------------ AdditionalSection --------------------------------------------

/// The additional section of a message.
///
/// This is mostly identical to `AnswerSection`, see there for more details.
#[derive(Clone, Debug)]
pub struct AdditionalSection<'a> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// A reference to the message’s section counts.
    counts: &'a HeaderCounts,
}

impl<'a> AdditionalSection<'a> {
    /// Creates a new answer section from parser and counts.
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AdditionalSection { parser: parser, counts: counts }
    }

    /// Returns an iterator over records covered by `D`.
    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.arcount())
    }
}


//------------ RecordIter ---------------------------------------------------

/// An iterator over the records in one of a record section.
///
/// Iterates over all the records in the section that `D` feels responsible
/// for.
#[derive(Clone, Debug)]
pub struct RecordIter<'a, D: FlatRecordData<'a, flavor::Lazy<'a>>> {
    /// The message’s parser.
    parser: ContextParser<'a>,

    /// The number of records remaining in the section.
    count: u16,

    /// A phantom.
    marker: PhantomData<D>
}

impl<'a, D: FlatRecordData<'a, flavor::Lazy<'a>>> RecordIter<'a, D> {
    /// Creates a new iterator using the given parser and record count.
    fn new(parser: ContextParser<'a>, count: u16) -> Self {
        RecordIter { parser: parser, count: count, marker: PhantomData }
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
            if let Err(e) = record {
                return Err(e)
            }
        }
        Ok(())
    }

    /// Returns the parse result for the next record.
    fn step(&mut self) -> ParseResult<Option<LazyRecord<'a, D>>> {
        LazyRecord::parse(&mut self.parser).map(|res| { self.count -= 1; res })
    }
}

impl<'a, D> Iterator for RecordIter<'a, D>
            where D: FlatRecordData<'a, flavor::Lazy<'a>> {
    type Item = ParseResult<LazyRecord<'a, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        loop {
            match self.step() {
                Ok(Some(record)) => return Some(Ok(record)),
                Ok(None) => (),
                Err(e) => return Some(Err(e)),
            }
        }
    }
}


//============ Building New Message =========================================

//------------ MessageBuilder -----------------------------------------------

/// A builder for constructing a DNS message.
///
/// This is generic over the composer trait but defaults to the bytes vector
/// backed composer.
#[derive(Clone, Debug)]
pub struct MessageBuilder<C: ComposeBytes=ComposeVec> {
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

/// # Creation for ComposeVec-backed builder.
///
impl MessageBuilder<ComposeVec> {
    /// Creates a new message builder.
    pub fn new(maxlen: Option<usize>, compress: bool) -> ComposeResult<Self> {
        MessageBuilder::from_target(ComposeVec::new(maxlen, compress))
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

    /// Finishes building the message and returns the underlying composition.
    ///
    /// This will result in a message with four empty sections.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }

    /// Proceeds to building the question section.
    pub fn question(self) -> QuestionBuilder<C> {
        QuestionBuilder::new(self.target)
    }
}


//------------ QuestionBuilder ----------------------------------------------

/// A builder for the question section of a message.
#[derive(Clone, Debug)]
pub struct QuestionBuilder<C: ComposeBytes> {
    /// The actual message being built.
    target: MessageTarget<C>
}

impl<C: ComposeBytes> QuestionBuilder<C> {
    /// Creates a question builder appending questions to the target.
    fn new(target: MessageTarget<C>) -> Self {
        QuestionBuilder { target: target }
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Appends a new question to the message.
    pub fn push<Q: ComposeQuestion>(&mut self, question: &Q)
                                   -> ComposeResult<()> {
        self.target.push(|target| question.compose(target),
                         |counts| counts.inc_qdcount(1))
    }

    /// Proceeds to building the answer section.
    pub fn answer(self) -> AnswerBuilder<C> {
        AnswerBuilder::new(self.target)
    }

    /// Finishes the message.
    ///
    /// This will result in a message with empty record sections.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


//------------ AnswerBuilder ------------------------------------------------

/// A builder for the answer section of a message.
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
    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
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


//------------ AuthorityBuilder ---------------------------------------------

/// A builder for the authority section of a message.
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

    /// Appends a new resource record to the authority section.
    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_nscount(1))
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


//------------ AdditionalBuilder --------------------------------------------

/// A builder for the additional section of a message.
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

    /// Appends a new resource record to the additional section.
    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_nscount(1))
    }

    /// Finishes the message.
    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
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
    use super::*;
    use bits::name::OwnedDName;
    use bits::iana::{Class, RRType};
    use bits::question::OwnedQuestion;
    use bits::rdata::A;
    use bits::record::OwnedRecord;

    struct ExampleMessage {
        bytes: Vec<u8>,
        name: OwnedDName,
        question: OwnedQuestion,
        rec1: OwnedRecord<A>,
        rec2: OwnedRecord<A>,
        rec3: OwnedRecord<A>
    }

    impl ExampleMessage {
        fn new() -> Self {
            let name = OwnedDName::from_str("example.com.").unwrap();
            let question = OwnedQuestion::new(name.clone(), RRType::A,
                                              Class::IN);
            let rec1 = OwnedRecord::new(name.clone(), Class::IN, 86400,
                                        A::from_octets(192, 0, 2, 1));
            let rec2 = OwnedRecord::new(name.clone(), Class::IN, 86400,
                                        A::from_octets(192, 0, 2, 2));
            let rec3 = OwnedRecord::new(name.clone(), Class::IN, 86400,
                                        A::from_octets(192, 0, 2, 3));
            
            let mut msg = MessageBuilder::new(None, true).unwrap();
            msg.header_mut().set_qr(true);
            let mut q = msg.question();
            q.push(&question).unwrap();
            let mut a = q.answer();
            a.push(&rec1).unwrap();
            a.push(&rec2).unwrap();
            let mut a = a.authority().additional();
            a.push(&rec3).unwrap();
            let bytes = a.finish().unwrap().finish();

            ExampleMessage { bytes: bytes, name: name, question: question,
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
        assert_eq!(item.to_owned().unwrap(), x.question);
        assert!(q.next().is_none());

        let mut s = q.answer();
        let iter = s.iter::<A>();
        let item = iter.next().unwrap().unwrap();
        assert_eq!(item.to_owned().unwrap(), x.rec1);
    }
}

