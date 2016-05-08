//! DNS messages.

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
/// Everything parsed out of a message will be of the lazy flavor.
///
/// This is an unsized type.
#[derive(Debug)]
pub struct Message {
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

    unsafe fn from_bytes_unsafe(slice: &[u8]) -> &Self {
        mem::transmute(slice)
    }

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
    /// Returns whether this the answer to some other message.
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
#[derive(Clone, Debug)]
pub struct MessageBuf {
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl MessageBuf {
    /// Creates a new owned message from the underlying vec.
    pub fn from_vec(vec: Vec<u8>) -> ParseResult<Self> {
        let _ = try!(Message::from_bytes(&vec));
        Ok(MessageBuf { inner: vec })
    }

    /// Creates a new owned message from a bytes slice.
    pub fn from_bytes(slice: &[u8]) -> ParseResult<Self> {
        let msg = try!(Message::from_bytes(slice));
        Ok(MessageBuf { inner: Vec::from(&msg.slice) })
    }

    unsafe fn from_bytes_unsafe(slice: &[u8]) -> Self {
        MessageBuf { inner: Vec::from(slice) }
    }

    pub fn as_slice(&self) -> &Message {
        self
    }

    pub fn query_from_question<C: ComposeQuestion>(question: &C)
            -> ComposeResult<MessageBuf> {
        let mut msg = try!(MessageBuilder::new(
                                          ComposeVec::new(Some(512), true)));
        msg.header_mut().set_rd(true);
        msg.header_mut().set_ad(true);
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

#[derive(Clone, Debug)]
pub struct QuestionSection<'a> {
    parser: ContextParser<'a>,
    counts: &'a HeaderCounts,
    count: u16
}

impl<'a> QuestionSection<'a> {
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        let count = counts.qdcount();
        QuestionSection { parser: parser, counts: counts, count: count }
    }

    pub fn iter(&mut self) -> &mut Self {
        self
    }

    /// Continues to the answer section.
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

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        Some(LazyQuestion::parse(&mut self.parser)
                      .map(|res| { self.count -= 1; res }))
    }
}


//------------ AnswerSection ------------------------------------------------

/// The answer section of a message.
#[derive(Clone, Debug)]
pub struct AnswerSection<'a> {
    parser: ContextParser<'a>,
    counts: &'a HeaderCounts,
}

impl<'a> AnswerSection<'a> {
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AnswerSection { parser: parser, counts: counts }
    }

    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.ancount())
    }

    pub fn authority(self) -> ParseResult<AuthoritySection<'a>> {
        let mut iter = self.iter::<GenericRecordData<'a, flavor::Lazy<'a>>>();
        try!(iter.exhaust());
        Ok(AuthoritySection::new(iter.parser, self.counts))
    }
}


//------------ AuthoritySection ---------------------------------------------

/// The authority section of a message.
#[derive(Clone, Debug)]
pub struct AuthoritySection<'a> {
    parser: ContextParser<'a>,
    counts: &'a HeaderCounts,
}

impl<'a> AuthoritySection<'a> {
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AuthoritySection { parser: parser, counts: counts }
    }

    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.nscount())
    }

    pub fn additional(self) -> ParseResult<AdditionalSection<'a>> {
        let mut iter = self.iter::<GenericRecordData<'a, flavor::Lazy<'a>>>();
        try!(iter.exhaust());
        Ok(AdditionalSection::new(iter.parser, self.counts))
    }
}


//------------ AdditionalSection --------------------------------------------

/// The additional section of a message.
#[derive(Clone, Debug)]
pub struct AdditionalSection<'a> {
    parser: ContextParser<'a>,
    counts: &'a HeaderCounts,
}

impl<'a> AdditionalSection<'a> {
    fn new(parser: ContextParser<'a>, counts: &'a HeaderCounts) -> Self {
        AdditionalSection { parser: parser, counts: counts }
    }

    pub fn iter<D>(&self) -> RecordIter<'a, D>
                where D: FlatRecordData<'a, flavor::Lazy<'a>> {
        RecordIter::new(self.parser.clone(), self.counts.arcount())
    }
}


//------------ RecordIter ---------------------------------------------------

/// An iterator over the records in one of a record section.
#[derive(Clone, Debug)]
pub struct RecordIter<'a, D: FlatRecordData<'a, flavor::Lazy<'a>>> {
    parser: ContextParser<'a>,
    count: u16,
    marker: PhantomData<D>
}

impl<'a, D: FlatRecordData<'a, flavor::Lazy<'a>>> RecordIter<'a, D> {
    fn new(parser: ContextParser<'a>, count: u16) -> Self {
        RecordIter { parser: parser, count: count, marker: PhantomData }
    }

    pub fn iter(&mut self) -> &mut Self { self }

    fn exhaust(&mut self) -> ParseResult<()> {
        for record in self.iter() {
            if let Err(e) = record {
                return Err(e)
            }
        }
        Ok(())
    }

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
#[derive(Clone, Debug)]
pub struct MessageBuilder<C: ComposeBytes> {
    target: MessageTarget<C>
}

impl<C: ComposeBytes> MessageBuilder<C> {
    /// Creates a new message builder.
    pub fn new(target: C) -> ComposeResult<Self> {
        MessageTarget::new(target)
                      .map(|target| MessageBuilder { target: target })
    }

    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }

    pub fn question(self) -> QuestionBuilder<C> {
        QuestionBuilder::new(self.target)
    }
}


//------------ QuestionBuilder ----------------------------------------------

#[derive(Clone, Debug)]
pub struct QuestionBuilder<C: ComposeBytes> {
    target: MessageTarget<C>
}

impl<C: ComposeBytes> QuestionBuilder<C> {
    fn new(target: MessageTarget<C>) -> Self {
        QuestionBuilder { target: target }
    }

    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn push<Q: ComposeQuestion>(&mut self, question: &Q)
                                   -> ComposeResult<()> {
        self.target.push(|target| question.compose(target),
                         |counts| counts.inc_qdcount(1))
    }

    pub fn answer(self) -> AnswerBuilder<C> {
        AnswerBuilder::new(self.target)
    }

    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


//------------ AnswerBuilder ------------------------------------------------

#[derive(Clone, Debug)]
pub struct AnswerBuilder<C: ComposeBytes> {
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AnswerBuilder<C> {
    fn new(target: MessageTarget<C>) -> Self {
        AnswerBuilder { target: target }
    }

    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    pub fn authority(self) -> AuthorityBuilder<C> {
        AuthorityBuilder::new(self.target)
    }

    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


//------------ AuthorityBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct AuthorityBuilder<C: ComposeBytes> {
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AuthorityBuilder<C> {
    fn new(target: MessageTarget<C>) -> Self {
        AuthorityBuilder { target: target }
    }

    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_nscount(1))
    }

    pub fn additional(self) -> AdditionalBuilder<C> {
        AdditionalBuilder::new(self.target)
    }

    pub fn finish(self) -> ComposeResult<C> {
        self.target.finish()
    }
}


//------------ AuthorityBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct AdditionalBuilder<C: ComposeBytes> {
    target: MessageTarget<C>
}

impl<C: ComposeBytes> AdditionalBuilder<C> {
    fn new(target: MessageTarget<C>) -> Self {
        AdditionalBuilder { target: target }
    }

    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn push<R: ComposeRecord>(&mut self, record: &R) -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_nscount(1))
    }

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
    fn new(mut target: C) -> ComposeResult<Self> {
        let start = target.pos();
        try!(target.push_empty(mem::size_of::<FullHeader>()));
        Ok(MessageTarget {
            target: target,
            header: FullHeader::new(),
            start: start
        })
    }

    fn header(&self) -> &Header {
        self.header.header()
    }

    fn header_mut(&mut self) -> &mut Header {
        self.header.header_mut()
    }

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

    fn finish(mut self) -> ComposeResult<C> {
        self.header.header_mut().set_tc(self.target.truncated());
        try!(self.target.update_bytes(self.start, self.header.as_bytes()));
        Ok(self.target)
    }
}

