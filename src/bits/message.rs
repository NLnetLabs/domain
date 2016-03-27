//! DNS messages.

use std::marker::PhantomData;
use std::mem;
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, ParseResult};
use super::flavor::{self, FlatFlavor};
use super::header::{Header, HeaderCounts, FullHeader};
use super::nest::{self, FlatNest, Nest};
use super::parse::ParseBytes;
use super::question::{ComposeQuestion, Question};
use super::rdata::{GenericRecordData, FlatRecordData};
use super::record::{ComposeRecord, Record};


//============ Disecting Existing Messages ==================================

//============ Message ======================================================

/// A DNS message.
#[derive(Clone, Debug)]
pub struct Message<'a, F: FlatFlavor<'a>> {
    nest: F::FlatNest
}

pub type OwnedMessage<'a> = Message<'a, flavor::Owned>;
pub type MessageRef<'a> = Message<'a, flavor::Ref<'a>>;
pub type LazyMessage<'a> = Message<'a, flavor::Lazy<'a>>;

/// # Creation and Conversion
///
impl<'a, F: FlatFlavor<'a>> Message<'a, F> {
    /// Creates a message from a nest.
    pub fn from_nest(nest: F::FlatNest) -> Self {
        Message { nest: nest }
    }
}

impl<'a> Message<'a, flavor::Ref<'a>> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Message::from_nest(nest::NestRef::from_bytes(bytes))
    }
}

impl<'a> Message<'a, flavor::Lazy<'a>> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Message::from_nest(nest::LazyNest::new(bytes, bytes))
    }
}


// # Header Access
//
impl<'a, F: FlatFlavor<'a>> Message<'a, F> {
    /// Returns a reference to the message header.
    pub fn header<'b: 'a>(&'b self) -> &'a Header {
        unsafe { Header::from_message(self.nest.as_slice()) }
    }

    /// Returns a reference to the header counts of the message.
    pub fn counts<'b: 'a>(&'b self) -> &'a HeaderCounts {
        unsafe { HeaderCounts::from_message(self.nest.as_slice()) }
    }

    /// Returns an iterator over the question section
    pub fn question<'b: 'a>(&'b self) -> QuestionSection<'a, F> {
        let mut parser = self.nest.parser();
        parser.skip(mem::size_of::<FullHeader>()).unwrap(); // XXX Hmm.
        QuestionSection::new(parser, (*self.counts()).clone())
    }
}


//------------ QuestionSection ----------------------------------------------

#[derive(Clone, Debug)]
pub struct QuestionSection<'a, F: FlatFlavor<'a>> {
    parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
    counts: HeaderCounts,
    count: u16
}

impl<'a, F: FlatFlavor<'a>> QuestionSection<'a, F> {
    fn new(parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
           counts: HeaderCounts) -> Self {
        let count = counts.qdcount();
        QuestionSection { parser: parser, counts: counts, count: count }
    }

    pub fn iter(&mut self) -> &mut Self {
        self
    }

    /// Continues to the answer section.
    pub fn answer(mut self) -> ParseResult<AnswerSection<'a, F>> {
        for question in self.iter() {
            if let Err(e) = question {
                return Err(e)
            }
        }
        Ok(AnswerSection::new(self.parser, self.counts))
    }
}

impl<'a, F: FlatFlavor<'a>> Iterator for QuestionSection<'a, F> {
    type Item = ParseResult<Question<F>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        Some(Question::parse(&mut self.parser)
                      .map(|res| { self.count -= 1; res }))
    }
}


//------------ AnswerSection ------------------------------------------------

/// The answer section of a message.
#[derive(Clone, Debug)]
pub struct AnswerSection<'a, F: FlatFlavor<'a>> {
    parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
    counts: HeaderCounts,
}

impl<'a, F: FlatFlavor<'a>> AnswerSection<'a, F> {
    fn new(parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
           counts: HeaderCounts) -> Self {
        AnswerSection { parser: parser, counts: counts }
    }

    pub fn iter<D: FlatRecordData<'a, F>>(&self) -> RecordIter<'a, F, D> {
        RecordIter::new(self.parser.clone(), self.counts.ancount())
    }

    pub fn authority(self) -> ParseResult<AuthoritySection<'a, F>> {
        let mut iter = self.iter::<GenericRecordData<'a, F>>();
        try!(iter.exhaust());
        Ok(AuthoritySection::new(iter.parser, self.counts))
    }
}


//------------ AuthoritySection ---------------------------------------------

/// The authority section of a message.
#[derive(Clone, Debug)]
pub struct AuthoritySection<'a, F: FlatFlavor<'a>> {
    parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
    counts: HeaderCounts,
}

impl<'a, F: FlatFlavor<'a>> AuthoritySection<'a, F> {
    fn new(parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
           counts: HeaderCounts) -> Self {
        AuthoritySection { parser: parser, counts: counts }
    }

    pub fn iter<D: FlatRecordData<'a, F>>(&self) -> RecordIter<'a, F, D> {
        RecordIter::new(self.parser.clone(), self.counts.nscount())
    }

    pub fn additional(self) -> ParseResult<AdditionalSection<'a, F>> {
        let mut iter = self.iter::<GenericRecordData<'a, F>>();
        try!(iter.exhaust());
        Ok(AdditionalSection::new(iter.parser, self.counts))
    }
}


//------------ AdditionalSection --------------------------------------------

/// The additional section of a message.
#[derive(Clone, Debug)]
pub struct AdditionalSection<'a, F: FlatFlavor<'a>> {
    parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
    counts: HeaderCounts,
}

impl<'a, F: FlatFlavor<'a>> AdditionalSection<'a, F> {
    fn new(parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
           counts: HeaderCounts) -> Self {
        AdditionalSection { parser: parser, counts: counts }
    }

    pub fn iter<D: FlatRecordData<'a, F>>(&self) -> RecordIter<'a, F, D> {
        RecordIter::new(self.parser.clone(), self.counts.ancount())
    }
}

//------------ RecordIter ---------------------------------------------------

/// An iterator over the records in one of a record section.
#[derive(Clone, Debug)]
pub struct RecordIter<'a, F: FlatFlavor<'a>, D: FlatRecordData<'a, F>> {
    parser: <F::FlatNest as FlatNest<'a, F>>::Parser,
    count: u16,
    marker: PhantomData<D>
}

impl<'a, F: FlatFlavor<'a>, D: FlatRecordData<'a, F>> RecordIter<'a, F, D> {
    fn new(parser: <F::FlatNest as FlatNest<'a, F>>::Parser, count: u16)
           -> Self {
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

    fn step(&mut self) -> ParseResult<Option<Record<F, D>>> {
        Record::parse(&mut self.parser).map(|res| { self.count -= 1; res })
    }
}

impl<'a, F, D> Iterator for RecordIter<'a, F, D> 
     where F: FlatFlavor<'a>, D: FlatRecordData<'a, F> {
    type Item = ParseResult<Record<F, D>>;

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

