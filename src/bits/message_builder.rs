//! Building a new message.
//!
//! DNS messages consist of five sections. The first, the *header section*
//! contain, among other things, the number of entries in the following four
//! section which then contain these entries without any further
//! delimitation. In order to safely build a correct message, it thus needs
//! to be assembled step by step, entry by entry. This module provides four
//! types, each responsible for assembling one of the entry sections.
//!
//! You start out with a [`MessageBuilder`] which you can either create from
//! an existing [`Composer`] or, as a shortcut, either completely [`new()`]
//! or from an existing bytes vector via [`from_vec()`]. Like all of these
//! type, the [`MessageBuilder`] allows access to the header section. In
//! addition, it is used for building the *question section* of the message.
//! This section contains [`Question`]s to be asked of a name server,
//! normally exactly one. You can add questions using the
//! [`push()`](struct.MessageBuilder.html#method.push) method.
//!
//! Once you are happy with the question section, you can proceed to the
//! next section, the *answer section,* by calling the
//! [`answer()`](struct.MessageBuilder.html#method.answer) method. In a
//! response, this section contains those resource records that answer the
//! question. The section is represented by the [`AnswerBuilder`] type.
//! It, too, has a [`push()`](struct.AnswerBuilder.html#method.push) method,
//! but for [`Record`]s.
//!
//! A call to [`authority()`](struct.AnswerBuilder.html#method.authority)
//! moves on to the *authority section*. It contains resource records that
//! point to the name servers that serve authoritative for the question.
//! Like with the answer section,
//! [`push()`](struct.AuthorityBuilder.html#method.push) adds records to this
//! section.
//!
//! The final section is the *additional section.* Here a name server can add
//! information it believes will help the client to get to the answer it
//! really wants. Which these are depends on the question and is generally
//! given in RFCs that define the record types. Unsurprisingly, you will
//! arrive at a [`AdditionalBuilder`] by calling the
//! [`additional()`](struct.AuthorityBuilder.html#method.additional) method
//! once you are done with the authority section.
//! 
//! Once you are done with the additional section, too, you call
//! [`finish()`](struct.AdditionalBuilder.html#method.finish) to retrieve
//! the bytes vector with the assembled message data.
//!
//! Since at least some of the sections are empty in many messages, for
//! instance, a simple request only contains a single question, there are
//! shortcuts in place to skip over sections. Each type can go to any later
//! section through the methods named above. Each type also has a `finish()`
//! method to arrive at the final data quickly.
//!
//!
//! # Example
//!
//! To summarize all of this, here is an example that builds a
//! response to an A query for example.com that contains two A records and
//! nothing else.
//!
//! ```
//! /*
//! use std::str::FromStr;
//! use domain::bits::{ComposeMode, DNameBuf, MessageBuilder, Question};
//! use domain::iana::Rtype;
//! use domain::rdata::A;
//!
//! let name = DNameBuf::from_str("example.com.").unwrap();
//! let mut msg = MessageBuilder::new(ComposeMode::Limited(512),
//!                                   true).unwrap();
//! msg.header_mut().set_rd(true);
//! msg.push((&name, Rtype::A));
//! let mut msg = msg.answer();
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 1))).unwrap();
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 2))).unwrap();
//! let _ = msg.finish(); // get the Vec<u8>
//! */
//! ```
//!
//! [`AdditionalBuilder`]: struct.AdditionalBuilder.html
//! [`AnswerBuilder`]: struct.AnswerBuilder.html
//! [`AuthorityBuilder`]: struct.AuthorityBuilder.html
//! [`Composer`]: ../compose/Composer.html
//! [`MessageBuilder`]: struct.MessageBuilder.html
//! [`Question`]: ../question/struct.Question.html
//! [`Record`]: ../record/struct.Record.html
//! [`new()`]: struct.MessageBuilder.html#method.new
//! [`from_vec()`]: struct.MessageBuilder.html#method.from_vec

use std::{mem, ops};
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, Bytes, BytesMut};
use iana::opt::OptionCode;
use super::compose::{Compose, Compress, Compressor};
use super::header::{Header, HeaderCounts, HeaderSection};
use super::name::ToDname;
use super::opt::{OptData, OptHeader};
use super::parse::ShortBuf;
use super::question::Question;
use super::rdata::RecordData;
use super::record::Record;


//------------ MessageBuilder -----------------------------------------------

/// A type for building the question section of a DNS message.
///
/// This type starts building a DNS message and allows adding questions to
/// its question section. See the [module documentation] for details.
///
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct MessageBuilder {
    target: MessageTarget,
}


/// # Creation and Preparation
///
impl MessageBuilder {
    pub fn new_udp() -> Self {
        Self::with_params(512, 512, 0)
    }

    pub fn from_buf(buf: BytesMut) -> Self {
        MessageBuilder { target: MessageTarget::from_buf(buf) }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_buf(BytesMut::with_capacity(capacity))
    }

    pub fn with_params(initial: usize, limit: usize, page_size: usize)
                       -> Self {
        let mut res = Self::with_capacity(initial);
        res.set_limit(limit);
        res.set_page_size(page_size);
        res
    }

    pub fn enable_compression(&mut self) {
        self.target.buf.enable_compression()
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    pub fn set_page_size(&mut self, page_size: usize) {
        self.target.buf.set_page_size(page_size)
    }
}


/// # Building
///
impl MessageBuilder {
    /// Returns a reference to the message’s header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the message’s header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    pub fn rewind(&mut self, snapshot: Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new question to the message.
    ///
    /// This function is generic over anything that can be converted into a
    /// [`Question`]. In particular, triples of a domain name, a record type,
    /// and a class as well as pairs of just a domain name and a record type
    /// fulfill this requirement with the class assumed to be `Class::In` in
    /// the latter case.
    ///
    /// [`Question`]: ../question/struct.Question.html
    pub fn push<N: ToDname>(&mut self, question: &Question<N>)
                            -> Result<(), ShortBuf> {
        self.target.push(|target| question.compress(target),
                         |counts| counts.inc_qdcount())
    }

    /// Proceeds to building the answer section.
    pub fn answer(self) -> AnswerBuilder {
        AnswerBuilder::new(self.target)
    }

    /// Proceeds to building the authority section, skipping the answer.
    pub fn authority(self) -> AuthorityBuilder {
        self.answer().authority()
    }

    /// Proceeds to building the additonal section.
    ///
    /// Leaves the answer and additional sections empty.
    pub fn additional(self) -> AdditionalBuilder {
        self.answer().authority().additional()
    }

    /// Proceeds to building the OPT record.
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// This method requires a `&mut self` since it may need to update some
    /// length values to return a valid message.
    ///
    /// In case the builder was created from a vector with previous content,
    /// the returned reference is for the full content of this vector.
    pub fn preview(&mut self) -> &[u8] {
        self.target.preview()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    pub fn freeze(self) -> Bytes {
        self.target.freeze()
    }
}


//------------ AnswerBuilder -------------------------------------------------

/// A type for building the answer section of a DNS message.
///
/// This type is typically constructed by calling [`answer()`] on a
/// [`MessageBuilder`]. See the [module documentation] for details.
///
/// [`answer()`]: struct.MessageBuilder.html#method.answer
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AnswerBuilder {
    target: MessageTarget,
}


impl AnswerBuilder {
    /// Creates a new answer builder from a compser.
    fn new(target: MessageTarget) -> Self {
        AnswerBuilder { target }
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    pub fn rewind(&mut self, snapshot: Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the answer section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D>(&mut self, record: &Record<N, D>)
                      -> Result<(), ShortBuf>
                where N: ToDname,
                      D: RecordData {
        self.target.push(|target| record.compress(target),
                         |counts| counts.inc_ancount())
    }

    /// Proceeds to building the authority section.
    pub fn authority(self) -> AuthorityBuilder {
        AuthorityBuilder::new(self.target)
    }

    /// Proceeds to building the additional section, skipping authority.
    pub fn additional(self) -> AdditionalBuilder {
        self.authority().additional()
    }

    /// Proceeds to building the OPT record.
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// This method requires a `&mut self` since it may need to update some
    /// length values to return a valid message.
    ///
    /// In case the builder was created from a vector with previous content,
    /// the returned reference is for the full content of this vector.
    pub fn preview(&mut self) -> &[u8] {
        self.target.preview()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    pub fn freeze(self) -> Bytes {
        self.target.freeze()
    }
}


//------------ AuthorityBuilder ---------------------------------------------

/// A type for building the authority section of a DNS message.
///
/// This type can be constructed by calling `authority()` on a
/// [`MessageBuilder`] or [`AnswerBuilder`]. See the [module documentation]
/// for details.
///
/// [`AnswerBuilder`]: struct.AnswerBuilder.html
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AuthorityBuilder {
    target: MessageTarget,
}


impl AuthorityBuilder {
    /// Creates a new authority builder from a compser.
    fn new(target: MessageTarget) -> Self {
        AuthorityBuilder { target }
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    pub fn rewind(&mut self, snapshot: Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the authority section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D>(&mut self, record: &Record<N, D>)
                      -> Result<(), ShortBuf>
                where N: ToDname,
                      D: RecordData {
        self.target.push(|target| record.compress(target),
                         |counts| counts.inc_nscount())
    }

    /// Proceeds to building the additional section.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.target)
    }

    /// Proceeds to building the OPT record.
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// This method requires a `&mut self` since it may need to update some
    /// length values to return a valid message.
    ///
    /// In case the builder was created from a vector with previous content,
    /// the returned reference is for the full content of this vector.
    pub fn preview(&mut self) -> &[u8] {
        self.target.preview()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    pub fn freeze(self) -> Bytes {
        self.target.freeze()
    }
}


//------------ AdditionalBuilder --------------------------------------------

/// A type for building the additional section of a DNS message.
///
/// This type can be constructed by calling `additional()` on a
/// [`MessageBuilder`], [`AnswerBuilder`], or [`AuthorityBuilder`]. See the
/// [module documentation] for details.
///
/// [`AnswerBuilder`]: struct.AnswerBuilder.html
/// [`AuthorityBuilder`]: struct.AuthorityBuilder.html
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AdditionalBuilder {
    target: MessageTarget,
}


impl AdditionalBuilder {
    /// Creates a new additional builder from a compser.
    fn new(target: MessageTarget) -> Self {
        AdditionalBuilder { target }
    }

    /// Returns a reference to the messages header.
    pub fn header(&self) -> &Header {
        self.target.header()
    }

    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    pub fn rewind(&mut self, snapshot: Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the additional section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D>(&mut self, record: &Record<N, D>)
                      -> Result<(), ShortBuf>
                where N: ToDname,
                      D: RecordData {
        self.target.push(|target| record.compress(target),
                         |counts| counts.inc_arcount())
    }

    /// Proceeds to building the OPT record.
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        OptBuilder::new(self.target)
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// This method requires a `&mut self` since it may need to update some
    /// length values to return a valid message.
    ///
    /// In case the builder was created from a vector with previous content,
    /// the returned reference is for the full content of this vector.
    pub fn preview(&mut self) -> &[u8] {
        self.target.preview()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    pub fn freeze(self) -> Bytes {
        self.target.freeze()
    }
}


//------------ OptBuilder ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptBuilder {
    target: MessageTarget,
    pos: usize,
}

impl OptBuilder {
    fn new(mut target: MessageTarget) -> Result<Self, ShortBuf> {
        let pos = target.len();
        target.compose(&OptHeader::default())?;
        target.compose(&0u16)?;
        Ok(OptBuilder { pos, target })
    }

    /// Pushes an option to the OPT record.
    pub fn push<O: OptData>(&mut self, option: &O) -> Result<(), ShortBuf> {
        self.target.compose(&option.code())?;
        let len = option.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        self.target.compose(&(len as u16))?;
        self.target.compose(option)
    }

    pub(super) fn build<F>(&mut self, code: OptionCode, len: u16, op: F)
                           -> Result<(), ShortBuf>
                        where F: FnOnce(&mut Compressor)
                                        -> Result<(), ShortBuf> {
        self.target.compose(&code)?;
        self.target.compose(&len)?;
        op(&mut self.target.buf)
    }

    /// Completes the OPT record and returns the additional section builder.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.complete())
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.complete().unwrap()
    }

    pub fn freeze(self) -> Bytes {
        self.complete().freeze()
    }

    fn complete(mut self) -> MessageTarget {
        let len = self.target.len()
                - (self.pos + mem::size_of::<OptHeader>() + 2);
        assert!(len <= ::std::u16::MAX as usize);
        BigEndian::write_u16(&mut self.target.as_slice_mut()[self.pos..],
                             len as u16);
        self.target.counts_mut().inc_arcount();
        self.target
    }
}

impl ops::Deref for OptBuilder {
    type Target = OptHeader;

    fn deref(&self) -> &Self::Target {
        OptHeader::for_record_slice(&self.target.as_slice()[self.pos..])
    }
}

impl ops::DerefMut for OptBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        OptHeader::for_record_slice_mut(&mut self.target.as_slice_mut()
                                                                 [self.pos..])
    }
}

//------------ MessageTarget -------------------------------------------------

/// Underlying data for constructing a DNS message.
///
/// This private type does all the heavy lifting for constructing messages.
#[derive(Clone, Debug)]
struct MessageTarget {
    buf: Compressor,
    start: usize,
}


impl MessageTarget {
    /// Creates a new message target atop a given buffer.
    fn from_buf(mut buf: BytesMut) -> Self {
        let start = buf.len();
        if buf.remaining_mut() < 2 + mem::size_of::<HeaderSection>() {
            let additional = 2 + mem::size_of::<HeaderSection>()
                           - buf.remaining_mut();
            buf.reserve(additional)
        }
        0u16.compose(&mut buf);
        let mut buf = Compressor::from_buf(buf);
        HeaderSection::default().compose(&mut buf);
        MessageTarget { buf, start }
    }

    /// Returns a reference to the message’s header.
    fn header(&self) -> &Header {
        Header::for_message_slice(self.buf.so_far())
    }

    /// Returns a mutable reference to the message’s header.
    fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(self.buf.so_far_mut())
    }

    fn counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.buf.so_far())
    }

    /// Returns a mutable reference to the message’s header counts.
    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(self.buf.so_far_mut())
    }

    /// Pushes something to the end of the message.
    ///
    /// There’s two closures here. The first one, `composeop` actually
    /// writes the data. The second, `incop` increments the counter in the
    /// messages header to reflect the new element. The latter is assumed to
    /// never fail. This means you need to check before you push whether
    /// there is still space in whatever counter you plan to increase.
    /// `HeaderCount`’s `inc_*` methods, which are supposed to be used here,
    /// have assertions for your own safety.
    fn push<O, I, E>(&mut self, composeop: O, incop: I) -> Result<(), E>
            where O: FnOnce(&mut Compressor) -> Result<(), E>,
                  I: FnOnce(&mut HeaderCounts) {
        composeop(&mut self.buf).map(|()| incop(self.counts_mut()))
    }

    fn snapshot<T>(&self) -> Snapshot<T> {
        Snapshot {
            pos: self.buf.len(),
            counts: self.counts().clone(),
            marker: PhantomData,
        }
    }

    fn rewind<T>(&mut self, snapshot: Snapshot<T>) {
        self.buf.truncate(snapshot.pos);
        self.counts_mut().set(&snapshot.counts);
    }

    fn update_shim(&mut self) {
        let len = (self.buf.len() - self.start) as u16;
        BigEndian::write_u16(&mut self.buf.as_slice_mut()[self.start..], len);
    }

    fn preview(&mut self) -> &[u8] {
        self.update_shim();
        self.buf.as_slice()
    }

    fn unwrap(mut self) -> BytesMut {
        self.update_shim();
        self.buf.unwrap()
    }

    fn freeze(mut self) -> Bytes {
        self.update_shim();
        self.unwrap().freeze()
    }
}

impl ops::Deref for MessageTarget {
    type Target = Compressor;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl ops::DerefMut for MessageTarget {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}


//------------ Snapshot ------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot<T> {
    pos: usize,
    counts: HeaderCounts,
    marker: PhantomData<T>,
}

