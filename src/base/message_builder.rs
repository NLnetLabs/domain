//! Building a new DNS message.
//!
//! The types in this module allow building a DNS message consecutively from
//! its parts. Since messages consist of five parts, a number of types are
//! involved. The concept is that you start out with a [`MessageBuilder`] and
//! work your way step by step through the sections by trading the builder in
//! for on of another type representing the following section. The sequence
//! is [`MessageBuilder`], [`QuestionBuilder`], [`AnswerBuilder`],
//! [`AuthorityBuilder`], and finally [`AdditionalBuilder`].
//!
//! You can skip forward over unwanted sections. You can also go backwards,
//! but then you’ll loose anything you built before. The naming of the
//! methods that do these things is consistent across types: `builder` takes
//! you to the message builder. The four methods `question`, `answer`,
//! `additional`, and `authority` progress or return to the respective
//! section. Finally, `finish` completes building.
//!
//! Each of the section builders offers a `push` method to add elements to
//! the section. For the question section, the method accepts anything that
//! resembles a [`Question`] while the three record sections except
//! something that looks like a [`Record`]. Apart from actual values
//! of these types, tuples of the components also work, such as a pair of a
//! domain name and a record type for a question or a triple of the owner
//! name, TTL, and record data for a record. If you already have a question
//! or record, you can use the `push_ref` method to add
//!
//!
//! The `push` method of the record
//! section builders is also available via the [`RecordSectionBuilder`]
//! trait so you can build code that works with all three record sections.
//!
//! The [`AdditionalBuilder`] has a special feature that helps building the
//! OPT record for EDNS. Its [`opt`][AdditionalBuilder::opt] method allows a
//! closure to build this record on the fly via the [`OptBuilder`] type.
//!
//! Building happens atop any [octets builder], so the type of buffer to use
//! for building can be chosen. The module also provides a few helper types
//! that provide optional features for building messages. All of these are
//! wrappers around an octets builder and are octets builders themselves, so
//! you can mix and match.
//!
//! First, the [`StreamTarget`] builds a message for use with streaming
//! transport protocols, e.g., TCP, where the actual message is preceded by
//! a 16 bit length counter. The stream target keeps this counter up-to-date
//! and makes sure the message doesn’t become longer than what the counter
//! can provide for.
//!
//! Two further types, [`TreeCompressor`] and [`StaticCompressor`], provide
//! name compression. This is a mechanism to decrease the size of a DNS
//! message by avoiding repeating domain names: Instead of including a domain
//! name or suffix of a domain name that has been mentioned already, a pointer
//! to the position of the original mention is provided. Since this process is
//! somewhat expensive as you have to remember which names have already been
//! used, it isn’t enabled by default and provided via separate octets
//! builders instead which we call compressors.
//!
//! Currently, there are two different compressors. [`TreeCompressor`] stores
//! all names it encountered in a binary tree. While it can handle any number
//! of names, it does require an allocator and therefore cannot be used in a
//! `no_std` environment. [`StaticCompressor`], meanwhile, has a static table
//! for up to 24 names. It is thus becoming ineffective on large messages
//! with lots of different names. However, 24 should be good enough for most
//! normal messages.
//!
//! # Example
//!
//! The following example builds a message with both name compression and
//! the stream length and simply puts two A records into it.
//!
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! use std::str::FromStr;
//! use domain::base::{
//!     Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget
//! };
//! use domain::rdata::A;
//!
//! // Make a domain name we can use later on.
//! let name = Dname::<Vec<u8>>::from_str("example.com").unwrap();
//!
//! // Create a message builder wrapping a compressor wrapping a stream
//! // target.
//! let mut msg = MessageBuilder::from_target(
//!     StaticCompressor::new(
//!         StreamTarget::new_vec()
//!     )
//! ).unwrap();
//!
//! // Set the RD bit in the header and proceed to the question section.
//! msg.header_mut().set_rd(true);
//! let mut msg = msg.question();
//!
//! // Add a question and proceed to the answer section.
//! msg.push((&name, Rtype::A)).unwrap();
//! let mut msg = msg.answer();
//!
//! // Add two answer and proceed to the additional sections
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 1))).unwrap();
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 2))).unwrap();
//! let mut msg = msg.additional();
//!
//! // Add an OPT record.
//! msg.opt(|opt| {
//!     opt.set_udp_payload_size(4096);
//!     Ok(())
//! }).unwrap();
//!
//! // Convert the builder into the actual message.
//! let target = msg.finish().into_target();
//!
//! // A stream target can provide access to the data with or without the
//! // length counter:
//! let _ = target.as_stream_slice(); // With length
//! let _ = target.as_dgram_slice(); // Without length
//! ```
//!
//! [`MessageBuilder`]: struct.MessageBuilder.html
//! [`QuestionBuilder`]: struct.QuestionBuilder.html
//! [`AnswerBuilder`]: struct.AnswerBuilder.html
//! [`AuthorityBuilder`]: struct.AuthorityBuilder.html
//! [`AdditionalBuilder`]: struct.AdditionalBuilder.html
//! [`AdditionalBuilder::opt`]: struct.AdditionalBuilder.html#method.opt
//! [`OptBuilder`]: struct.OptBuilder.html
//! [`RecordSectionBuilder`]: trait.RecordSectionBuilder.html
//! [`StaticCompressor`]: struct.StaticCompressor.html
//! [`StreamTarget`]: struct.StreamTarget.html
//! [`TreeCompressor`]: struct.TreeCompressor.html
//! [`Question`]: ../question/struct.Question.html
//! [`Record`]: ../question/struct.Record.html
//! [octets builder]: ../octets/trait.OctetsBuilder.html

use super::header::{CountOverflow, Header, HeaderCounts, HeaderSection};
#[cfg(feature = "rand")]
use super::iana::Rtype;
use super::iana::{OptRcode, OptionCode, Rcode};
use super::message::Message;
use super::name::{Label, ToDname};
use super::opt::{ComposeOptData, OptHeader};
use super::question::ComposeQuestion;
use super::record::ComposeRecord;
use super::wire::{Compose, Composer};
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem};
#[cfg(feature = "std")]
use octseq::array::Array;
#[cfg(any(feature = "std", feature = "bytes"))]
use octseq::builder::infallible;
use octseq::builder::{FreezeBuilder, OctetsBuilder, ShortBuf, Truncate};
use octseq::octets::Octets;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ MessageBuilder ------------------------------------------------

/// Starts building a DNS message.
///
/// This type wraps an [`OctetsBuilder`] and starts the process of building a
/// message. It allows access to the header section. The message builder can
/// be traded in for any section builder or the underlying octets builder.
///
/// For more details see the [module documentation].
///
/// [module documentation]: index.html
/// [`OctetsBuilder`]: ../../octets/trait.OctetsBuilder.html
#[derive(Clone, Debug)]
pub struct MessageBuilder<Target> {
    target: Target,
}

/// # Creating Message Builders
///
impl<Target: OctetsBuilder + Truncate> MessageBuilder<Target> {
    /// Creates a new message builder using the given target.
    ///
    /// The target must be an [`OctetsBuilder`]. It will be truncated to zero
    /// size before appending the header section. That is, all data that was
    /// in the builder before will be lost.
    ///
    /// The function will result in an error if the builder doesn’t have
    /// enough space for the header section.
    pub fn from_target(
        mut target: Target,
    ) -> Result<Self, Target::AppendError> {
        target.truncate(0);
        target.append_slice(HeaderSection::new().as_slice())?;
        Ok(MessageBuilder { target })
    }
}

#[cfg(feature = "std")]
impl MessageBuilder<Vec<u8>> {
    /// Creates a new message builder atop a `Vec<u8>`.
    #[must_use]
    pub fn new_vec() -> Self {
        infallible(Self::from_target(Vec::new()))
    }
}

#[cfg(feature = "std")]
impl MessageBuilder<StreamTarget<Vec<u8>>> {
    /// Creates a new builder for a streamable message atop a `Vec<u8>`.
    #[must_use]
    pub fn new_stream_vec() -> Self {
        Self::from_target(StreamTarget::new_vec()).unwrap()
    }
}

#[cfg(feature = "bytes")]
impl MessageBuilder<BytesMut> {
    /// Creates a new message builder atop a bytes value.
    pub fn new_bytes() -> Self {
        infallible(Self::from_target(BytesMut::new()))
    }
}

#[cfg(feature = "bytes")]
impl MessageBuilder<StreamTarget<BytesMut>> {
    /// Creates a new streamable message builder atop a bytes value.
    pub fn new_stream_bytes() -> Self {
        Self::from_target(StreamTarget::new_bytes()).unwrap()
    }
}

impl<Target: Composer> MessageBuilder<Target> {
    /// Starts creating an answer for the given message.
    ///
    /// Specifically, this sets the ID, QR, OPCODE, RD, and RCODE fields
    /// in the header and attempts to push the message’s questions to the
    /// builder. If iterating of the questions fails, it adds what it can.
    ///
    /// The method converts the message builder into an answer builder ready
    /// to receive the answer for the question.
    pub fn start_answer<Octs: Octets + ?Sized>(
        mut self,
        msg: &Message<Octs>,
        rcode: Rcode,
    ) -> Result<AnswerBuilder<Target>, PushError> {
        {
            let header = self.header_mut();
            header.set_id(msg.header().id());
            header.set_qr(true);
            header.set_opcode(msg.header().opcode());
            header.set_rd(msg.header().rd());
            header.set_rcode(rcode);
        }
        let mut builder = self.question();
        for item in msg.question().flatten() {
            builder.push(item)?;
        }
        Ok(builder.answer())
    }

    /// Creates an AXFR request for the given domain.
    ///
    /// Sets a random ID, pushes the domain and the AXFR record type into
    /// the question section, and converts the builder into an answer builder.
    #[cfg(feature = "rand")]
    pub fn request_axfr<N: ToDname>(
        mut self,
        apex: N,
    ) -> Result<AnswerBuilder<Target>, PushError> {
        self.header_mut().set_random_id();
        let mut builder = self.question();
        builder.push((apex, Rtype::AXFR))?;
        Ok(builder.answer())
    }
}

/// # Access to the Message Header
///
impl<Target: OctetsBuilder + AsRef<[u8]>> MessageBuilder<Target> {
    /// Return the current value of the message header.
    pub fn header(&self) -> Header {
        *Header::for_message_slice(self.target.as_ref())
    }

    /// Return the current value of the message header counts.
    pub fn counts(&self) -> HeaderCounts {
        *HeaderCounts::for_message_slice(self.target.as_ref())
    }
}

impl<Target: OctetsBuilder + AsMut<[u8]>> MessageBuilder<Target> {
    /// Returns a mutable reference to the message header for manipulations.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(self.target.as_mut())
    }

    /// Returns a mutable reference to the message header counts.
    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(self.target.as_mut())
    }
}

/// # Conversions
///
impl<Target> MessageBuilder<Target> {
    /// Converts the message builder into a message builder
    ///
    /// This is a no-op.
    pub fn builder(self) -> MessageBuilder<Target> {
        self
    }
}

impl<Target: Composer> MessageBuilder<Target> {
    /// Converts the message builder into a question builder.
    pub fn question(self) -> QuestionBuilder<Target> {
        QuestionBuilder::new(self)
    }

    /// Converts the message builder into an answer builder.
    ///
    /// This will leave the question section empty.
    pub fn answer(self) -> AnswerBuilder<Target> {
        self.question().answer()
    }

    /// Converts the message builder into an authority builder.
    ///
    /// This will leave the question and answer sections empty.
    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.question().answer().authority()
    }

    /// Converts the message builder into an additional builder.
    ///
    /// This will leave the question, answer, and authority sections empty.
    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.question().answer().authority().additional()
    }

    /// Converts the message into the underlying octets builder.
    ///
    /// This will leave the all sections empty.
    pub fn finish(self) -> Target {
        self.target
    }
}

impl<Target: FreezeBuilder> MessageBuilder<Target> {
    /// Converts the builder into a message.
    ///
    /// The method will return a message atop whatever octets sequence the
    /// builder’s octets builder converts into.
    pub fn into_message(self) -> Message<Target::Octets> {
        unsafe { Message::from_octets_unchecked(self.target.freeze()) }
    }
}

impl<Target> MessageBuilder<Target> {
    /// Returns a reference to the underlying octets builder.
    pub fn as_target(&self) -> &Target {
        &self.target
    }

    /// Returns a mutable reference to the underlying octets builder.
    ///
    /// Since one could entirely mess up the message with this reference, the
    /// method is private.
    fn as_target_mut(&mut self) -> &mut Target {
        &mut self.target
    }

    /// Returns an octets slice of the octets assembled so far.
    pub fn as_slice(&self) -> &[u8]
    where
        Target: AsRef<[u8]>,
    {
        self.as_target().as_ref()
    }

    /// Returns a message atop for the octets assembled so far.
    ///
    /// This message is atop the octets slices derived from the builder, so
    /// it can be created cheaply.
    pub fn as_message(&self) -> Message<&[u8]>
    where
        Target: AsRef<[u8]>,
    {
        unsafe { Message::from_octets_unchecked(self.target.as_ref()) }
    }
}

impl<Target: Composer> MessageBuilder<Target> {
    fn push<Push, Inc>(
        &mut self,
        push: Push,
        inc: Inc,
    ) -> Result<(), PushError>
    where
        Push: FnOnce(&mut Target) -> Result<(), ShortBuf>,
        Inc: FnOnce(&mut HeaderCounts) -> Result<(), CountOverflow>,
    {
        let pos = self.target.as_ref().len();
        if let Err(err) = push(&mut self.target) {
            self.target.truncate(pos);
            return Err(From::from(err));
        }
        if inc(self.counts_mut()).is_err() {
            self.target.truncate(pos);
            return Err(PushError::CountOverflow);
        }
        Ok(())
    }
}

//--- From

impl<Target> From<QuestionBuilder<Target>> for MessageBuilder<Target>
where
    Target: Composer,
{
    fn from(src: QuestionBuilder<Target>) -> Self {
        src.builder()
    }
}

impl<Target> From<AnswerBuilder<Target>> for MessageBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.builder()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for MessageBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.builder()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for MessageBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.builder()
    }
}

impl<Target> From<MessageBuilder<Target>> for Message<Target::Octets>
where
    Target: FreezeBuilder,
{
    fn from(src: MessageBuilder<Target>) -> Self {
        src.into_message()
    }
}

//--- AsRef
//
// XXX Should we deref down to target?

impl<Target> AsRef<Target> for MessageBuilder<Target> {
    fn as_ref(&self) -> &Target {
        self.as_target()
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for MessageBuilder<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//------------ QuestionBuilder -----------------------------------------------

/// Builds the question section of a DNS message.
///
/// A value of this type can be acquired by calling the `question` method on
/// any other builder type. See the [module documentation] for an overview of
/// how to build a message.
///
/// You can push questions to the end of the question section via the
/// [`push`] method. It accepts various things that represent a question:
/// question values and references; tuples of a domain name, record type, and
/// class; and, using the regular class of IN, a pair of just a domain name
/// and record type.
///
/// Once you are finished building the question section, you can progress to
/// the answer section via the [`answer`] method or finish the message via
/// [`finish`]. Additionally, conversions to all other builder types are
/// available as well.
///
/// [`answer`]: #method.answer
/// [`finish`]: #method.finish
/// [`push`]: #method.push
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct QuestionBuilder<Target> {
    builder: MessageBuilder<Target>,
}

impl<Target: OctetsBuilder> QuestionBuilder<Target> {
    /// Creates a new question builder from a message builder.
    fn new(builder: MessageBuilder<Target>) -> Self {
        Self { builder }
    }
}

impl<Target: Composer> QuestionBuilder<Target> {
    /// Appends a question to the question section.
    ///
    /// This method accepts anything that implements the [`ComposeQuestion`]
    /// trait. Apart from an actual [`Question`][super::question::Question]
    /// or a reference to it, this can also be a tuple of a domain name,
    /// record type, and class or, if the class is the usual IN, a pair of
    /// just the name and type.
    ///
    /// In other words, the options are:
    ///
    #[cfg_attr(feature = "std", doc = "```")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// use domain::base::{Dname, MessageBuilder, Question, Rtype};
    /// use domain::base::iana::Class;
    ///
    /// let mut msg = MessageBuilder::new_vec().question();
    /// msg.push(Question::new_in(Dname::root_ref(), Rtype::A)).unwrap();
    /// msg.push(&Question::new_in(Dname::root_ref(), Rtype::A)).unwrap();
    /// msg.push((Dname::root_ref(), Rtype::A, Class::IN)).unwrap();
    /// msg.push((Dname::root_ref(), Rtype::A)).unwrap();
    /// ```
    pub fn push(
        &mut self,
        question: impl ComposeQuestion,
    ) -> Result<(), PushError> {
        self.builder.push(
            |target| question.compose_question(target).map_err(Into::into),
            |counts| counts.inc_qdcount(),
        )
    }
}

/// # Conversions
///
/// Additional conversion are available via the `Deref` implementation.
impl<Target: Composer> QuestionBuilder<Target> {
    /// Rewinds to an empty question section.
    ///
    /// All previously added questions will be lost.
    pub fn rewind(&mut self) {
        self.as_target_mut()
            .truncate(mem::size_of::<HeaderSection>());
        self.counts_mut().set_qdcount(0);
    }

    /// Converts the question builder into a message builder.
    ///
    /// All questions will be dropped and the question section will be empty.
    pub fn builder(mut self) -> MessageBuilder<Target> {
        self.rewind();
        self.builder
    }
}

impl<Target> QuestionBuilder<Target> {
    /// Converts the question builder into a question builder.
    ///
    /// In other words, doesn’t do anything.
    pub fn question(self) -> QuestionBuilder<Target> {
        self
    }
}

impl<Target: Composer> QuestionBuilder<Target> {
    /// Converts the question builder into an answer builder.
    pub fn answer(self) -> AnswerBuilder<Target> {
        AnswerBuilder::new(self.builder)
    }

    /// Converts the question builder into an authority builder.
    ///
    /// This will leave the answer section empty.
    pub fn authority(self) -> AuthorityBuilder<Target> {
        self.answer().authority()
    }

    /// Converts the question builder into an additional builder.
    ///
    /// This will leave the answer and authority sections empty.
    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.answer().authority().additional()
    }

    /// Converts the question builder into the underlying octets builder.
    ///
    /// This will leave the answer, authority, and additional sections empty.
    pub fn finish(self) -> Target {
        self.builder.finish()
    }
}

impl<Target: FreezeBuilder> QuestionBuilder<Target> {
    /// Converts the question builder into the final message.
    ///
    /// The method will return a message atop whatever octets sequence the
    /// builder’s octets builder converts into.
    pub fn into_message(self) -> Message<Target::Octets> {
        self.builder.into_message()
    }
}

impl<Target> QuestionBuilder<Target> {
    /// Returns a reference to the underlying message builder.
    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        &self.builder
    }

    /// Returns a mutable reference to the underlying message builder.
    pub fn as_builder_mut(&mut self) -> &mut MessageBuilder<Target> {
        &mut self.builder
    }
}

//--- From

impl<Target> From<MessageBuilder<Target>> for QuestionBuilder<Target>
where
    Target: Composer,
{
    fn from(src: MessageBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AnswerBuilder<Target>> for QuestionBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for QuestionBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for QuestionBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.question()
    }
}

impl<Target> From<QuestionBuilder<Target>> for Message<Target::Octets>
where
    Target: FreezeBuilder,
{
    fn from(src: QuestionBuilder<Target>) -> Self {
        src.into_message()
    }
}

//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for QuestionBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<Target> DerefMut for QuestionBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

impl<Target> AsRef<MessageBuilder<Target>> for QuestionBuilder<Target> {
    fn as_ref(&self) -> &MessageBuilder<Target> {
        self.as_builder()
    }
}

impl<Target> AsMut<MessageBuilder<Target>> for QuestionBuilder<Target> {
    fn as_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.as_builder_mut()
    }
}

impl<Target> AsRef<Target> for QuestionBuilder<Target> {
    fn as_ref(&self) -> &Target {
        self.as_target()
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for QuestionBuilder<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//------------ AnswerBuilder -------------------------------------------------

/// Builds the answer section of a DNS message.
///
/// A value of this type can be acquired by calling the `answer` method on
/// any other builder type. See the [module documentation] for an overview of
/// how to build a message.
///
/// You can push records to the end of the answer section via the [`push`]
/// method. It accepts various things that represent resource records: record
/// values and references, tuples of an owner domain name, a class, TTL, and
/// record data, as well as tuples of just the owner, TTL, and data, assuming
/// the class of IN.
///
/// Once you are finished building the answer section, you can progress to
/// the authority section via the [`authority`] method or finish the message
/// via [`finish`]. Additionally, conversions to all other builder types are
/// available as well.
///
/// [`authority`]: #method.authority
/// [`finish`]: #method.finish
/// [`push`]: #method.push
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AnswerBuilder<Target> {
    /// The message builder we work on.
    builder: MessageBuilder<Target>,

    /// The index in the octets builder where the answer section starts.
    start: usize,
}

impl<Target: Composer> AnswerBuilder<Target> {
    /// Creates a new answer builder from an underlying message builder.
    ///
    /// Assumes that all three record sections are empty.
    #[must_use]
    fn new(builder: MessageBuilder<Target>) -> Self {
        AnswerBuilder {
            start: builder.target.as_ref().len(),
            builder,
        }
    }
}

impl<Target> AnswerBuilder<Target> {
    #[must_use]
    pub fn into_target(self) -> Target {
        self.builder.target
    }
}

impl<Target: Composer> AnswerBuilder<Target> {
    /// Appends a record to the answer section.
    ///
    /// This methods accepts anything that implements the [`ComposeRecord`]
    /// trait. Apart from record values and references, this are tuples of
    /// the owner domain name, optionally the class (which is taken to be IN
    /// if missing), the TTL, and record data.
    ///
    /// In other words, you can do the following things:
    ///
    #[cfg_attr(feature = "std", doc = "```")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// use domain::base::{Dname, MessageBuilder, Record, Rtype, Ttl};
    /// use domain::base::iana::Class;
    /// use domain::rdata::A;
    ///
    /// let mut msg = MessageBuilder::new_vec().answer();
    /// let record = Record::new(
    ///     Dname::root_ref(), Class::IN, Ttl::from_secs(86400), A::from_octets(192, 0, 2, 1)
    /// );
    /// msg.push(&record).unwrap();
    /// msg.push(record).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), Class::IN, 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// ```
    ///
    pub fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<(), PushError> {
        self.builder.push(
            |target| record.compose_record(target).map_err(Into::into),
            |counts| counts.inc_ancount(),
        )
    }
}

/// # Conversions
///
/// Additional conversion are available via the `Deref` implementation.
impl<Target: Composer> AnswerBuilder<Target> {
    /// Rewinds to an empty answer section.
    ///
    /// All previously added answers will be lost.
    pub fn rewind(&mut self) {
        self.builder.target.truncate(self.start);
        self.counts_mut().set_ancount(0);
    }

    /// Converts the answer builder into a message builder.
    ///
    /// All questions and answers will be dropped and all sections will be
    /// empty.
    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    /// Converts the answer builder into a question builder.
    ///
    /// All answers will be dropped. All previously added questions will,
    /// however, remain.
    pub fn question(mut self) -> QuestionBuilder<Target> {
        self.rewind();
        QuestionBuilder::new(self.builder)
    }
}

impl<Target: Composer> AnswerBuilder<Target> {
    /// Converts the answer builder into an answer builder.
    ///
    /// This doesn’t do anything, really.
    pub fn answer(self) -> AnswerBuilder<Target> {
        self
    }

    /// Converts the answer builder into an authority builder.
    pub fn authority(self) -> AuthorityBuilder<Target> {
        AuthorityBuilder::new(self)
    }

    /// Converts the answer builder into an additional builder.
    ///
    /// This will leave the authority section empty.
    pub fn additional(self) -> AdditionalBuilder<Target> {
        self.authority().additional()
    }

    /// Converts the answer builder into the underlying octets builder.
    ///
    /// This will leave the authority and additional sections empty.
    pub fn finish(self) -> Target {
        self.builder.finish()
    }
}

impl<Target: FreezeBuilder> AnswerBuilder<Target> {
    /// Converts the answer builder into the final message.
    ///
    /// The method will return a message atop whatever octets sequence the
    /// builder’s octets builder converts into.
    pub fn into_message(self) -> Message<Target::Octets> {
        self.builder.into_message()
    }
}

impl<Target> AnswerBuilder<Target> {
    /// Returns a reference to the underlying message builder.
    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        &self.builder
    }

    /// Returns a mutable reference to the underlying message builder.
    pub fn as_builder_mut(&mut self) -> &mut MessageBuilder<Target> {
        &mut self.builder
    }
}

//--- From

impl<Target> From<MessageBuilder<Target>> for AnswerBuilder<Target>
where
    Target: Composer,
{
    fn from(src: MessageBuilder<Target>) -> Self {
        src.answer()
    }
}

impl<Target> From<QuestionBuilder<Target>> for AnswerBuilder<Target>
where
    Target: Composer,
{
    fn from(src: QuestionBuilder<Target>) -> Self {
        src.answer()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for AnswerBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.answer()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for AnswerBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.answer()
    }
}

impl<Target> From<AnswerBuilder<Target>> for Message<Target::Octets>
where
    Target: FreezeBuilder,
{
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.into_message()
    }
}

//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AnswerBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<Target> DerefMut for AnswerBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

impl<Target> AsRef<MessageBuilder<Target>> for AnswerBuilder<Target> {
    fn as_ref(&self) -> &MessageBuilder<Target> {
        self.as_builder()
    }
}

impl<Target> AsMut<MessageBuilder<Target>> for AnswerBuilder<Target> {
    fn as_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.as_builder_mut()
    }
}

impl<Target> AsRef<Target> for AnswerBuilder<Target> {
    fn as_ref(&self) -> &Target {
        self.as_target()
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for AnswerBuilder<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//------------ AuthorityBuilder ----------------------------------------------

/// Builds the authority section of a DNS message.
///
/// A value of this type can be acquired by calling the `authority` method on
/// any other builder type. See the [module documentation] for an overview of
/// how to build a message.
///
/// You can push records to the end of the authority section via the [`push`]
/// method. It accepts various things that represent resource records: record
/// values and references, tuples of an owner domain name, a class, TTL, and
/// record data, as well as tuples of just the owner, TTL, and data, assuming
/// the class of IN.
///
/// Once you are finished building the authority section, you can progress to
/// the additional section via the [`additional`] method or finish the message
/// via [`finish`]. Additionally, conversions to all other builder types are
/// available as well.
///
/// [`additional`]: #method.additional
/// [`finish`]: #method.finish
/// [`push`]: #method.push
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AuthorityBuilder<Target> {
    /// The message builder we work on.
    answer: AnswerBuilder<Target>,

    /// The index in the octets builder where the authority section starts.
    start: usize,
}

impl<Target: Composer> AuthorityBuilder<Target> {
    /// Creates a new authority builder from an answer builder.
    ///
    /// Assumes that the authority and additional sections are empty.
    fn new(answer: AnswerBuilder<Target>) -> Self {
        AuthorityBuilder {
            start: answer.as_target().as_ref().len(),
            answer,
        }
    }
}

impl<Target: Composer> AuthorityBuilder<Target> {
    /// Appends a record to the authority section.
    ///
    /// This methods accepts anything that implements the [`ComposeRecord`] trait.
    /// Apart from record values and references, this are tuples of the owner
    /// domain name, optionally the class (which is taken to be IN if
    /// missing), the TTL, and record data.
    ///
    /// In other words, you can do the following things:
    ///
    #[cfg_attr(feature = "std", doc = "```")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// use domain::base::{Dname, MessageBuilder, Record, Rtype, Ttl};
    /// use domain::base::iana::Class;
    /// use domain::rdata::A;
    ///
    /// let mut msg = MessageBuilder::new_vec().authority();
    /// let record = Record::new(
    ///     Dname::root_ref(), Class::IN, Ttl::from_secs(86400),
    ///     A::from_octets(192, 0, 2, 1)
    /// );
    /// msg.push(&record).unwrap();
    /// msg.push(record).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), Class::IN, 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// ```
    pub fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<(), PushError> {
        self.answer.builder.push(
            |target| record.compose_record(target).map_err(Into::into),
            |counts| counts.inc_nscount(),
        )
    }
}

/// # Conversions
///
/// Additional conversion methods are available via the `Deref`
/// implementation.
impl<Target: Composer> AuthorityBuilder<Target> {
    /// Rewinds to an empty authority section.
    ///
    /// All previously added authority records will be lost.
    pub fn rewind(&mut self) {
        self.answer.as_target_mut().truncate(self.start);
        self.counts_mut().set_nscount(0);
    }

    /// Converts the authority builder into a message builder.
    ///
    /// All questions, answer and authority records will be dropped and all
    /// sections will be empty.
    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    /// Converts the authority builder into a question builder.
    ///
    /// All authority and answer records will be dropped. All previously added
    /// questions will, however, remain.
    pub fn question(self) -> QuestionBuilder<Target> {
        self.answer().question()
    }

    /// Converts the authority builder into an answer builder.
    ///
    /// All authority records will be dropped. All previously added questions
    /// and answer records will, however, remain.
    pub fn answer(mut self) -> AnswerBuilder<Target> {
        self.rewind();
        self.answer
    }

    /// Converts the authority builder into an authority builder.
    ///
    /// This is identical to the identity function.
    pub fn authority(self) -> AuthorityBuilder<Target> {
        self
    }

    /// Converts the authority builder into an additional builder.
    pub fn additional(self) -> AdditionalBuilder<Target> {
        AdditionalBuilder::new(self)
    }

    /// Converts the authority builder into the underlying octets builder.
    ///
    /// This will leave the additional section empty.
    pub fn finish(self) -> Target {
        self.answer.finish()
    }
}

impl<Target: FreezeBuilder> AuthorityBuilder<Target> {
    /// Converts the authority builder into the final message.
    ///
    /// The method will return a message atop whatever octets sequence the
    /// builder’s octets builder converts into.
    pub fn into_message(self) -> Message<Target::Octets> {
        self.answer.into_message()
    }
}

impl<Target> AuthorityBuilder<Target> {
    /// Returns a reference to the underlying message builder.
    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        self.answer.as_builder()
    }

    /// Returns a mutable reference to the underlying message builder.
    pub fn as_builder_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.answer.as_builder_mut()
    }
}

//--- From

impl<Target> From<MessageBuilder<Target>> for AuthorityBuilder<Target>
where
    Target: Composer,
{
    fn from(src: MessageBuilder<Target>) -> Self {
        src.authority()
    }
}

impl<Target> From<QuestionBuilder<Target>> for AuthorityBuilder<Target>
where
    Target: Composer,
{
    fn from(src: QuestionBuilder<Target>) -> Self {
        src.authority()
    }
}

impl<Target> From<AnswerBuilder<Target>> for AuthorityBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.authority()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for AuthorityBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.authority()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for Message<Target::Octets>
where
    Target: FreezeBuilder,
{
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.into_message()
    }
}

//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AuthorityBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        self.answer.deref()
    }
}

impl<Target> DerefMut for AuthorityBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.answer.deref_mut()
    }
}

impl<Target> AsRef<MessageBuilder<Target>> for AuthorityBuilder<Target> {
    fn as_ref(&self) -> &MessageBuilder<Target> {
        self.as_builder()
    }
}

impl<Target> AsMut<MessageBuilder<Target>> for AuthorityBuilder<Target> {
    fn as_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.as_builder_mut()
    }
}

impl<Target> AsRef<Target> for AuthorityBuilder<Target> {
    fn as_ref(&self) -> &Target {
        self.as_target()
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for AuthorityBuilder<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//------------ AdditionalBuilder ---------------------------------------------

/// Builds the additional section of a DNS message.
///
/// A value of this type can be acquired by calling the `additional` method on
/// any other builder type. See the [module documentation] for an overview of
/// how to build a message.
///
/// You can push records to the end of the additional section via the [`push`]
/// method. It accepts various things that represent resource records: record
/// values and references, tuples of an owner domain name, a class, TTL, and
/// record data, as well as tuples of just the owner, TTL, and data, assuming
/// the class of IN.
///
/// A special method exists to make adding an OPT record to the section
/// easier. The [`opt`] method creates an [`OptBuilder`] and passes it to a
/// closure. This way, you can add and remove OPT records from additional
/// builders that are part of another type and cannot be traded in easily.
///
/// Once you are finished building the additional section, you can finish the
/// message via [`finish`]. Additionally, conversions to all other builder
/// types are available as well.
///
/// [`finish`]: #method.finish
/// [`opt`]: #method.opt
/// [`push`]: #method.push
/// [`OptBuilder`]: struct.OptBuilder.html
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AdditionalBuilder<Target> {
    /// The message builder we work on.
    authority: AuthorityBuilder<Target>,

    /// The index in the octets builder where the additional section starts.
    start: usize,
}

impl<Target: Composer> AdditionalBuilder<Target> {
    /// Creates a new additional builder from an authority builder.
    ///
    /// Assumes that the additional section is currently empty.
    fn new(authority: AuthorityBuilder<Target>) -> Self {
        AdditionalBuilder {
            start: authority.as_target().as_ref().len(),
            authority,
        }
    }
}

impl<Target: Composer> AdditionalBuilder<Target> {
    /// Appends a record to the additional section.
    ///
    /// This methods accepts anything that implements the
    /// [`ComposeRecord`] trait.
    /// Apart from record values and references, this are tuples of the owner
    /// domain name, optionally the class (which is taken to be IN if
    /// missing), the TTL, and record data.
    ///
    /// In other words, you can do the following things:
    ///
    #[cfg_attr(feature = "std", doc = "```")]
    #[cfg_attr(not(feature = "std"), doc = "```ignore")]
    /// use domain::base::{Dname, MessageBuilder, Record, Rtype, Ttl};
    /// use domain::base::iana::Class;
    /// use domain::rdata::A;
    ///
    /// let mut msg = MessageBuilder::new_vec().additional();
    /// let record = Record::new(
    ///     Dname::root_ref(), Class::IN, Ttl::from_secs(86400), A::from_octets(192, 0, 2, 1)
    /// );
    /// msg.push(&record).unwrap();
    /// msg.push(record).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), Class::IN, 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// msg.push(
    ///     (Dname::root_ref(), 86400, A::from_octets(192, 0, 2, 1))
    /// ).unwrap();
    /// ```
    pub fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<(), PushError> {
        self.authority.answer.builder.push(
            |target| record.compose_record(target).map_err(Into::into),
            |counts| counts.inc_arcount(),
        )
    }
}

impl<Target: Composer> AdditionalBuilder<Target> {
    /// Appends and builds an OPT record.
    ///
    /// The actual building of the record is handled by a closure that
    /// receives an [`OptBuilder`] which can both change the header of the
    /// record and add options.
    ///
    /// The method will return whatever the closure returns. In addition, it
    /// will return an error if it failed to add the header of the OPT record.
    ///
    /// [`OptBuilder`]: struct.OptBuilder.html
    pub fn opt<F>(&mut self, op: F) -> Result<(), PushError>
    where
        F: FnOnce(&mut OptBuilder<Target>) -> Result<(), Target::AppendError>,
    {
        self.authority.answer.builder.push(
            |target| OptBuilder::new(target)?.build(op).map_err(Into::into),
            |counts| counts.inc_arcount(),
        )
    }
}

/// # Conversions
///
/// Additional conversion methods are available via the `Deref`
/// implementation.
impl<Target: Composer> AdditionalBuilder<Target> {
    /// Rewinds to an empty additional section.
    ///
    /// All previously added additional records will be lost.
    pub fn rewind(&mut self) {
        self.authority.as_target_mut().truncate(self.start);
        self.counts_mut().set_arcount(0);
    }

    /// Converts the additional builder into a message builder.
    ///
    /// All questions and records will be dropped and all sections will be
    /// empty.
    pub fn builder(self) -> MessageBuilder<Target> {
        self.question().builder()
    }

    /// Converts the additional builder into a question builder.
    ///
    /// All answer, authority, and additional records will be dropped. All
    /// previously added questions will, however, remain.
    pub fn question(self) -> QuestionBuilder<Target> {
        self.answer().question()
    }

    /// Converts the additional builder into an answer builder.
    ///
    /// All authority and additional records will be dropped. All questions
    /// and answer records will remain.
    pub fn answer(self) -> AnswerBuilder<Target> {
        self.authority().answer()
    }

    /// Converts the additional builder into an authority builder.
    ///
    /// All additional records will be dropped. All questions, answer, and
    /// authority records will remain.
    pub fn authority(mut self) -> AuthorityBuilder<Target> {
        self.rewind();
        self.authority
    }

    /// Converts the additional builder into an additional builder.
    ///
    /// In other words, does absolutely nothing.
    pub fn additional(self) -> AdditionalBuilder<Target> {
        self
    }

    /// Converts the additional builder into the underlying octets builder.
    pub fn finish(self) -> Target {
        self.authority.finish()
    }
}

impl<Target: FreezeBuilder> AdditionalBuilder<Target> {
    /// Converts the additional builder into the final message.
    ///
    /// The method will return a message atop whatever octets sequence the
    /// builder’s octets builder converts into.
    pub fn into_message(self) -> Message<Target::Octets> {
        self.authority.into_message()
    }
}

impl<Target> AdditionalBuilder<Target> {
    /// Returns a reference to the underlying message builder.
    pub fn as_builder(&self) -> &MessageBuilder<Target> {
        self.authority.as_builder()
    }

    /// Returns a mutable reference to the underlying message builder.
    pub fn as_builder_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.authority.as_builder_mut()
    }
}

//--- From

impl<Target> From<MessageBuilder<Target>> for AdditionalBuilder<Target>
where
    Target: Composer,
{
    fn from(src: MessageBuilder<Target>) -> Self {
        src.additional()
    }
}

impl<Target> From<QuestionBuilder<Target>> for AdditionalBuilder<Target>
where
    Target: Composer,
{
    fn from(src: QuestionBuilder<Target>) -> Self {
        src.additional()
    }
}

impl<Target> From<AnswerBuilder<Target>> for AdditionalBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AnswerBuilder<Target>) -> Self {
        src.additional()
    }
}

impl<Target> From<AuthorityBuilder<Target>> for AdditionalBuilder<Target>
where
    Target: Composer,
{
    fn from(src: AuthorityBuilder<Target>) -> Self {
        src.additional()
    }
}

impl<Target> From<AdditionalBuilder<Target>> for Message<Target::Octets>
where
    Target: FreezeBuilder,
{
    fn from(src: AdditionalBuilder<Target>) -> Self {
        src.into_message()
    }
}

//--- Deref, DerefMut, AsRef, and AsMut

impl<Target> Deref for AdditionalBuilder<Target> {
    type Target = MessageBuilder<Target>;

    fn deref(&self) -> &Self::Target {
        self.as_builder()
    }
}

impl<Target> DerefMut for AdditionalBuilder<Target> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_builder_mut()
    }
}

impl<Target> AsRef<MessageBuilder<Target>> for AdditionalBuilder<Target> {
    fn as_ref(&self) -> &MessageBuilder<Target> {
        self.as_builder()
    }
}

impl<Target> AsMut<MessageBuilder<Target>> for AdditionalBuilder<Target> {
    fn as_mut(&mut self) -> &mut MessageBuilder<Target> {
        self.as_builder_mut()
    }
}

impl<Target> AsRef<Target> for AdditionalBuilder<Target> {
    fn as_ref(&self) -> &Target {
        self.as_target()
    }
}

impl<Target: AsRef<[u8]>> AsRef<[u8]> for AdditionalBuilder<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

//------------ RecordSectionBuilder ------------------------------------------

/// A section that can have records pushed to it.
///
/// This trait exists to make it possible to write code that works for all
/// three record sections. It basically just duplicates the `push` method of
/// these sections.
///
/// (This method is available on the sections as a method, too, so you don’t
/// need to import the `RecordSectionBuilder` all the time.)
pub trait RecordSectionBuilder<Target: Composer> {
    /// Appends a record to a record section.
    ///
    /// The methods accepts anything that implements the [`ComposeRecord`] trait.
    /// Apart from record values and references, this are tuples of the owner
    /// domain name, optionally the class (which is taken to be IN if
    /// missing), the TTL, and record data.
    fn push(&mut self, record: impl ComposeRecord) -> Result<(), PushError>;
}

impl<Target> RecordSectionBuilder<Target> for AnswerBuilder<Target>
where
    Target: Composer,
{
    fn push(&mut self, record: impl ComposeRecord) -> Result<(), PushError> {
        Self::push(self, record)
    }
}

impl<Target: Composer> RecordSectionBuilder<Target>
    for AuthorityBuilder<Target>
{
    fn push(&mut self, record: impl ComposeRecord) -> Result<(), PushError> {
        Self::push(self, record)
    }
}

impl<Target> RecordSectionBuilder<Target> for AdditionalBuilder<Target>
where
    Target: Composer,
{
    fn push(&mut self, record: impl ComposeRecord) -> Result<(), PushError> {
        Self::push(self, record)
    }
}

//------------ OptBuilder ----------------------------------------------------

/// Builds an OPT record.
///
/// A mutable reference of this type is passed to the closure given to
/// [`AdditionalBuilder::opt`] allowing this closure to manipulate both the
/// header values of the record and push options to the record data.
///
/// [`AdditionalBuilder::opt`]: struct.AdditonalBuilder.html#method.opt
pub struct OptBuilder<'a, Target: ?Sized> {
    start: usize,
    target: &'a mut Target,
}

impl<'a, Target: Composer + ?Sized> OptBuilder<'a, Target> {
    /// Creates a new opt builder atop an additional builder.
    fn new(target: &'a mut Target) -> Result<Self, ShortBuf> {
        let start = target.as_ref().len();
        OptHeader::default().compose(target).map_err(Into::into)?;
        Ok(OptBuilder { start, target })
    }

    fn build<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where
        F: FnOnce(&mut Self) -> Result<(), Target::AppendError>,
    {
        self.target.append_slice(&[0; 2]).map_err(Into::into)?;
        let pos = self.target.as_ref().len();
        match op(self) {
            Ok(_) => match u16::try_from(self.target.as_ref().len() - pos) {
                Ok(len) => {
                    self.target.as_mut()[pos - 2..pos]
                        .copy_from_slice(&(len).to_be_bytes());
                    Ok(())
                }
                Err(_) => {
                    self.target.truncate(pos);
                    Err(ShortBuf)
                }
            },
            Err(_) => {
                self.target.truncate(pos);
                Err(ShortBuf)
            }
        }
    }

    /// Appends an option to the OPT record.
    pub fn push<Opt: ComposeOptData + ?Sized>(
        &mut self,
        opt: &Opt,
    ) -> Result<(), Target::AppendError> {
        self.push_raw_option(opt.code(), opt.compose_len(), |target| {
            opt.compose_option(target)
        })
    }

    /// Appends a raw option to the OPT record.
    ///
    /// The method will append an option with the given option code. The data
    /// of the option will be written via the closure `op`.
    pub fn push_raw_option<F>(
        &mut self,
        code: OptionCode,
        option_len: u16,
        op: F,
    ) -> Result<(), Target::AppendError>
    where
        F: FnOnce(&mut Target) -> Result<(), Target::AppendError>,
    {
        code.compose(self.target)?;
        option_len.compose(self.target)?;
        op(self.target)
    }

    /// Returns the current UDP payload size field of the OPT record.
    ///
    /// This field contains the largest UDP datagram the sender can accept.
    /// This is not the path MTU but really what the sender can work with
    /// internally.
    #[must_use]
    pub fn udp_payload_size(&self) -> u16 {
        self.opt_header().udp_payload_size()
    }

    /// Sets the UDP payload size field of the OPT record.
    pub fn set_udp_payload_size(&mut self, value: u16) {
        self.opt_header_mut().set_udp_payload_size(value)
    }

    /// Returns the extended rcode of the message.
    ///
    /// The method assembles the rcode both from the message header and the
    /// OPT header.
    #[must_use]
    pub fn rcode(&self) -> OptRcode {
        self.opt_header()
            .rcode(*Header::for_message_slice(self.target.as_ref()))
    }

    /// Sets the extended rcode of the message.
    //
    /// The method will update both the message header and the OPT header.
    pub fn set_rcode(&mut self, rcode: OptRcode) {
        Header::for_message_slice_mut(self.target.as_mut())
            .set_rcode(rcode.rcode());
        self.opt_header_mut().set_rcode(rcode)
    }

    /// Returns the EDNS version of the OPT header.
    ///
    /// Only EDNS version 0 is currently defined.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.opt_header().version()
    }

    /// Sets the EDNS version of the OPT header.
    pub fn set_version(&mut self, version: u8) {
        self.opt_header_mut().set_version(version)
    }

    /// Returns the value of the DNSSEC OK (DO) bit.
    ///
    /// By setting this bit, a resolver indicates that it is interested in
    /// also receiving the DNSSEC-related resource records necessary to
    /// validate an answer. The bit and the related procedures are defined in
    /// [RFC 3225].
    ///
    /// [RFC 3225]: https://tools.ietf.org/html/rfc3225
    #[must_use]
    pub fn dnssec_ok(&self) -> bool {
        self.opt_header().dnssec_ok()
    }

    /// Sets the DNSSEC OK (DO) bit to the given value.
    pub fn set_dnssec_ok(&mut self, value: bool) {
        self.opt_header_mut().set_dnssec_ok(value)
    }

    /// Returns a reference to the full OPT header.
    fn opt_header(&self) -> &OptHeader {
        OptHeader::for_record_slice(&self.target.as_ref()[self.start..])
    }

    /// Returns a mutual reference to the full OPT header.
    fn opt_header_mut(&mut self) -> &mut OptHeader {
        let start = self.start;
        OptHeader::for_record_slice_mut(&mut self.target.as_mut()[start..])
    }
}

//------------ StreamTarget --------------------------------------------------

/// A builder target for sending messages on stream transports.
///
/// TODO: Rename this type and adjust the doc comments as it is usable both
/// for datagram AND stream transports via [`as_dgram_slice()`] and
/// [`as_stream_slice()`].
///
/// When messages are sent over stream-oriented transports such as TCP, a DNS
/// message is preceded by a 16 bit length value in order to determine the
/// end of a message. This type transparently adds this length value as the
/// first two octets of an octets builder and itself presents an octets
/// builder interface for building the actual message. Whenever data is pushed
/// to that builder interface, the type will update the length value.
///
/// Because the length is 16 bits long, the assembled message can be at most
/// 65536 octets long, independently of the maximum length the underlying
/// builder allows.
#[derive(Clone, Debug, Default)]
pub struct StreamTarget<Target> {
    /// The underlying octets builder.
    target: Target,
}

impl<Target: Composer> StreamTarget<Target> {
    /// Creates a new stream target wrapping an octets builder.
    ///
    /// The function will truncate the builder back to empty and append the
    /// length value. Because of the latter, this can fail if the octets
    /// builder doesn’t even have space for that.
    pub fn new(mut target: Target) -> Result<Self, Target::AppendError> {
        target.truncate(0);
        0u16.compose(&mut target)?;
        Ok(StreamTarget { target })
    }
}

#[cfg(feature = "std")]
impl StreamTarget<Vec<u8>> {
    /// Creates a stream target atop an empty `Vec<u8>`.
    #[must_use]
    pub fn new_vec() -> Self {
        infallible(Self::new(Vec::new()))
    }
}

#[cfg(feature = "bytes")]
impl StreamTarget<BytesMut> {
    /// Creates a stream target atop an empty `Vec<u8>`.
    pub fn new_bytes() -> Self {
        infallible(Self::new(BytesMut::new()))
    }
}

impl<Target> StreamTarget<Target> {
    /// Returns a reference to the underlying octets builder.
    pub fn as_target(&self) -> &Target {
        &self.target
    }

    /// Converts the stream target into the underlying octets builder.
    ///
    /// The returned builder will contain the 16 bit length value with the
    /// correct content and the assembled message.
    pub fn into_target(self) -> Target {
        self.target
    }
}

impl<Target: AsRef<[u8]> + AsMut<[u8]>> StreamTarget<Target> {
    /// Updates the length value to the current length of the target.
    fn update_shim(&mut self) -> Result<(), ShortBuf> {
        match u16::try_from(self.target.as_ref().len() - 2) {
            Ok(len) => {
                self.target.as_mut()[..2].copy_from_slice(&len.to_be_bytes());
                Ok(())
            }
            Err(_) => Err(ShortBuf),
        }
    }
}

impl<Target: AsRef<[u8]>> StreamTarget<Target> {
    /// Returns an octets slice of the message for stream transports.
    ///
    /// The slice will start with the length octets and can be send as is
    /// through a stream transport such as TCP.
    pub fn as_stream_slice(&self) -> &[u8] {
        self.target.as_ref()
    }

    /// Returns an octets slice of the message for datagram transports.
    ///
    /// The slice will not contain the length octets but only the actual
    /// message itself. This slice can be used for sending via datagram
    /// transports such as UDP.
    pub fn as_dgram_slice(&self) -> &[u8] {
        &self.target.as_ref()[2..]
    }
}

//--- AsRef, AsMut

impl<Target: AsRef<[u8]>> AsRef<[u8]> for StreamTarget<Target> {
    fn as_ref(&self) -> &[u8] {
        &self.target.as_ref()[2..]
    }
}

impl<Target: AsMut<[u8]>> AsMut<[u8]> for StreamTarget<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.target.as_mut()[2..]
    }
}

//--- OctetsBuilder, Truncate, Composer

impl<Target> OctetsBuilder for StreamTarget<Target>
where
    Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Target::AppendError: Into<ShortBuf>,
{
    type AppendError = ShortBuf;

    fn append_slice(
        &mut self,
        slice: &[u8],
    ) -> Result<(), Self::AppendError> {
        self.target.append_slice(slice).map_err(Into::into)?;
        self.update_shim()
    }
}

impl<Target: Composer> Truncate for StreamTarget<Target> {
    fn truncate(&mut self, len: usize) {
        self.target
            .truncate(len.checked_add(2).expect("long truncate"));
        self.update_shim().expect("truncate grew buffer???")
    }
}

impl<Target> Composer for StreamTarget<Target>
where
    Target: Composer,
    Target::AppendError: Into<ShortBuf>,
{
    fn append_compressed_dname<N: ToDname + ?Sized>(
        &mut self,
        name: &N,
    ) -> Result<(), Self::AppendError> {
        self.target
            .append_compressed_dname(name)
            .map_err(Into::into)?;
        self.update_shim()
    }
}

//------------ StaticCompressor ----------------------------------------------

/// A domain name compressor that doesn’t require an allocator.
///
/// This type wraps around an octets builder and implements domain name
/// compression. It does not require an allocator but because of that it
/// can only remember the position of up to 24 domain names. This should be
/// sufficient for most messages.
///
/// The position of a domain name is calculated relative to the beginning of
/// the underlying octets builder. This means that this builder must represent
/// the message only. This means that if you are using the [`StreamTarget`],
/// you need to place it inside this type, _not_ the other way around.
///
/// [`StreamTarget`]: struct.StreamTarget.html
#[derive(Clone, Debug)]
pub struct StaticCompressor<Target> {
    /// The underlying octets builder.
    target: Target,

    /// The domain names we have encountered so far.
    ///
    /// The value is the position of the domain name within the message.
    entries: [u16; 24],

    /// The number of entries in `entries`.
    len: usize,
}

impl<Target> StaticCompressor<Target> {
    /// Creates a static compressor from an octets builder.
    pub fn new(target: Target) -> Self {
        StaticCompressor {
            target,
            entries: Default::default(),
            len: 0,
        }
    }

    /// Returns a reference to the underlying octets builder.
    pub fn as_target(&self) -> &Target {
        &self.target
    }

    /// Converts the static compressor into the underlying octets builder.
    pub fn into_target(self) -> Target {
        self.target
    }

    /// Returns a reference to the octets slice of the content.
    pub fn as_slice(&self) -> &[u8]
    where
        Target: AsRef<[u8]>,
    {
        self.target.as_ref()
    }

    /// Returns a reference to the octets slice of the content.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Target: AsMut<[u8]>,
    {
        self.target.as_mut()
    }

    /// Returns a known position of a domain name if there is one.
    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
    ) -> Option<u16>
    where
        Target: AsRef<[u8]>,
    {
        self.entries[..self.len].iter().find_map(|&pos| {
            if name
                .clone()
                .eq(Label::iter_slice(self.target.as_ref(), pos as usize))
            {
                Some(pos)
            } else {
                None
            }
        })
    }

    /// Inserts the position of a new domain name if possible.
    fn insert(&mut self, pos: usize) -> bool {
        if pos < 0xc000 && self.len < self.entries.len() {
            self.entries[self.len] = pos as u16;
            self.len += 1;
            true
        } else {
            false
        }
    }
}

//--- AsRef and AsMut

impl<Target: AsRef<[u8]>> AsRef<[u8]> for StaticCompressor<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Target: AsMut<[u8]>> AsMut<[u8]> for StaticCompressor<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- OctetsBuilder

impl<Target: OctetsBuilder> OctetsBuilder for StaticCompressor<Target> {
    type AppendError = Target::AppendError;

    fn append_slice(
        &mut self,
        slice: &[u8],
    ) -> Result<(), Self::AppendError> {
        self.target.append_slice(slice)
    }
}

impl<Target: Composer> Composer for StaticCompressor<Target> {
    fn append_compressed_dname<N: ToDname + ?Sized>(
        &mut self,
        name: &N,
    ) -> Result<(), Self::AppendError> {
        let mut name = name.iter_labels().peekable();

        loop {
            // If the parent is root, just write that and return.
            // Because we do that, there will always be a label left here.
            if let Some(label) = name.peek() {
                if label.is_root() {
                    label.compose(self)?;
                    return Ok(());
                }
            }

            // If we already know this name, append it as a compressed label.
            if let Some(pos) = self.get(name.clone()) {
                return (pos | 0xC000).compose(self);
            }

            // So we don’t know the name. Try inserting it into the
            // compressor. If we can’t insert anymore, just write out what’s
            // left and return.
            if !self.insert(self.target.as_ref().len()) {
                for label in &mut name {
                    label.compose(self)?;
                }
                return Ok(());
            }

            // Advance to the parent.
            let label = name.next().unwrap();
            label.compose(self)?;
        }
    }

    fn can_compress(&self) -> bool {
        true
    }
}

impl<Target: Truncate> Truncate for StaticCompressor<Target> {
    fn truncate(&mut self, len: usize) {
        self.target.truncate(len);
        if len < 0xC000 {
            let len = len as u16;
            for i in 0..self.len {
                if self.entries[i] >= len {
                    self.len = i;
                    break;
                }
            }
        }
    }
}

//------------ TreeCompressor ------------------------------------------------

/// A domain name compressor that uses a tree.
///
/// This type wraps around an octets builder and implements domain name
/// compression for it. It stores the position of any domain name it has seen
/// in a binary tree.
///
/// The position of a domain name is calculated relative to the beginning of
/// the underlying octets builder. This means that this builder must represent
/// the message only. This means that if you are using the [`StreamTarget`],
/// you need to place it inside this type, _not_ the other way around.
///
/// [`StreamTarget`]: struct.StreamTarget.html
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct TreeCompressor<Target> {
    /// The underlying octetsbuilder.
    target: Target,

    /// The topmost node of our tree.
    start: Node,
}

/// A node in our tree.
///
/// The tree is a bit odd. It follows the labels of the domain names from the
/// root towards the left. The root node is for the root label. It contains a
/// map that maps all the labels encountered to the immediate left of the
/// name traced by this path through the tree to a node for the name resulting
/// by adding this label to the name constructed so far.
///
/// Each node also contains the position of that name in the message.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
struct Node {
    /// The labels immediately to the left of this name and their nodes.
    parents: HashMap<Array<64>, Self>,

    /// The position of this name in the message.
    value: Option<u16>,
}

#[cfg(feature = "std")]
impl Node {
    fn drop_above(&mut self, len: u16) {
        self.value = match self.value {
            Some(value) if value < len => Some(value),
            _ => None,
        };
        self.parents
            .values_mut()
            .for_each(|node| node.drop_above(len))
    }
}

#[cfg(feature = "std")]
impl<Target> TreeCompressor<Target> {
    /// Creates a new compressor from an underlying octets builder.
    pub fn new(target: Target) -> Self {
        TreeCompressor {
            target,
            start: Default::default(),
        }
    }

    /// Returns a reference to the underlying octets builder.
    pub fn as_target(&self) -> &Target {
        &self.target
    }

    /// Converts the compressor into the underlying octets builder.
    pub fn into_target(self) -> Target {
        self.target
    }

    /// Returns an octets slice of the data.
    pub fn as_slice(&self) -> &[u8]
    where
        Target: AsRef<[u8]>,
    {
        self.target.as_ref()
    }

    /// Returns an mutable octets slice of the data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Target: AsMut<[u8]>,
    {
        self.target.as_mut()
    }

    fn get<'a, N: Iterator<Item = &'a Label> + Clone>(
        &self,
        name: N,
    ) -> Option<u16> {
        let mut node = &self.start;
        for label in name {
            if label.is_root() {
                return node.value;
            }
            node = node.parents.get(label.as_ref())?;
        }
        None
    }

    fn insert<'a, N: Iterator<Item = &'a Label> + Clone>(
        &mut self,
        name: N,
        pos: usize,
    ) -> bool {
        if pos >= 0xC000 {
            return false;
        }
        let pos = pos as u16;
        let mut node = &mut self.start;
        for label in name {
            if label.is_root() {
                node.value = Some(pos);
                break;
            }
            node = node
                .parents
                .entry(label.as_ref().try_into().unwrap())
                .or_default();
        }
        true
    }
}

//--- AsRef, AsMut, and OctetsBuilder

#[cfg(feature = "std")]
impl<Target: AsRef<[u8]>> AsRef<[u8]> for TreeCompressor<Target> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[cfg(feature = "std")]
impl<Target: AsMut<[u8]>> AsMut<[u8]> for TreeCompressor<Target> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

#[cfg(feature = "std")]
impl<Target: OctetsBuilder> OctetsBuilder for TreeCompressor<Target> {
    type AppendError = Target::AppendError;

    fn append_slice(
        &mut self,
        slice: &[u8],
    ) -> Result<(), Self::AppendError> {
        self.target.append_slice(slice)
    }
}

#[cfg(feature = "std")]
impl<Target: Composer> Composer for TreeCompressor<Target> {
    fn append_compressed_dname<N: ToDname + ?Sized>(
        &mut self,
        name: &N,
    ) -> Result<(), Self::AppendError> {
        let mut name = name.iter_labels().peekable();

        loop {
            // If the parent is root, just write that and return.
            // Because we do that, there will always be a label left here.
            if let Some(label) = name.peek() {
                if label.is_root() {
                    label.compose(self)?;
                    return Ok(());
                }
            }

            // If we already know this name, append it as a compressed label.
            if let Some(pos) = self.get(name.clone()) {
                return (pos | 0xC000).compose(self);
            }

            // So we don’t know the name. Try inserting it into the
            // compressor. If we can’t insert anymore, just write out what’s
            // left and return.
            if !self.insert(name.clone(), self.target.as_ref().len()) {
                for label in &mut name {
                    label.compose(self)?;
                }
                return Ok(());
            }

            // Advance to the parent. If the parent is root, just write that
            // and return. Because we do that, there will always be a label
            // left here.
            let label = name.next().unwrap();
            label.compose(self)?;
        }
    }

    fn can_compress(&self) -> bool {
        true
    }
}

#[cfg(feature = "std")]
impl<Target: Composer> Truncate for TreeCompressor<Target> {
    fn truncate(&mut self, len: usize) {
        self.target.truncate(len);
        if len < 0xC000 {
            self.start.drop_above(len as u16)
        }
    }
}

//============ Errors ========================================================

#[derive(Clone, Copy, Debug)]
pub enum PushError {
    CountOverflow,
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for PushError {
    fn from(_: T) -> Self {
        Self::ShortBuf
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PushError::CountOverflow => f.write_str("counter overflow"),
            PushError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::opt;
    use crate::base::{Dname, Serial, Ttl};
    use crate::rdata::{Ns, Soa, A};
    use core::str::FromStr;

    #[test]
    fn message_builder() {
        // Make a domain name we can use later on.
        let name = Dname::<Vec<u8>>::from_str("example.com").unwrap();

        // Create a message builder wrapping a compressor wrapping a stream
        // target.
        let mut msg = MessageBuilder::from_target(StaticCompressor::new(
            StreamTarget::new_vec(),
        ))
        .unwrap();

        // Set the RD bit in the header and proceed to the question section.
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();

        // Add a question and proceed to the answer section.
        msg.push((&name, Rtype::A)).unwrap();
        let mut msg = msg.answer();

        // Add two answer and proceed to the additional sections
        msg.push((&name, 86400, A::from_octets(192, 0, 2, 1)))
            .unwrap();
        msg.push((&name, 86400, A::from_octets(192, 0, 2, 2)))
            .unwrap();

        // Add an authority
        let mut msg = msg.authority();
        msg.push((&name, 0, Ns::from(name.clone()))).unwrap();

        // Add additional
        let mut msg = msg.additional();
        msg.push((&name, 86400, A::from_octets(192, 0, 2, 1)))
            .unwrap();

        // Convert the builder into the actual message.
        let target = msg.finish().into_target();

        // Reparse message and check contents
        let msg = Message::from_octets(target.as_dgram_slice()).unwrap();
        let q = msg.first_question().unwrap();
        assert_eq!(q.qname(), &name);
        assert_eq!(q.qtype(), Rtype::A);

        let section = msg.answer().unwrap();
        let mut records = section.limit_to::<A>();
        assert_eq!(
            records.next().unwrap().unwrap().data(),
            &A::from_octets(192, 0, 2, 1)
        );
        assert_eq!(
            records.next().unwrap().unwrap().data(),
            &A::from_octets(192, 0, 2, 2)
        );

        let section = msg.authority().unwrap();
        let mut records = section.limit_to::<Ns<_>>();
        let rr = records.next().unwrap().unwrap();
        assert_eq!(rr.owner(), &name);
        assert_eq!(rr.data().nsdname(), &name);

        let section = msg.additional().unwrap();
        let mut records = section.limit_to::<A>();
        let rr = records.next().unwrap().unwrap();
        assert_eq!(rr.owner(), &name);
        assert_eq!(rr.data(), &A::from_octets(192, 0, 2, 1));
    }

    #[test]
    fn opt_builder() {
        let mut msg = MessageBuilder::new_vec().additional();

        // Add an OPT record.
        let nsid = opt::nsid::Nsid::from_octets(&b"example"[..]).unwrap();
        msg.opt(|o| {
            o.set_udp_payload_size(4096);
            o.push(&nsid)?;
            Ok(())
        })
        .unwrap();

        let msg = msg.finish();
        println!("{:?}", msg);
        let msg = Message::from_octets(msg).unwrap();
        let opt = msg.opt().unwrap();

        // Check options
        assert_eq!(opt.udp_payload_size(), 4096);
        let mut opts = opt.opt().iter::<opt::nsid::Nsid<_>>();
        assert_eq!(opts.next(), Some(Ok(nsid)));
    }

    fn create_compressed<T: Composer>(target: T) -> T
    where
        T::AppendError: fmt::Debug,
    {
        let mut msg = MessageBuilder::from_target(target).unwrap().question();
        msg.header_mut().set_rcode(Rcode::NXDOMAIN);
        msg.header_mut().set_rd(true);
        msg.header_mut().set_ra(true);
        msg.header_mut().set_qr(true);

        msg.push((&"example".parse::<Dname<Vec<u8>>>().unwrap(), Rtype::NS))
            .unwrap();
        let mut msg = msg.authority();

        let mname: Dname<Vec<u8>> = "a.root-servers.net".parse().unwrap();
        let rname = "nstld.verisign-grs.com".parse().unwrap();
        msg.push((
            Dname::root_slice(),
            86390,
            Soa::new(
                mname,
                rname,
                Serial(2020081701),
                Ttl::from_secs(1800),
                Ttl::from_secs(900),
                Ttl::from_secs(604800),
                Ttl::from_secs(86400),
            ),
        ))
        .unwrap();
        msg.finish()
    }

    #[test]
    fn compressor() {
        // An example negative response to `example. NS` with an SOA to test
        // various compressed name situations.
        let expect = &[
            0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x00, 0x00,
            0x02, 0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x51,
            0x76, 0x00, 0x40, 0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d,
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74,
            0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72,
            0x69, 0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x78, 0x68, 0x00, 0x25, 0x00, 0x00, 0x07, 0x08,
            0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01, 0x51,
            0x80,
        ];

        let msg = create_compressed(StaticCompressor::new(Vec::new()));
        assert_eq!(&expect[..], msg.as_ref());

        let msg = create_compressed(TreeCompressor::new(Vec::new()));
        assert_eq!(&expect[..], msg.as_ref());
    }
}
