//! Building a new DNS message.
//!
//! DNS messages consist of five sections. The first, the *header section*
//! contain, among other things, the number of entries in the following four
//! section which then contain these entries without any further
//! delimitation. In order to safely build a correct message, it thus needs
//! to be assembled step by step, entry by entry. This module provides a
//! number of types that can be used to assembling entries in these sections.
//!
//! Message building happens by appending data to a [`BytesMut`] buffer. This
//! buffer is automatically grown to accomodate the data if necessary. It
//! does, however, consider the size limit that all DNS messages have. Thus,
//! when you start building by creating a [`MessageBuilder`], you can pass
//! an initial buffer size, a size limit, and a strategy for growing to its
//! [`with_params`][`MessageBuilder::with_params`] function. Alternatively,
//! you can create the message atop an existing buffer via
//! [`from_buf`][`MessageBuilder::from_buf`]. In this case you can adjust the
//! limits via methods such as [`set_limit`][`MessageBuilder::set_limit`].
//! 
//! All types allow to change the limit later. This is useful if you know
//! already that your message will have to end with an OPT or TSIG record.
//! Since for these you also know the size in advance, you can reserve space
//! by setting a lower limit and increase it only when finally adding those
//! records.
//!
//! Because domain name compression is somewhat expensive, it needs to be
//! enable explicitely through the 
//! [`enable_compression`][`MessageBuilder::enable_compression`] method.
//!
//! The inital [`MessageBuilder`] allows access to the two first sections of
//! the new message. The header section can be accessed via
//! [`header`][`MessageBuilder::header`] and
//! [`header_mut`][`MessageBuilder::header_mut`]. In addition, it is used for
//! building the *question section* of the message. This section contains
//! [`Question`]s to be asked of a name server, normally exactly one. You
//! can add questions using the [`push`][`MessageBuilder::push`] method.
//!
//! Once you are happy with the question section, you can proceed to the
//! next section, the *answer section,* by calling the
//! [`answer`][`MessageBuilder::answer`] method.
//! In a response, this section contains those resource records that answer
//! the question. The section is represented by the [`AnswerBuilder`] type.
//! It, too, has a [`push`][`AnswerBuilder::push`] method, but for adding
//! [`Record`]s.
//!
//! A call to [`authority`][`AnswerBuilder::authority`] moves on to the
//! *authority section,* represented by an [`AuthorityBuilder`]. It contains
//! resource records that allow to identify the name servers that are
//! authoritative for the records requested in the question. As with the
//! answer section, [`push`][`AdditionalBuilder`] adds records to this
//! section.
//!
//! The final section is the *additional section.* Here a name server can add
//! information it believes will help the client to get to the answer it
//! really wants. Which these are depends on the question and is generally
//! given in RFCs that define the record types. Unsurprisingly, you will
//! arrive at an [`AdditionalBuilder`] by calling the
//! [`additional`][`AuthorityBuilder::additional`] method once you are done
//! with the authority section. Adding records, once again, happens via the
//! [`push`][`AdditionalBuilder::push`] method.
//! 
//! Once you are done with the additional section, too, you call
//! [`finish`][`AdditionalBuilder::finish`] to retrieve the bytes buffer with
//! the message data or [`freeze`][`AdditionalBuilder::freeze`] to get the
//! [`Message`] instead.
//!
//! Since some of the sections are empty in many messages – for instance, a
//! simple request only contains a single question – there are
//! shortcuts in place to skip over sections. Each type can go to any later
//! section through the methods named above. Each type also has the `finish`
//! and `freeze` methods to arrive at the final data quickly.
//!
//! There is one more type: [`OptBuilder`]. It can be used to assemble an
//! OPT record in the additional section. This is helpful because the OPT
//! record in turn is a sequence of options that need to be assembled one
//! by one.
//!
//! Since OPT records are part of the additional section, an [`OptBuilder`]
//! can be retrieved from an [`AdditionalBuilder`] via its
//! [`opt`][`AdditionalBuilder::opt`] method. Options can then be added as
//! usually via [`push`][`OptBuilder::push`]. Once done, you can return to
//! the additional section with [`additional`][`OptBuilder::additional`] or,
//! if your OPT record is the final record, conclude message construction
//! via [`finish`][`OptBuilder::finish`] or [`freeze`][`OptBuilder::freeze`].
//!
//! # Example
//!
//! To summarize all of this, here is an example that builds a
//! response to an A query for example.com that contains two A records and
//! and empty OPT record setting the UDP payload size.
//!
//! ```
//! use std::str::FromStr;
//! use domain_core::bits::{Dname, MessageBuilder};
//! use domain_core::iana::Rtype;
//! use domain_core::rdata::A;
//!
//! let name = Dname::from_str("example.com.").unwrap();
//! let mut msg = MessageBuilder::new_udp();
//! msg.header_mut().set_rd(true);
//! msg.push((&name, Rtype::A));
//! let mut msg = msg.answer();
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 1))).unwrap();
//! msg.push((&name, 86400, A::from_octets(192, 0, 2, 2))).unwrap();
//! let mut msg = msg.opt().unwrap();
//! msg.set_udp_payload_size(4096);
//! let _ = msg.freeze(); // get the message
//! ```
//!
//! [`BytesMut`]: ../../../bytes/struct.BytesMut.html
//! [`AdditionalBuilder`]: struct.AdditionalBuilder.html
//! [`AdditionalBuilder::opt`]: struct.AdditionalBuilder.html#method.opt
//! [`AdditionalBuilder::push`]: struct.AdditionalBuilder.html#method.push
//! [`AdditionalBuilder::finish`]: struct.AdditionalBuilder.html#method.finish
//! [`AdditionalBuilder::freeze`]: struct.AdditionalBuilder.html#method.freeze
//! [`AnswerBuilder`]: struct.AnswerBuilder.html
//! [`AnswerBuilder::authority`]: struct.AnswerBuilder.html#method.authority
//! [`AnswerBuilder::push`]: struct.AnswerBuilder.html#method.push
//! [`AuthorityBuilder`]: struct.AuthorityBuilder.html
//! [`AuthorityBuilder::additional`]: struct.AuthorityBuilder.html#method.additional
//! [`AuthorityBuilder::push`]: struct.AuthorityBuilder.html#method.push
//! [`Composer`]: ../compose/Composer.html
//! [`Message`]: ../message/struct.Messsage.html
//! [`MessageBuilder`]: struct.MessageBuilder.html
//! [`MessageBuilder::answer`]: struct.MessageBuilder.html#method.answer
//! [`MessageBuilder::enable_compression`]: struct.MessageBuilder.html#method.enable_compression
//! [`MessageBuilder::from_buf`]: struct.MessageBuilder.html#method.from_buf
//! [`MessageBuilder::header`]: struct.MessageBuilder.html#method.header
//! [`MessageBuilder::header_mut`]: struct.MessageBuilder.html#method.header_mut
//! [`MessageBuilder::push`]: struct.MessageBuilder.html#method.push
//! [`MessageBuilder::with_params`]: struct.MessageBuilder.html#method.with_params
//! [`MessageBuilder::set_limit`]: struct.MessageBuilder.html#method.set_limit
//! [`OptBuilder`]: struct.OptBuilder.html
//! [`OptBuilder::additional`]: struct.OptBuilder.html#method.additional
//! [`OptBuilder::finish`]: struct.OptBuilder.html#method.finish
//! [`OptBuilder::freeze`]: struct.OptBuilder.html#method.freeze
//! [`OptBuilder::push`]: struct.OptBuilder.html#method.push
//! [`Question`]: ../question/struct.Question.html
//! [`Record`]: ../record/struct.Record.html

use std::{mem, ops};
use std::marker::PhantomData;
use bytes::{BigEndian, BufMut, ByteOrder, BytesMut};
use iana::opt::OptionCode;
use super::compose::{Compose, Compress, Compressor};
use super::header::{Header, HeaderCounts, HeaderSection};
use super::message::Message;
use super::name::ToDname;
use super::opt::{OptData, OptHeader};
use super::parse::ShortBuf;
use super::question::Question;
use super::rdata::RecordData;
use super::record::Record;


//------------ MessageBuilder -----------------------------------------------

/// Starts building a DNS message.
///
/// This type starts building a DNS message and allows adding questions to
/// its question section. See the [module documentation] for an overview of 
/// how to build a message.
///
/// Message builders operate atop a [`BytesMut`] byte buffer. There are a
/// number of functions to create a builder either using an existing
/// buffer or with a newly created buffer. 
/// 
/// Once created, it is possible to access the message header or append
/// questions to the question section before proceeding to the subsequent
/// parts of the message.
///
/// [module documentation]: index.html
/// [`BytesMut`]: ../../../bytes/struct.BytesMut.html
#[derive(Clone, Debug)]
pub struct MessageBuilder {
    target: MessageTarget,
}


/// # Creation and Preparation
///
impl MessageBuilder {
    /// Creates a new builder for a UDP message.
    ///
    /// The builder will use a new bytes buffer. The buffer will have a
    /// capacity of 512 bytes and will also be limited to that.
    ///
    /// This will result in a UDP message following the original limit. If you
    /// want to create larger messages, you should signal this through the use
    /// of EDNS.
    pub fn new_udp() -> Self {
        Self::with_params(512, 512, 0)
    }

    /// Creates a new builder for a TCP message.
    ///
    /// The builder will use a new buffer. It will be limited to 65535 bytes,
    /// starting with the capacity given and also growing by that amount.
    ///
    /// Since DNS messages are preceded on TCP by a two octet length
    /// inicator, the function will add two bytes with zero before the
    /// message. Once you have completed your message, you can use can set
    /// these two bytes to the size of the message. But remember that they
    /// are in network byte order.
    pub fn new_tcp(capacity: usize) -> Self {
        let mut buf = BytesMut::with_capacity(capacity + 2);
        buf.put_u16_be(0);
        let mut res = Self::from_buf(buf);
        res.set_limit(::std::u16::MAX as usize);
        res.set_page_size(capacity);
        res
    }

    /// Creates a new message builder using an existing bytes buffer.
    ///
    /// The builder’s initial limit will be equal to whatever capacity is
    /// left in the buffer. As a consequence, the builder will never grow
    /// beyond that remaining capacity.
    pub fn from_buf(buf: BytesMut) -> Self {
        MessageBuilder { target: MessageTarget::from_buf(buf) }
    }

    /// Creates a message builder with the given capacity.
    ///
    /// The builder will have its own newly created bytes buffer. Its inital
    /// limit will be equal to the capacity of that buffer. This may be larger
    /// than `capacity`. If you need finer control over the limit, use
    /// [`with_params`] instead.
    ///
    /// [`with_params`]: #method.with_params
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_buf(BytesMut::with_capacity(capacity))
    }

    /// Creates a new message builder.
    ///
    /// A new buffer will be created for this builder. It will initially
    /// allocate space for at least `initial` bytes. The message will never
    /// exceed a size of `limit` bytes. Whenever the buffer’s capacity is
    /// exhausted, the builder will allocate at least another `page_size`
    /// bytes. If `page_size` is set to `0`, the builder will allocate at
    /// most once and then enough bytes to have room for the limit.
    pub fn with_params(initial: usize, limit: usize, page_size: usize)
                       -> Self {
        let mut res = Self::with_capacity(initial);
        res.set_limit(limit);
        res.set_page_size(page_size);
        res
    }

    /// Enables support for domain name compression.
    ///
    /// After this method is called, the domain names in questions, the owner
    /// domain names of resource records, and domain names appearing in the
    /// record data of record types defined in [RFC 1035] will be compressed.
    ///
    /// [RFC 1035]: ../../rdata/rfc1035.rs
    pub fn enable_compression(&mut self) {
        self.target.buf.enable_compression()
    }

    /// Sets the maximum size of the constructed DNS message.
    ///
    /// After this method was called, additional data will not be added to the
    /// message if that would result in the message exceeding a size of
    /// `limit` bytes. If the message is already larger than `limit` when the
    /// method is called, it will _not_ be truncated. That is, you can never
    /// actually set a limit smaller than the current message size.
    ///
    /// Note also that the limit only regards the message constructed by the
    /// builder itself. If a builder was created atop a buffer that already
    /// contained some data, this pre-existing data is not considered.
    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    /// Sets the amount of data by which to grow the underlying buffer.
    ///
    /// Whenever the buffer runs out of space but the message size limit has
    /// not yet been reached, the builder will grow the buffer by at least
    /// `page_size` bytes.
    ///
    /// A special case is a page size of zero, in which case the buffer will
    /// be grown only once to have enough space to reach the current limit.
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

    pub fn rewind(&mut self, snapshot: &Snapshot<Self>) {
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
    /// The method will fail if by appending the question the message would
    /// exceed its size limit.
    ///
    /// [`Question`]: ../question/struct.Question.html
    pub fn push<N: ToDname, Q: Into<Question<N>>>(&mut self, question: Q)
                                                  -> Result<(), ShortBuf> {
        self.target.push(|target| question.into().compress(target),
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
    ///
    /// Leaves the answer and additional sections empty. Since the method
    /// adds the header of the OPT record already, it can fail if there
    /// isn’t enough space left in the message.
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    pub fn preview(&self) -> &[u8] {
        self.target.preview()
    }

    /// Returns a reference to the slice preceeding the message.
    ///
    /// The slice is may be empty.
    pub fn prelude(&self) -> &[u8] {
        self.target.prelude()
    }

    /// Returns a mutable reference to the slice preceeding the message.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        self.target.prelude_mut()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    /// Finishes the messages and returns the bytes value of the message.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn freeze(self) -> Message {
        self.target.freeze()
    }
}


//------------ AnswerBuilder -------------------------------------------------

/// Builds the answer section of a DNS message.
///
/// This type is typically constructed by calling [`answer`] on a
/// [`MessageBuilder`]. See the [module documentation] for an overview of how
/// to build a message.
///
/// Once acquired, you can access a message’s header or append resource
/// records to the message’s answer section with the [`push`] method.
///
/// [`answer`]: struct.MessageBuilder.html#method.answer
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [`push`]: #method.push
/// [module documentation]: index.html
#[derive(Clone, Debug)]
pub struct AnswerBuilder {
    target: MessageTarget,
}


impl AnswerBuilder {
    /// Creates a new answer builder from a message target.
    fn new(target: MessageTarget) -> Self {
        AnswerBuilder { target }
    }

    /// Updates the message’s size limit.
    ///
    /// After this method was called, additional data will not be added to the
    /// message if that would result in the message exceeding a size of
    /// `limit` bytes. If the message is already larger than `limit` when the
    /// method is called, it will _not_ be truncated. That is, you can never
    /// actually set a limit smaller than the current message size.
    ///
    /// Note also that the limit only regards the message constructed by the
    /// builder itself. If a builder was created atop a buffer that already
    /// contained some data, this pre-existing data is not considered.
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

    /// Returns a snapshot indicating the current state of the message.
    ///
    /// The returned value can be used to later return the message to the
    /// state at the time the method was called through the [`rewind`]
    /// method.
    ///
    /// [`rewind`]: #method.rewind
    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    /// Rewinds the message to the state it had at `snapshot`.
    ///
    /// This will truncate the message to the size it had at the time the
    /// [`snapshot`] method was called, making it forget all records added
    /// since.
    ///
    /// [`snapshot`]: #method.snapshot
    pub fn rewind(&mut self, snapshot: &Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the answer section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// If appending the record would result in the message exceeding its
    /// size limit, the method will fail.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
                where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.target.push(|target| record.into().compress(target),
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
    ///
    /// The method will start by adding the record header. Since this may
    /// exceed the message limit, the method may fail.
    /// If you have saved space for the OPT record via [`set_limit`] earlier,
    /// remember to increase the limit again before calling `opt`.
    ///
    /// [`set_limit`]: #method.set_limit
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    pub fn preview(&self) -> &[u8] {
        self.target.preview()
    }

    /// Returns a reference to the slice preceeding the message.
    ///
    /// The slice is may be empty.
    pub fn prelude(&self) -> &[u8] {
        self.target.prelude()
    }

    /// Returns a mutable reference to the slice preceeding the message.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        self.target.prelude_mut()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with empty authority and additional
    /// sections.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    /// Finishes the message and returns the resulting bytes value.
    ///
    /// This will result in a message with empty authority and additional
    /// sections.
    pub fn freeze(self) -> Message {
        self.target.freeze()
    }
}


//------------ AuthorityBuilder ---------------------------------------------

/// Builds the authority section of a DNS message.
///
/// This type can be constructed by calling `authority()` on a
/// [`MessageBuilder`] or [`AnswerBuilder`]. See the [module documentation]
/// for details on constructing messages.
///
/// Once acquired, you can use this type to add records to the authority
/// section of a message via the [`push`] method.
///
/// [`AnswerBuilder`]: struct.AnswerBuilder.html
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [`push`]: #method.push
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

    /// Updates the message’s size limit.
    ///
    /// After this method was called, additional data will not be added to the
    /// message if that would result in the message exceeding a size of
    /// `limit` bytes. If the message is already larger than `limit` when the
    /// method is called, it will _not_ be truncated. That is, you can never
    /// actually set a limit smaller than the current message size.
    ///
    /// Note also that the limit only regards the message constructed by the
    /// builder itself. If a builder was created atop a buffer that already
    /// contained some data, this pre-existing data is not considered.
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

    /// Returns a snapshot indicating the current state of the message.
    ///
    /// The returned value can be used to later return the message to the
    /// state at the time the method was called through the [`rewind`]
    /// method.
    ///
    /// [`rewind`]: #method.rewind
    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    /// Rewinds the message to the state it had at `snapshot`.
    ///
    /// This will truncate the message to the size it had at the time the
    /// [`snapshot`] method was called, making it forget all records added
    /// since.
    ///
    /// [`snapshot`]: #method.snapshot
    pub fn rewind(&mut self, snapshot: &Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the authority section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// If appending the record would result in the message exceeding its
    /// size limit, the method will fail.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
                where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.target.push(|target| record.into().compress(target),
                         |counts| counts.inc_nscount())
    }

    /// Proceeds to building the additional section.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.target)
    }

    /// Proceeds to building the OPT record.
    ///
    /// The method will start by adding the record header. Since this may
    /// exceed the message limit, the method may fail.
    /// If you have saved space for the OPT record via [`set_limit`] earlier,
    /// remember to increase the limit again before calling `opt`.
    ///
    /// [`set_limit`]: #method.set_limit
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        self.additional().opt()
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    pub fn preview(&self) -> &[u8] {
        self.target.preview()
    }

    /// Returns a reference to the slice preceeding the message.
    ///
    /// The slice is may be empty.
    pub fn prelude(&self) -> &[u8] {
        self.target.prelude()
    }

    /// Returns a mutable reference to the slice preceeding the message.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        self.target.prelude_mut()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    ///
    /// This will result in a message with an empty additional section.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    /// Finishes the message and returns the resulting bytes value.
    ///
    /// This will result in a message with an empty additional section.
    pub fn freeze(self) -> Message {
        self.target.freeze()
    }
}


//------------ AdditionalBuilder --------------------------------------------

/// Builds the additional section of a DNS message.
///
/// This type can be constructed by calling `additional` on a
/// [`MessageBuilder`], [`AnswerBuilder`], or [`AuthorityBuilder`]. See the
/// [module documentation] for on overview on building messages.
///
/// Once aquired, you can add records to the additional section via the
/// [`push`] method. If the record you want to add is an OPT record, you
/// can also use the [`OptBuilder`] type which you can acquire via the
/// [`opt`] method.
///
/// [`AnswerBuilder`]: struct.AnswerBuilder.html
/// [`AuthorityBuilder`]: struct.AuthorityBuilder.html
/// [`MessageBuilder`]: struct.MessageBuilder.html
/// [`OptBuilder`]: struct.OptBuilder.html
/// [`push`]: #method.push
/// [`opt`]: #method.opt
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

    /// Updates the message’s size limit.
    ///
    /// After this method was called, additional data will not be added to the
    /// message if that would result in the message exceeding a size of
    /// `limit` bytes. If the message is already larger than `limit` when the
    /// method is called, it will _not_ be truncated. That is, you can never
    /// actually set a limit smaller than the current message size.
    ///
    /// Note also that the limit only regards the message constructed by the
    /// builder itself. If a builder was created atop a buffer that already
    /// contained some data, this pre-existing data is not considered.
    pub fn set_limit(&mut self, limit: usize) {
        self.target.buf.set_limit(limit)
    }

    /// Returns a mutable reference to the messages header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.target.header_mut()
    }

    /// Returns a snapshot indicating the current state of the message.
    ///
    /// The returned value can be used to later return the message to the
    /// state at the time the method was called through the [`rewind`]
    /// method.
    ///
    /// [`rewind`]: #method.rewind
    pub fn snapshot(&self) -> Snapshot<Self> {
        self.target.snapshot()
    }

    /// Rewinds the message to the state it had at `snapshot`.
    ///
    /// This will truncate the message to the size it had at the time the
    /// [`snapshot`] method was called, making it forget all records added
    /// since.
    ///
    /// [`snapshot`]: #method.snapshot
    pub fn rewind(&mut self, snapshot: &Snapshot<Self>) {
        self.target.rewind(snapshot)
    }

    /// Appends a new resource record to the additional section.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// If appending the record would result in the message exceeding its
    /// size limit, the method will fail.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D, R>(&mut self, record: R) -> Result<(), ShortBuf>
                where N: ToDname, D: RecordData, R: Into<Record<N, D>> {
        self.target.push(|target| record.into().compress(target),
                         |counts| counts.inc_nscount())
    }

    /// Proceeds to building the OPT record.
    ///
    /// The method will start by adding the record header. Since this may
    /// exceed the message limit, the method may fail.
    /// If you have saved space for the OPT record via [`set_limit`] earlier,
    /// remember to increase the limit again before calling `opt`.
    ///
    /// [`set_limit`]: #method.set_limit
    pub fn opt(self) -> Result<OptBuilder, ShortBuf> {
        OptBuilder::new(self.target)
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    pub fn preview(&self) -> &[u8] {
        self.target.preview()
    }

    /// Returns a reference to the slice preceeding the message.
    ///
    /// The slice is may be empty.
    pub fn prelude(&self) -> &[u8] {
        self.target.prelude()
    }

    /// Returns a mutable reference to the slice preceeding the message.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        self.target.prelude_mut()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    /// Finishes the message and returns the resulting bytes value.
    pub fn freeze(self) -> Message {
        self.target.freeze()
    }
}


//------------ OptBuilder ----------------------------------------------------

/// Builds an OPT record as part of the additional section of a DNS message,
///
/// This type can be constructed by calling the `opt` method on any other
/// builder type.  See the [module documentation] for on overview
/// on building messages.
///
/// As OPT records are part of the additional section, this type will, when
/// constructed proceed to this section and append an OPT record without any
/// options to it. Options can be appened via the [`push`] method.
///
/// The type also deref-muts to [`OptHeader`] allowing you to modify the
/// header’s fields such as setting the
/// [UDP payload size][`OptHeader::set_udp_payload_size`] or the
/// [DO bit][`OptHeader::set_dnssec_ok`].
///
/// Once you have adjusted the OPT record to your liking, you can return to
/// the additional section via [`additional`]. Note, however, that the OPT
/// record should be the last record except for a possible TSIG record. You
/// can also finish the message via [`finish`] or [`freeze`].
///
/// [module documentation]: index.html
/// [`OptHeader`]: ../opt/struct.OptHeader.html
/// [`additional`]: #method.additional
/// [`finish`]: #method.finish
/// [`freeze`]: #method.freeze
/// [`push`]: #method.push
/// [`OptHeader::set_udp_payload_size`]: ../opt/struct.OptHeader.html#method.set_udp_payload_size
/// [`OptHeader::set_dnssec_ok`]: ../opt/struct.OptHeader.html#method.set_dnssec_ok
#[derive(Clone, Debug)]
pub struct OptBuilder {
    target: MessageTarget,

    /// The position of in `target` of the start of the OPT record.
    pos: usize,
}

impl OptBuilder {
    /// Creates a new OPT builder atop the given target.
    ///
    /// This appends the OPT header to the message but doesn’t increase the
    /// ARCOUNT of the message just yet.
    fn new(mut target: MessageTarget) -> Result<Self, ShortBuf> {
        let pos = target.len();
        target.compose(&OptHeader::default())?;
        target.compose(&0u16)?;
        target.counts_mut().inc_arcount();
        Ok(OptBuilder { pos, target })
    }

    /// Pushes an option to the OPT record.
    ///
    /// The method is generic over anything that implements the `OptData`
    /// trait representing an option. Alternatively, most of these types
    /// provide a `push` associated function that allows to construct an
    /// option directly into a record from its data.
    pub fn push<O: OptData>(&mut self, option: &O) -> Result<(), ShortBuf> {
        self.target.compose(&option.code())?;
        let len = option.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        self.target.compose(&(len as u16))?;
        self.target.compose(option)?;
        self.complete();
        Ok(())
    }

    /// Builds an option into the record.
    ///
    /// The option will have the option code `code`. Its data will be `len`
    /// octets long and appened to the record via the `op` closure.
    pub(super) fn build<F>(&mut self, code: OptionCode, len: u16, op: F)
                           -> Result<(), ShortBuf>
                        where F: FnOnce(&mut Compressor)
                                        -> Result<(), ShortBuf> {
        self.target.compose(&code)?;
        self.target.compose(&len)?;
        op(&mut self.target.buf)?;
        self.complete();
        Ok(())
    }

    /// Completes the OPT record and returns to the additional section builder.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.target)
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    pub fn preview(&self) -> &[u8] {
        self.target.preview()
    }

    /// Returns a reference to the slice preceeding the message.
    ///
    /// The slice is may be empty.
    pub fn prelude(&self) -> &[u8] {
        self.target.prelude()
    }

    /// Returns a mutable reference to the slice preceeding the message.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        self.target.prelude_mut()
    }

    /// Finishes the message and returns the underlying bytes buffer.
    pub fn finish(self) -> BytesMut {
        self.target.unwrap()
    }

    /// Finishes the message and returns it.
    pub fn freeze(self) -> Message {
        self.target.freeze()
    }

    /// Completes building the OPT record.
    ///
    /// This will update the RDLEN field of the record header.
    fn complete(&mut self) {
        let len = self.target.len()
                - (self.pos + mem::size_of::<OptHeader>() + 2);
        assert!(len <= ::std::u16::MAX as usize);
        let count_pos = self.pos + mem::size_of::<OptHeader>();
        BigEndian::write_u16(&mut self.target.as_slice_mut()[count_pos..],
                             len as u16);
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
        if buf.remaining_mut() < mem::size_of::<HeaderSection>() {
            let additional = mem::size_of::<HeaderSection>()
                           - buf.remaining_mut();
            buf.reserve(additional)
        }
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
    /// messages header to reflect the new element.
    fn push<O, I, E>(&mut self, composeop: O, incop: I) -> Result<(), E>
            where O: FnOnce(&mut Compressor) -> Result<(), E>,
                  I: FnOnce(&mut HeaderCounts) {
        composeop(&mut self.buf).map(|()| incop(self.counts_mut()))
    }

    fn snapshot<T>(&self) -> Snapshot<T> {
        Snapshot {
            pos: self.buf.len(),
            counts: *self.counts(),
            marker: PhantomData,
        }
    }

    fn rewind<T>(&mut self, snapshot: &Snapshot<T>) {
        self.buf.truncate(snapshot.pos);
        self.counts_mut().set(snapshot.counts);
    }

    /// Returns a reference to the message assembled so far.
    ///
    /// In case the builder was created from a buffer with pre-existing
    /// content, the returned reference is for the complete content of this
    /// buffer.
    fn preview(&self) -> &[u8] {
        self.buf.as_slice()
    }

    fn prelude(&self) -> &[u8] {
        &self.buf.as_slice()[..self.start]
    }

    fn prelude_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_slice_mut()[..self.start]
    }

    fn unwrap(self) -> BytesMut {
        self.buf.unwrap()
    }

    fn freeze(self) -> Message {
        let bytes = if self.start == 0 {
            self.buf.unwrap().freeze()
        }
        else {
            self.buf.unwrap().freeze().slice_from(self.start)
        };
        unsafe { Message::from_bytes_unchecked(bytes) }
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

/// Contains information about the state of a message.
///
/// This type is returned by the `snapshot` method of the various builders and
/// allows to later return to that state through the `rewind` method.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot<T> {
    pos: usize,
    counts: HeaderCounts,
    marker: PhantomData<T>,
}

