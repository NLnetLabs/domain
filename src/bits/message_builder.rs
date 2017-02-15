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

use std::mem;
use super::{Composer, ComposeError, ComposeMode, ComposeResult,
            ComposeSnapshot, DName, HeaderSection, Header, HeaderCounts,
            Message, Question, Record, RecordData};


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


/// # Creation
///
impl MessageBuilder {
    /// Creates a new empty DNS message.
    ///
    /// The `mode` argument decides whether the message will have a size
    /// limit and whether it should include the length prefix for use with
    /// stream transports. If `compress` is `true`, name compression will
    /// be enabled for the message.
    ///
    /// This function may fail if the size limit in `mode` is too small to
    /// even add the header section.
    pub fn new(mode: ComposeMode, compress: bool) -> ComposeResult<Self> {
        Self::from_composer(Composer::new(mode, compress))
    }

    /// Creates a new DNS message appended to the content of a bytes vector.
    ///
    /// The `mode` argument decides whether the message will have a size
    /// limit and whether it should include the length prefix for use with
    /// stream transports. If `compress` is `true`, name compression will
    /// be enabled for the message.
    ///
    /// This function may fail if the size limit in `mode` is too small to
    /// even add the header section.
    pub fn from_vec(vec: Vec<u8>, mode: ComposeMode, compress: bool)
                    -> ComposeResult<Self> {
        Self::from_composer(Composer::from_vec(vec, mode, compress))
    }

    /// Creates a new DNS message atop an existing composer.
    ///
    /// This doesn’t reset the composer but starts off after whatever is in
    /// there already. As this may result in invalid message, user discretion
    /// is advised.
    pub fn from_composer(mut composer: Composer) -> ComposeResult<Self> {
        try!(composer.compose_empty(mem::size_of::<HeaderSection>()));
        Ok(MessageBuilder{target: MessageTarget::new(composer)})
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

    /// Appends a new question to the message.
    ///
    /// This function is generic over anything that can be converted into a
    /// [`Question`]. In particular, triples of a domain name, a record type,
    /// and a class as well as pairs of just a domain name and a record type
    /// fulfill this requirement with the class assumed to be `Class::In` in
    /// the latter case.
    ///
    /// [`Question`]: ../question/struct.Question.html
    pub fn push<N: DName, Q: Into<Question<N>>>(&mut self, question: Q)
                          -> ComposeResult<()> {
        self.target.push(|target| question.into().compose(target),
                         |counts| counts.inc_qdcount(1))
    }

    /// Rewinds to the beginning of the question section.
    ///
    /// This drops all previously assembled questions.
    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_qdcount(0));
    }

    /// Proceeds to building the answer section.
    pub fn answer(self) -> AnswerBuilder {
        AnswerBuilder::new(self.target.commit())
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

    /// Finishes the message and returns the underlying target.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
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
    fn new(composer: Composer) -> Self {
        AnswerBuilder { 
            target: MessageTarget::new(composer)
        }
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
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N, D, R>(&mut self, record: R) -> ComposeResult<()>
                where N: DName,
                      D: RecordData,
                      R: Into<Record<N, D>> {
        self.target.push(|target| record.into().compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Rewinds to the beginning of the answer section.
    ///
    /// This drops all previously assembled answer records.
    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_ancount(0))
    }

    /// Proceeds to building the authority section.
    pub fn authority(self) -> AuthorityBuilder {
        AuthorityBuilder::new(self.target.commit())
    }

    /// Proceeds to building the additional section, skipping authority.
    pub fn additional(self) -> AdditionalBuilder {
        self.authority().additional()
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

    /// Finishes the message.
    ///
    /// The resulting message will have empty authority and additional
    /// sections.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
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
    fn new(composer: Composer) -> Self {
        AuthorityBuilder { 
            target: MessageTarget::new(composer)
        }
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
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N: DName, D: RecordData>(&mut self, record: Record<N, D>)
                                         -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Rewinds to the beginning of the authority section.
    ///
    /// This drops all previously assembled authority records.
    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_ancount(0))
    }

    /// Proceeds to building the additional section.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.target.commit())
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

    /// Finishes the message.
    ///
    /// The resulting message will have an empty additional section.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
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
    fn new(composer: Composer) -> Self {
        AdditionalBuilder { 
            target: MessageTarget::new(composer)
        }
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
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Record`]. In particular, you can use four-tuples consisting of
    /// a domain name, class, TTL, and record data or triples leaving out
    /// the class which will then be assumed to be `Class::In`.
    ///
    /// [`Record`]: ../record/struct.Record.html
    pub fn push<N: DName, D: RecordData>(&mut self, record: Record<N, D>)
                                         -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    /// Rewinds to the beginning of the additional section.
    ///
    /// This drops all previously assembled additonal records.
    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_ancount(0))
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

    /// Finishes the message.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
    }
}

impl AsRef<Message> for AdditionalBuilder {
    fn as_ref(&self) -> &Message {
        self.target.as_ref()
    }
}


//------------ MessageTarget -------------------------------------------------

/// Underlying data for constructing a DNS message.
///
/// This private type does all the heavy lifting for constructing messages.
#[derive(Clone, Debug)]
struct MessageTarget {
    composer: ComposeSnapshot,
}


impl MessageTarget {
    /// Creates a new message target atop a given composer.
    fn new(composer: Composer) -> Self {
        MessageTarget{composer: composer.snapshot()}
    }

    /// Returns a reference to the message’s header.
    fn header(&self) -> &Header {
        Header::from_message(self.composer.so_far())
    }

    /// Returns a mutable reference to the message’s header.
    fn header_mut(&mut self) -> &mut Header {
        Header::from_message_mut(self.composer.so_far_mut())
    }

    /// Returns a mutable reference to the message’s header counts.
    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::from_message_mut(self.composer.so_far_mut())
    }

    /// Pushes something to the end of the message.
    ///
    /// There’s two closures here. The first one, `composeop` actually
    /// writes the data. The second, `incop` increments the counter in the
    /// messages header to reflect the new element.
    fn push<O, I>(&mut self, composeop: O, incop: I) -> ComposeResult<()>
            where O: FnOnce(&mut Composer) -> ComposeResult<()>,
                  I: FnOnce(&mut HeaderCounts) -> ComposeResult<()> {
        if !self.composer.is_truncated() {
            self.composer.mark_checkpoint();
            match composeop(&mut self.composer) {
                Ok(()) => {
                    try!(incop(self.counts_mut()));
                    Ok(())
                }
                Err(ComposeError::SizeExceeded) => Ok(()),
                Err(error) => Err(error)
            }
        }
        else { Ok(()) }
    }

    /// Returns a reference to the message assembled so far.
    fn preview(&mut self) -> &[u8] {
        self.composer.preview()
    }

    /// Finishes the message building and extracts the underlying vector.
    fn finish(mut self) -> Vec<u8> {
        let tc = self.composer.is_truncated();
        self.header_mut().set_tc(tc);
        self.composer.commit().finish()
    }

    /// Rewinds the compose snapshots and allows updating the header counts.
    fn rewind<F>(&mut self, op: F)
              where F: FnOnce(&mut HeaderCounts) {
        op(self.counts_mut());
        self.composer.rewind()
    }

    /// Commit the compose snapshot.
    fn commit(self) -> Composer {
        self.composer.commit()
    }
}


impl AsRef<Message> for MessageTarget {
    fn as_ref(&self) -> &Message {
        unsafe { Message::from_bytes_unsafe(self.composer.so_far()) }
    }
}
