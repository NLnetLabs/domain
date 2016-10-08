//! Building a new message.

use std::mem;
use super::{Composer, ComposeError, ComposeMode, ComposeResult,
            ComposeSnapshot, DName, HeaderSection, Header, HeaderCounts,
            Question, Record, RecordData};


//------------ MessageBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct MessageBuilder {
    target: MessageTarget,
}


/// # Creation
///
impl MessageBuilder {
    pub fn new(mode: ComposeMode, compress: bool) -> ComposeResult<Self> {
        Self::from_composer(Composer::new(mode, compress))
    }

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
    pub fn push<N: DName, Q: Into<Question<N>>>(&mut self, question: Q)
                          -> ComposeResult<()> {
        self.target.push(|target| question.into().compose(target),
                         |counts| counts.inc_qdcount(1))
    }

    pub fn preview(&mut self) -> &[u8] {
        self.target.preview()
    }

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

    /// Finishes the message and returns the underlying target.
    ///
    /// This will result in a message with all three record sections empty.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
    }
}


//------------ AnswerBuilder -------------------------------------------------

#[derive(Clone, Debug)]
pub struct AnswerBuilder {
    target: MessageTarget,
}


impl AnswerBuilder {
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
    pub fn push<N: DName, D: RecordData>(&mut self, record: Record<N, D>)
                                         -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

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

    /// Finishes the message.
    ///
    /// The resulting message will have empty authority and additional
    /// sections.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
    }
}


//------------ AuthorityBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct AuthorityBuilder {
    target: MessageTarget,
}


impl AuthorityBuilder {
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

    /// Appends a new resource record to the answer section.
    pub fn push<N: DName, D: RecordData>(&mut self, record: Record<N, D>)
                                         -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_ancount(0))
    }

    /// Proceeds to building the additional section.
    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.target.commit())
    }


    /// Finishes the message.
    ///
    /// The resulting message will have empty authority and additional
    /// sections.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
    }
}


//------------ AdditionalBuilder --------------------------------------------

#[derive(Clone, Debug)]
pub struct AdditionalBuilder {
    target: MessageTarget,
}


impl AdditionalBuilder {
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

    /// Appends a new resource record to the answer section.
    pub fn push<N: DName, D: RecordData>(&mut self, record: Record<N, D>)
                                         -> ComposeResult<()> {
        self.target.push(|target| record.compose(target),
                         |counts| counts.inc_ancount(1))
    }

    pub fn rewind(&mut self) {
        self.target.rewind(|counts| counts.set_ancount(0))
    }

    /// Finishes the message.
    ///
    /// The resulting message will have empty authority and additional
    /// sections.
    pub fn finish(self) -> Vec<u8> {
        self.target.finish()
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

    fn preview(&mut self) -> &[u8] {
        self.composer.preview()
    }

    /// Finishes the message building and extracts the underlying vector.
    fn finish(mut self) -> Vec<u8> {
        let tc = self.composer.is_truncated();
        self.header_mut().set_tc(tc);
        self.composer.commit().finish()
    }

    fn rewind<F>(&mut self, op: F)
              where F: FnOnce(&mut HeaderCounts) {
        op(self.counts_mut());
        self.composer.rewind()
    }

    fn commit(self) -> Composer {
        self.composer.commit()
    }
}

