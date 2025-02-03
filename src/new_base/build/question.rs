//! Building DNS questions.

use crate::new_base::{
    name::UnparsedName,
    parse::ParseMessageBytes,
    wire::{ParseBytes, TruncationError},
    QClass, QType, Question,
};

use super::{BuildCommitted, BuildIntoMessage, MessageBuilder, MessageState};

//----------- QuestionBuilder ------------------------------------------------

/// A DNS question builder.
///
/// A [`QuestionBuilder`] provides control over a DNS question that has been
/// appended to a message (using a [`MessageBuilder`]).  It can be used to
/// inspect the question's fields, to replace it with a new question, and to
/// commit (finish building) or cancel (remove) the question.
pub struct QuestionBuilder<'b> {
    /// The underlying message builder.
    builder: MessageBuilder<'b, 'b>,

    /// The offset of the question name.
    name: u16,
}

//--- Construction

impl<'b> QuestionBuilder<'b> {
    /// Build a [`Question`].
    ///
    /// The provided builder must be empty (i.e. must not have uncommitted
    /// content).
    pub(super) fn build<N: BuildIntoMessage>(
        mut builder: MessageBuilder<'b, 'b>,
        question: &Question<N>,
    ) -> Result<Self, TruncationError> {
        // TODO: Require that the QNAME serialize correctly?
        let start = builder.context.size;
        question.build_into_message(builder.builder(start))?;
        let name = start.try_into().expect("Messages are at most 64KiB");
        builder.context.state = MessageState::MidQuestion { name };
        Ok(Self { builder, name })
    }

    /// Reconstruct a [`QuestionBuilder`] from raw parts.
    ///
    /// # Safety
    ///
    /// `builder.message().contents[name..]` must represent a valid
    /// [`Question`] in the wire format.
    pub unsafe fn from_raw_parts(
        builder: MessageBuilder<'b, 'b>,
        name: u16,
    ) -> Self {
        Self { builder, name }
    }
}

//--- Inspection

impl<'b> QuestionBuilder<'b> {
    /// The (unparsed) question name.
    pub fn qname(&self) -> &UnparsedName {
        let contents = &self.builder.message().contents;
        let contents = &contents[usize::from(self.name)..contents.len() - 4];
        <&UnparsedName>::parse_message_bytes(contents, self.name.into())
            .expect("The question was serialized correctly")
    }

    /// The question type.
    pub fn qtype(&self) -> QType {
        let contents = &self.builder.message().contents;
        QType::parse_bytes(&contents[contents.len() - 4..contents.len() - 2])
            .expect("The question was serialized correctly")
    }

    /// The question class.
    pub fn qclass(&self) -> QClass {
        let contents = &self.builder.message().contents;
        QClass::parse_bytes(&contents[contents.len() - 2..])
            .expect("The question was serialized correctly")
    }

    /// Deconstruct this [`QuestionBuilder`] into its raw parts.
    pub fn into_raw_parts(self) -> (MessageBuilder<'b, 'b>, u16) {
        (self.builder, self.name)
    }
}

//--- Interaction

impl QuestionBuilder<'_> {
    /// Commit this question.
    ///
    /// The builder will be consumed, and the question will be committed so
    /// that it can no longer be removed.
    pub fn commit(self) -> BuildCommitted {
        self.builder.context.state = MessageState::Questions;
        self.builder.message.header.counts.questions += 1;
        BuildCommitted
    }

    /// Stop building and remove this question.
    ///
    /// The builder will be consumed, and the question will be removed.
    pub fn cancel(self) {
        self.builder.context.size = self.name.into();
        self.builder.context.state = MessageState::Questions;
    }
}
