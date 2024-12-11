//! Parsing DNS messages.

use core::ops::ControlFlow;

use crate::new_base::{Header, Question, Record};

/// A type that can be constructed by parsing a DNS message.
pub trait ParseMessage<'a>: Sized {
    /// The type of visitors for incrementally building the output.
    type Visitor: VisitMessagePart<'a>;

    /// The type of errors from converting a visitor into [`Self`].
    // TODO: Just use 'Visitor::Error'?
    type Error;

    /// Construct a visitor, providing the message header.
    fn make_visitor(header: &'a Header)
        -> Result<Self::Visitor, Self::Error>;

    /// Convert a visitor back to this type.
    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error>;
}

/// A type that can visit the components of a DNS message.
pub trait VisitMessagePart<'a> {
    /// The type of errors produced by visits.
    type Error;

    /// Visit a component of the message.
    fn visit(
        &mut self,
        component: MessagePart<'a>,
    ) -> Result<ControlFlow<()>, Self::Error>;
}

/// A component of a DNS message.
pub enum MessagePart<'a> {
    /// A question.
    Question(Question<'a>),

    /// An answer record.
    Answer(Record<'a>),

    /// An authority record.
    Authority(Record<'a>),

    /// An additional record.
    Additional(Record<'a>),
}
