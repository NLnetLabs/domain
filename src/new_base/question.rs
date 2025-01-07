//! DNS questions.

use domain_macros::*;

use super::{
    build::{self, BuildIntoMessage},
    name::RevNameBuf,
    parse::{ParseFromMessage, SplitFromMessage},
    wire::{AsBytes, ParseError, TruncationError, U16},
    Message,
};

//----------- Question -------------------------------------------------------

/// A DNS question.
#[derive(Clone, BuildBytes, ParseBytes, SplitBytes)]
pub struct Question<N> {
    /// The domain name being requested.
    pub qname: N,

    /// The type of the requested records.
    pub qtype: QType,

    /// The class of the requested records.
    pub qclass: QClass,
}

/// An unparsed DNS question.
pub type UnparsedQuestion = Question<RevNameBuf>;

//--- Construction

impl<N> Question<N> {
    /// Construct a new [`Question`].
    pub fn new(qname: N, qtype: QType, qclass: QClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N> SplitFromMessage<'a> for Question<N>
where
    N: SplitFromMessage<'a>,
{
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (qname, rest) = N::split_from_message(message, start)?;
        let (&qtype, rest) = <&QType>::split_from_message(message, rest)?;
        let (&qclass, rest) = <&QClass>::split_from_message(message, rest)?;
        Ok((Self::new(qname, qtype, qclass), rest))
    }
}

impl<'a, N> ParseFromMessage<'a> for Question<N>
where
    N: SplitFromMessage<'a>,
{
    fn parse_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<Self, ParseError> {
        let (qname, rest) = N::split_from_message(message, start)?;
        let (&qtype, rest) = <&QType>::split_from_message(message, rest)?;
        let &qclass = <&QClass>::parse_from_message(message, rest)?;
        Ok(Self::new(qname, qtype, qclass))
    }
}

//--- Building into DNS messages

impl<N> BuildIntoMessage for Question<N>
where
    N: BuildIntoMessage,
{
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.qname.build_into_message(builder.delegate())?;
        builder.append_bytes(self.qtype.as_bytes())?;
        builder.append_bytes(self.qclass.as_bytes())?;
        Ok(())
    }
}

//----------- QType ----------------------------------------------------------

/// The type of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct QType {
    /// The type code.
    pub code: U16,
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct QClass {
    /// The class code.
    pub code: U16,
}
