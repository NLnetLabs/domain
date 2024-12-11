//! DNS questions.

use core::ops::Range;

use zerocopy::network_endian::U16;
use zerocopy_derive::*;

use super::{
    name::RevNameBuf,
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    Message,
};

//----------- Question -------------------------------------------------------

/// A DNS question.
#[derive(Clone)]
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
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let (qname, rest) = N::split_from_message(message, range.start)?;
        let (&qtype, rest) = <&QType>::split_from_message(message, rest)?;
        let &qclass =
            <&QClass>::parse_from_message(message, rest..range.end)?;
        Ok(Self::new(qname, qtype, qclass))
    }
}

//--- Parsing from bytes

impl<'a, N> SplitFrom<'a> for Question<N>
where
    N: SplitFrom<'a>,
{
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (qname, rest) = N::split_from(bytes)?;
        let (&qtype, rest) = <&QType>::split_from(rest)?;
        let (&qclass, rest) = <&QClass>::split_from(rest)?;
        Ok((Self::new(qname, qtype, qclass), rest))
    }
}

impl<'a, N> ParseFrom<'a> for Question<N>
where
    N: SplitFrom<'a>,
{
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (qname, rest) = N::split_from(bytes)?;
        let (&qtype, rest) = <&QType>::split_from(rest)?;
        let &qclass = <&QClass>::parse_from(rest)?;
        Ok(Self::new(qname, qtype, qclass))
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct QClass {
    /// The class code.
    pub code: U16,
}
