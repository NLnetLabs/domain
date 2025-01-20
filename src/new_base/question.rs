//! DNS questions.

use domain_macros::*;

use super::{
    build::{self, BuildIntoMessage, BuildResult},
    name::RevNameBuf,
    parse::{ParseFromMessage, SplitFromMessage},
    wire::{AsBytes, ParseError, U16},
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
    ) -> BuildResult {
        self.qname.build_into_message(builder.delegate())?;
        builder.append_bytes(self.qtype.as_bytes())?;
        builder.append_bytes(self.qclass.as_bytes())?;
        Ok(builder.commit())
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

//--- Associated Constants

impl QType {
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of an [`A`](crate::new_rdata::A) record.
    pub const A: Self = Self::new(1);

    /// The type of an [`Ns`](crate::new_rdata::Ns) record.
    pub const NS: Self = Self::new(2);

    /// The type of a [`CName`](crate::new_rdata::CName) record.
    pub const CNAME: Self = Self::new(5);

    /// The type of an [`Soa`](crate::new_rdata::Soa) record.
    pub const SOA: Self = Self::new(6);

    /// The type of a [`Wks`](crate::new_rdata::Wks) record.
    pub const WKS: Self = Self::new(11);

    /// The type of a [`Ptr`](crate::new_rdata::Ptr) record.
    pub const PTR: Self = Self::new(12);

    /// The type of a [`HInfo`](crate::new_rdata::HInfo) record.
    pub const HINFO: Self = Self::new(13);

    /// The type of a [`Mx`](crate::new_rdata::Mx) record.
    pub const MX: Self = Self::new(15);

    /// The type of a [`Txt`](crate::new_rdata::Txt) record.
    pub const TXT: Self = Self::new(16);

    /// The type of an [`Aaaa`](crate::new_rdata::Aaaa) record.
    pub const AAAA: Self = Self::new(28);
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

//--- Associated Constants

impl QClass {
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The Internet class.
    pub const IN: Self = Self::new(1);

    /// The CHAOS class.
    pub const CH: Self = Self::new(3);
}
