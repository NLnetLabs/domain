//! DNS questions.

use core::fmt;

use domain_macros::*;

use super::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseError, U16},
};

//----------- Question -------------------------------------------------------

/// A DNS question.
#[derive(Clone, Debug, BuildBytes, ParseBytes, SplitBytes, PartialEq, Eq)]
pub struct Question<N> {
    /// The domain name being requested.
    pub qname: N,

    /// The type of the requested records.
    pub qtype: QType,

    /// The class of the requested records.
    pub qclass: QClass,
}

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

//--- Interaction

impl<N> Question<N> {
    /// Map the name in this question to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Question<R> {
        Question {
            qname: (f)(self.qname),
            qtype: self.qtype,
            qclass: self.qclass,
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N> SplitMessageBytes<'a> for Question<N>
where
    N: SplitMessageBytes<'a>,
{
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let (qname, rest) = N::split_message_bytes(contents, start)?;
        let (&qtype, rest) = <&QType>::split_message_bytes(contents, rest)?;
        let (&qclass, rest) = <&QClass>::split_message_bytes(contents, rest)?;
        Ok((Self::new(qname, qtype, qclass), rest))
    }
}

impl<'a, N> ParseMessageBytes<'a> for Question<N>
where
    // TODO: Reduce to 'ParseMessageBytes'.
    N: SplitMessageBytes<'a>,
{
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        match Self::split_message_bytes(contents, start) {
            Ok((this, rest)) if rest == contents.len() => Ok(this),
            _ => Err(ParseError),
        }
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
    /// Create a new [`QType`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of queries for [`A`](crate::new_rdata::A) records.
    pub const A: Self = Self::new(1);

    /// The type of queries for [`Ns`](crate::new_rdata::Ns) records.
    pub const NS: Self = Self::new(2);

    /// The type of queries for [`CName`](crate::new_rdata::CName) records.
    pub const CNAME: Self = Self::new(5);

    /// The type of queries for [`Soa`](crate::new_rdata::Soa) records.
    pub const SOA: Self = Self::new(6);

    /// The type of queries for [`Wks`](crate::new_rdata::Wks) records.
    pub const WKS: Self = Self::new(11);

    /// The type of queries for [`Ptr`](crate::new_rdata::Ptr) records.
    pub const PTR: Self = Self::new(12);

    /// The type of queries for [`HInfo`](crate::new_rdata::HInfo) records.
    pub const HINFO: Self = Self::new(13);

    /// The type of queries for [`Mx`](crate::new_rdata::Mx) records.
    pub const MX: Self = Self::new(15);

    /// The type of queries for [`Txt`](crate::new_rdata::Txt) records.
    pub const TXT: Self = Self::new(16);

    /// The type of queries for [`Aaaa`](crate::new_rdata::Aaaa) records.
    pub const AAAA: Self = Self::new(28);
}

//--- Formatting

impl fmt::Debug for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::A => "QType::A",
            Self::NS => "QType::NS",
            Self::CNAME => "QType::CNAME",
            Self::SOA => "QType::SOA",
            Self::WKS => "QType::WKS",
            Self::PTR => "QType::PTR",
            Self::HINFO => "QType::HINFO",
            Self::MX => "QType::MX",
            Self::TXT => "QType::TXT",
            Self::AAAA => "QType::AAAA",
            _ => return write!(f, "QType({})", self.code),
        })
    }
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
#[derive(
    Copy,
    Clone,
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
    /// Create a new [`QClass`].
    const fn new(value: u16) -> Self {
        Self {
            code: U16::new(value),
        }
    }

    /// The type of queries in the Internet class.
    pub const IN: Self = Self::new(1);

    /// The type of queries in the CHAOS class.
    pub const CH: Self = Self::new(3);
}

//--- Formatting

impl fmt::Debug for QClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::IN => "QClass::IN",
            Self::CH => "QClass::CH",
            _ => return write!(f, "QClass({})", self.code),
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::{QClass, QType, Question};

    use crate::new_base::{
        name::Name,
        wire::{BuildBytes, ParseBytes, ParseError, SplitBytes},
    };

    #[test]
    fn parse_build() {
        let bytes = b"\x03com\x00\x00\x01\x00\x01\x2A";
        let (question, rest) = <Question<&Name>>::split_bytes(bytes).unwrap();
        assert_eq!(question.qname.as_bytes(), b"\x03com\x00");
        assert_eq!(question.qtype, QType::A);
        assert_eq!(question.qclass, QClass::IN);
        assert_eq!(rest, b"\x2A");

        assert_eq!(<Question<&Name>>::parse_bytes(bytes), Err(ParseError));
        assert!(<Question<&Name>>::parse_bytes(&bytes[..9]).is_ok());

        let mut buffer = [0u8; 9];
        assert_eq!(
            question.build_bytes(&mut buffer),
            Ok(&mut [] as &mut [u8])
        );
        assert_eq!(buffer, &bytes[..9]);
    }
}
