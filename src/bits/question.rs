use bytes::BufMut;
use ::iana::{Class, Rtype};
use super::compose::{Composable, Compressable, Compressor};
use super::error::ShortBuf;
use super::name::{ParsedDname, ParsedDnameError};
use super::parse::{Parseable, Parser};


//------------ Question ------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Question<N=ParsedDname> {
    qname: N,
    qtype: Rtype,
    qclass: Class,
}

/// # Creation and Conversion
///
impl<N> Question<N> {
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question { qname, qtype, qclass }
    }

    pub fn new_in(qname: N, qtype: Rtype) -> Self {
        Question { qname, qtype, qclass: Class::In }
    }
}


/// # Field Access
///
impl<N> Question<N> {
    pub fn qname(&self) -> &N {
        &self.qname
    }

    pub fn qtype(&self) -> Rtype {
        self.qtype
    }

    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


//--- Parseable, Composable, and Compressable

impl<N: Parseable> Parseable for Question<N> {
    type Err = QuestionParseError<N::Err>;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Question::new(
            N::parse(parser).map_err(QuestionParseError::Name)?,
            Rtype::parse(parser)
                  .map_err(|_| QuestionParseError::ShortBuf)?,
            Class::parse(parser)
                  .map_err(|_| QuestionParseError::ShortBuf)?
        ))
    }
}

impl<N: Composable> Composable for Question<N> {
    fn compose_len(&self) -> usize {
        self.qname.compose_len() + self.qtype.compose_len()
            + self.qclass.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.qname.compose(buf);
        self.qtype.compose(buf);
        self.qclass.compose(buf);
    }
}

impl<N: Compressable> Compressable for Question<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.qname.compress(buf)?;
        buf.compose(&self.qtype)?;
        buf.compose(&self.qclass)
    }
}


//------------ ParseQuestionError -------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuestionParseError<N=ParsedDnameError> {
    Name(N),
    ShortBuf,
}

