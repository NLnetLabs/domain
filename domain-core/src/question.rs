//! A single question in a DNS message.
//!
//! This module defines the type `Question` which represents an entry in
//! the question section of a DNS message.

use std::fmt;
use bytes::BufMut;
use crate::iana::{Class, Rtype};
use crate::compose::{Compose, Compress, Compressor};
use crate::name::ToDname;
use crate::parse::{Parse, Parser, ShortBuf};


//------------ Question ------------------------------------------------------

/// A question in a DNS message.
///
/// In DNS, a question describes what is requested in a query. It consists
/// of three elements: a domain name, a record type, and a class. This type
/// such a question.
///
/// Questions are generic over the domain name type. When read from an
/// actual message, a [`ParsedDname`] has to be used because the name part
/// may be compressed.
///
/// In order to allow questions on the fly, in particular when creating 
/// messages via [`MessageBuilder`], the `From` trait is implemented for
/// tuples of all three elements of a question as well as for only name
/// and record type assuming `Class::In` which is likely what you want,
/// anyway.
///
/// [`ParsedDname`]: ../name/struct.ParsedDname.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Question<N: ToDname> {
    /// The domain name of the question.
    qname: N,

    /// The record type of the question.
    qtype: Rtype,

    /// The class of the quesiton.
    qclass: Class,
}

/// # Creation and Conversion
///
impl<N: ToDname> Question<N> {
    /// Creates a new question from its three componets.
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question { qname, qtype, qclass }
    }

    /// Creates a new question from a name and record type, assuming class IN.
    pub fn new_in(qname: N, qtype: Rtype) -> Self {
        Question { qname, qtype, qclass: Class::In }
    }
}


/// # Field Access
///
impl<N: ToDname> Question<N> {
    /// Returns a reference to the domain nmae in the question,
    pub fn qname(&self) -> &N {
        &self.qname
    }

    /// Returns the record type of the question.
    pub fn qtype(&self) -> Rtype {
        self.qtype
    }

    /// Returns the class of the question.
    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


//--- From

impl<N: ToDname> From<(N, Rtype, Class)> for Question<N> {
    fn from((name, rtype, class): (N, Rtype, Class)) -> Self {
        Question::new(name, rtype, class)
    }
}

impl<N: ToDname> From<(N, Rtype)> for Question<N> {
    fn from((name, rtype): (N, Rtype)) -> Self {
        Question::new(name, rtype, Class::In)
    }
}


//--- Parse, Compose, and Compress

impl<N: ToDname + Parse> Parse for Question<N> {
    type Err = <N as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Question::new(
            N::parse(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?
        ))
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        N::skip(parser)?;
        Rtype::skip(parser)?;
        Class::skip(parser)?;
        Ok(())
    }
}

impl<N: ToDname> Compose for Question<N> {
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

impl<N: ToDname> Compress for Question<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        self.qname.compress(buf)?;
        buf.compose(&self.qtype)?;
        buf.compose(&self.qclass)
    }
}


//--- Display

impl<N: ToDname + fmt::Display> fmt::Display for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.\t{}\t{}", self.qname, self.qtype, self.qclass)
    }
}

