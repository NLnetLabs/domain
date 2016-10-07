//! A single question for a DNS message.

use std::fmt;
use ::iana::{Class, Rtype};
use super::{Composer, ComposeResult, DName, PackedDName, Parser, ParseResult};


//------------ Question -----------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Question<N: DName> {
    /// The domain name of the question.
    qname: N,

    /// The record type of the question.
    qtype: Rtype,

    /// The class of the quesiton.
    qclass: Class,
}


/// # Creation and Conversion
///
impl<N: DName> Question<N> {
    /// Creates a new question from its constituent elements.
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question { qname: qname, qtype: qtype, qclass: qclass }
    }
}


/// # Element Access
///
impl<N: DName> Question<N> {
    /// Returns the requested domain name.
    pub fn qname(&self) -> &N {
        &self.qname
    }

    /// Returns the requested record type.
    pub fn qtype(&self) -> Rtype {
        self.qtype
    }

    /// Returns the requested class.
    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


/// # Parsing
///
impl<'a> Question<PackedDName<'a>> {
    /// Parses a question from the beginning of a parser.
    pub fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Question::new(try!(PackedDName::parse(parser)),
                         try!(Rtype::parse(parser)),
                         try!(Class::parse(parser))))
    }
}


/// # Composing
///
impl<N: DName> Question<N> {
    pub fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                       -> ComposeResult<()> {
        try!(self.qname.compose(composer.as_mut()));
        try!(self.qtype.compose(composer.as_mut()));
        self.qclass.compose(composer.as_mut())
    }
}


//--- From

impl<N: DName> From<(N, Rtype, Class)> for Question<N> {
    fn from(src: (N, Rtype, Class)) -> Self {
        Self::new(src.0, src.1, src.2)
    }
}

impl<N: DName> From<(N, Rtype)> for Question<N> {
    fn from(src: (N, Rtype)) -> Self {
        Self::new(src.0, src.1, Class::In)
    }
}


//--- Display

impl<N: DName> fmt::Display for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{} {} {}", self.qname, self.qtype, self.qclass)
    }
}

