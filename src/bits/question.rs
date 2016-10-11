//! A single question of a DNS message.
//!
//! This module defines the type `Question` which represents an entry in
//! the question section of a DNS message.

use std::fmt;
use ::iana::{Class, Rtype};
use super::{Composer, ComposeResult, DName, ParsedDName, Parser, ParseResult};


//------------ Question -----------------------------------------------------

/// A question in a DNS message.
///
/// In DNS, a query is determined by three elements: a domain name, a record
/// type, and a class, collectively called a question. This type represents
/// such a question.
///
/// Questions are generic over the domain name type. For a question with a
/// [`ParsedDName`], parsing is implemented. Composing, meanwhile, is
/// available with all domain name types.
///
/// In order to allow questions on the fly, in particular when creating 
/// messages via [`MessageBuilder`], the `From` trait is implemented for
/// tuples of all three elements of a question as well as for only name
/// and record type assuming `Class::In` which is likely what you want,
/// anyway.
///
/// [`ParsedDName`]: ../name/struct.ParsedDName.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
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
impl<'a> Question<ParsedDName<'a>> {
    /// Parses a question from the beginning of a parser.
    pub fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Question::new(try!(ParsedDName::parse(parser)),
                         try!(Rtype::parse(parser)),
                         try!(Class::parse(parser))))
    }
}


/// # Composing
///
impl<N: DName> Question<N> {
    /// Appends the question to a composition.
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

impl<N: DName + fmt::Display> fmt::Display for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{} {} {}", self.qname, self.qtype, self.qclass)
    }
}

impl<N: DName + fmt::Octal> fmt::Octal for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{:o} {} {}", self.qname, self.qtype, self.qclass)
    }
}

impl<N: DName + fmt::LowerHex> fmt::LowerHex for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{:x} {} {}", self.qname, self.qtype, self.qclass)
    }
}

impl<N: DName + fmt::UpperHex> fmt::UpperHex for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{:X} {} {}", self.qname, self.qtype, self.qclass)
    }
}

impl<N: DName + fmt::Binary> fmt::Binary for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{:b} {} {}", self.qname, self.qtype, self.qclass)
    }
}

