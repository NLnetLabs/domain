//! A single question of a DNS message.

use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::flavor::{self, Flavor};
use super::iana::{Class, RRType};
use super::name::DName;
use super::parse::ParseFlavor;


//------------ Question -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Question<'a, F: Flavor<'a>> {
    qname: F::DName,
    qtype: RRType,
    qclass: Class,
}

pub type OwnedQuestion<'a> = Question<'a, flavor::Owned>;
pub type QuestionRef<'a> = Question<'a, flavor::Ref<'a>>;
pub type LazyQuestion<'a> = Question<'a, flavor::Lazy<'a>>;


/// # Creation and Conversion
///
impl<'a, F: Flavor<'a>> Question<'a, F> {
    pub fn new(qname: F::DName, qtype: RRType, qclass: Class) -> Self {
        Question { qname: qname, qtype: qtype, qclass: qclass }
    }
}


/// # Element Access
///
impl<'a, F: Flavor<'a>> Question<'a, F> {
    /// Returns the requested domain name.
    pub fn qname(&self) -> &F::DName {
        &self.qname
    }

    /// Returns the requested record type.
    pub fn qtype(&self) -> RRType {
        self.qtype
    }

    /// Returns the requested class.
    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


/// Parsing and Composing
///
impl<'a, F: Flavor<'a>> Question<'a, F> {
    pub fn parse<P>(parser: &mut P) -> ParseResult<Self>
                 where P: ParseFlavor<'a, F> {
        Ok(Question::new(try!(parser.parse_name()),
                         try!(parser.parse_u16()).into(),
                         try!(parser.parse_u16()).into()))
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        try!(target.push_dname_compressed(&self.qname));
        try!(target.push_u16(self.qtype.into()));
        target.push_u16(self.qclass.into())
    }
}


//------------ ComposeQuestion ----------------------------------------------

/// Helper trait to allow composing questions from tuples.
pub trait ComposeQuestion {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}

impl<'a, F: Flavor<'a>> ComposeQuestion for Question<'a, F> {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.compose(target)
    }
}

impl<D: DName> ComposeQuestion for (D, RRType, Class) {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_dname_compressed(&self.0));
        try!(target.push_u16(self.1.into()));
        target.push_u16(self.2.into())
    }
}
