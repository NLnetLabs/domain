//! A single question of a DNS message.

use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::flavor::{self, Flavor, FlatFlavor};
use super::iana::{Class, RRType};
use super::name::DName;
use super::parse::ParseFlavor;


//------------ Question -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Question<F: Flavor> {
    qname: F::DName,
    qtype: RRType,
    qclass: Class,
}

pub type OwnedQuestion = Question<flavor::Owned>;
pub type QuestionRef<'a> = Question<flavor::Ref<'a>>;
pub type LazyQuestion<'a> = Question<flavor::Lazy<'a>>;


/// # Creation and Conversion
///
impl<F: Flavor> Question<F> {
    pub fn new(qname: F::DName, qtype: RRType, qclass: Class) -> Self {
        Question { qname: qname, qtype: qtype, qclass: qclass }
    }
}


/// # Element Access
///
impl<F: Flavor> Question<F> {
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
impl<'a, F: FlatFlavor<'a>> Question<F> {
    pub fn parse<P>(parser: &mut P) -> ParseResult<Self>
                 where P: ParseFlavor<'a, F> {
        Ok(Question::new(try!(parser.parse_name()),
                         try!(parser.parse_u16()).into(),
                         try!(parser.parse_u16()).into()))
    }
}

impl<F: Flavor> Question<F> {
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

impl<F: Flavor> ComposeQuestion for Question<F> {
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
