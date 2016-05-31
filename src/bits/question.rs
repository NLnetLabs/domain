//! A single question of a DNS message.

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
//use super::flavor::{self, Flavor, FlatFlavor};
use super::iana::{Class, RRType};
use super::name::{AsDName, DName};
use super::parse::ParseBytes;


//------------ Question -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Question<'a> {
    qname: DName<'a>,
    qtype: RRType,
    qclass: Class,
}

/// # Creation and Conversion
///
impl<'a> Question<'a> {
    pub fn new(qname: DName<'a>, qtype: RRType, qclass: Class) -> Self {
        Question { qname: qname, qtype: qtype, qclass: qclass }
    }
}


/// # Element Access
///
impl<'a> Question<'a> {
    /// Returns the requested domain name.
    pub fn qname(&self) -> &DName<'a> {
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
impl<'a> Question<'a> {
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Question::new(try!(parser.parse_dname()),
                         try!(parser.parse_u16()).into(),
                         try!(parser.parse_u16()).into()))
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        try!(target.push_dname_compressed(&self.qname));
        try!(target.push_u16(self.qtype.into()));
        target.push_u16(self.qclass.into())
    }

    pub fn push<C, T, N>(target: &mut T, qname: N, qtype: RRType,
                         qclass: Class) -> ComposeResult<()>
                where C: ComposeBytes, T: QuestionTarget<C>, N: AsDName {
        target.compose(|target| {
            try!(target.push_dname_compressed(&qname.as_dname()));
            try!(target.push_u16(qtype.into()));
            target.push_u16(qclass.into())
        })
    }

    pub fn push_in<C, T, N>(target: &mut T, qname: N, qtype: RRType)
                            -> ComposeResult<()>
                where C: ComposeBytes, T: QuestionTarget<C>, N: AsDName {
        Question::push(target, qname, qtype, Class::IN)
    }
}


//--- PartialEq

impl<'a, 'b> PartialEq<Question<'b>> for Question<'a> {
    fn eq(&self, other: &Question<'b>) -> bool {
        self.qname == other.qname && self.qtype == other.qtype
             && self.qclass == other.qclass
    }
}


//--- Display

impl<'a> fmt::Display for Question<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) ->  fmt::Result {
        write!(f, "{}\t{}\t{}", self.qname, self.qtype, self.qclass)
    }
}


//------------ QuestionTarget -----------------------------------------------

pub trait QuestionTarget<C: ComposeBytes> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()>;
}


/*
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

impl<'a, D: DName> ComposeQuestion for (&'a D, RRType) {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        try!(target.push_dname_compressed(self.0));
        try!(target.push_u16(self.1.into()));
        target.push_u16(Class::IN.into())
    }
}
*/
