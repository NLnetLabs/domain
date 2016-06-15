//! A single question of a DNS message.
//!
//! This module defines the type `Question` which represents an element in
//! the question section of a DNS message.

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::iana::{Class, RRType};
use super::name::{AsDName, DName};
use super::parse::ParseBytes;


//------------ Question -----------------------------------------------------

/// A question in a DNS message.
///
/// In DNS, a query is determined by three elements: a domain name, a record
/// type, and a class, collectively called a question. This type represents
/// such a question.
///
/// Questions can be parsed out of existing messages. The `Message` class
/// allows for iterating over all the quesitons in a message, returning
/// values of the `Question` type.
///
/// When constructing a message via the `MessageBuilder` class, you can either
/// pass in `Question` references or use the associated functions
/// `Question::push()` or `Question::push_in()` to construct the questions
/// on the fly from their components.
#[derive(Clone, Debug)]
pub struct Question<'a> {
    /// The domain name of the question.
    qname: DName<'a>,

    /// The record type of the question.
    qtype: RRType,

    /// The class of the quesiton.
    qclass: Class,
}

/// # Creation and Conversion
///
impl<'a> Question<'a> {
    /// Creates a new question from its constituent elements.
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


/// # Parsing and Composing
///
impl<'a> Question<'a> {
    /// Parses a question from the beginning of a parser.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        Ok(Question::new(try!(parser.parse_dname()),
                         try!(parser.parse_u16()).into(),
                         try!(parser.parse_u16()).into()))
    }

    /// Pushes a question to the end of a compose target.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        try!(target.push_dname_compressed(&self.qname));
        try!(target.push_u16(self.qtype.into()));
        target.push_u16(self.qclass.into())
    }

    /// Builds a question from its components and pushes it to a target.
    ///
    /// This associate function can be used to streamline message creation.
    /// Instead of first creating a question from its parts, you can push
    /// them to the message directly. In order to allow the message builder
    /// to increase the quesiton counter once pushing is done, this happens
    /// through the `QuestionTarget` trait which `MessageBuilder` implements.
    pub fn push<C, T, N>(target: &mut T, qname: &N, qtype: RRType,
                         qclass: Class) -> ComposeResult<()>
                where C: ComposeBytes, T: QuestionTarget<C>, N: AsDName {
        target.compose(|target| {
            try!(target.push_dname_compressed(qname));
            try!(target.push_u16(qtype.into()));
            target.push_u16(qclass.into())
        })
    }

    /// Builds a question in IN class and pushes it to a target.
    ///
    /// This is the same as `Question::push()` with `Class::IN` as this is
    /// the most common class.
    pub fn push_in<C, T, N>(target: &mut T, qname: &N, qtype: RRType)
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

/// A helper trait for `Question::push()`
pub trait QuestionTarget<C: ComposeBytes> {
    /// Acquires a composition target for pushing a question to.
    ///
    /// The actual composing of the question happens inside the closure
    /// `push`. The implementor can assume `push` to have built exactly
    /// one question if it returns `Ok(())`.
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()>;
}

