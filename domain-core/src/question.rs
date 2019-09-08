//! A single question in a DNS message.
//!
//! This module defines the type `Question` which represents an entry in
//! the question section of a DNS message.

use core::{fmt, hash};
use core::cmp::Ordering;
use crate::cmp::CanonicalOrd;
use crate::iana::{Class, Rtype};
use crate::compose::{Compose, ComposeTarget};
use crate::name::ToDname;
use crate::parse::{Parse, Parser};


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
#[derive(Clone, Copy)]
pub struct Question<N> {
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


//--- PartialEq and Eq

impl<N, NN> PartialEq<Question<NN>> for Question<N>
where N: ToDname, NN: ToDname {
    fn eq(&self, other: &Question<NN>) -> bool {
        self.qname.name_eq(&other.qname)
        && self.qtype == other.qtype
        && self.qclass == other.qclass
    }
}

impl<N: ToDname> Eq for Question<N> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<N, NN> PartialOrd<Question<NN>> for Question<N>
where N: ToDname, NN: ToDname {
    fn partial_cmp(&self, other: &Question<NN>) -> Option<Ordering> {
        match self.qname.name_cmp(&other.qname) {
            Ordering::Equal => { }
            other => return Some(other)
        }
        match self.qtype.partial_cmp(&other.qtype) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        self.qclass.partial_cmp(&other.qclass)
    }
}

impl<N, NN> CanonicalOrd<Question<NN>> for Question<N>
where N: ToDname, NN: ToDname {
    fn canonical_cmp(&self, other: &Question<NN>) -> Ordering {
        match self.qname.lowercase_composed_cmp(&other.qname) {
            Ordering::Equal => { }
            other => return other
        }
        match self.qtype.cmp(&other.qtype) {
            Ordering::Equal => { }
            other => return other
        }
        self.qclass.cmp(&other.qclass)
    }
}

impl<N: ToDname> Ord for Question<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.qname.name_cmp(&other.qname) {
            Ordering::Equal => { }
            other => return other
        }
        match self.qtype.cmp(&other.qtype) {
            Ordering::Equal => { }
            other => return other
        }
        self.qclass.cmp(&other.qclass)
    }
}


//--- Hash

impl<N: hash::Hash> hash::Hash for Question<N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.qname.hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
    }
}


//--- Parse and Compose

impl<Octets, N> Parse<Octets> for Question<N>
where Octets: AsRef<[u8]>, N: ToDname + Parse<Octets>  {
    type Err = <N as Parse<Octets>>::Err;

    fn parse(parser: &mut Parser<Octets>) -> Result<Self, Self::Err> {
        Ok(Question::new(
            N::parse(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?
        ))
    }

    fn skip(parser: &mut Parser<Octets>) -> Result<(), Self::Err> {
        N::skip(parser)?;
        Rtype::skip(parser)?;
        Class::skip(parser)?;
        Ok(())
    }
}

impl<N: ToDname> Compose for Question<N> {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        self.qname.compose(target);
        self.qtype.compose(target);
        self.qclass.compose(target);
    }
}


//--- Display and Debug

impl<N: fmt::Display> fmt::Display for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.\t{}\t{}", self.qname, self.qtype, self.qclass)
    }
}

impl<N: fmt::Debug> fmt::Debug for Question<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Question")
            .field("qname", &self.qname)
            .field("qtype", &self.qtype)
            .field("qclass", &self.qclass)
            .finish()
    }
}

