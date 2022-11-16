//! A single question in a DNS message.
//!
//! This module defines the type `Question` which represents an entry in
//! the question section of a DNS message and the `AsQuestion` trait for
//! producing questions on the fly.

use super::cmp::CanonicalOrd;
use super::iana::{Class, Rtype};
use super::name::{ParsedDname, ToDname};
use super::octets::{
    Compose, Octets, OctetsBuilder, OctetsFrom, Parse, ParseError, Parser,
    ShortBuf,
};
use core::cmp::Ordering;
use core::{fmt, hash};

//------------ Question ------------------------------------------------------

/// A question in a DNS message.
///
/// In DNS, a question describes what is requested in a query. It consists
/// of three elements: a domain name, a record type, and a class. This type
/// represents such a question.
///
/// Questions are generic over the domain name type. When read from an
/// actual message, a [`ParsedDname`] has to be used because the name part
/// may be compressed.
///
/// [`ParsedDname`]: ../name/struct.ParsedDname.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
#[derive(Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
impl<N> Question<N> {
    /// Creates a new question from its three componets.
    pub fn new(qname: N, qtype: Rtype, qclass: Class) -> Self {
        Question {
            qname,
            qtype,
            qclass,
        }
    }

    /// Creates a new question from a name and record type, assuming class IN.
    pub fn new_in(qname: N, qtype: Rtype) -> Self {
        Question {
            qname,
            qtype,
            qclass: Class::In,
        }
    }

    /// Converts the question into the qname.
    pub fn into_qname(self) -> N {
        self.qname
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

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Question<SrcName>> for Question<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(
        source: Question<SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(Question::new(
            Name::try_octets_from(source.qname)?,
            source.qtype,
            source.qclass,
        ))
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Question<NN>> for Question<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Question<NN>) -> bool {
        self.qname.name_eq(&other.qname)
            && self.qtype == other.qtype
            && self.qclass == other.qclass
    }
}

impl<N: ToDname> Eq for Question<N> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<N, NN> PartialOrd<Question<NN>> for Question<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Question<NN>) -> Option<Ordering> {
        match self.qname.name_cmp(&other.qname) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match self.qtype.partial_cmp(&other.qtype) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.qclass.partial_cmp(&other.qclass)
    }
}

impl<N, NN> CanonicalOrd<Question<NN>> for Question<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn canonical_cmp(&self, other: &Question<NN>) -> Ordering {
        match self.qname.lowercase_composed_cmp(&other.qname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.qtype.cmp(&other.qtype) {
            Ordering::Equal => {}
            other => return other,
        }
        self.qclass.cmp(&other.qclass)
    }
}

impl<N: ToDname> Ord for Question<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.qname.name_cmp(&other.qname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.qtype.cmp(&other.qtype) {
            Ordering::Equal => {}
            other => return other,
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

impl<'a, Octs: Octets> Parse<'a, Octs> for Question<ParsedDname<'a, Octs>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        Ok(Question::new(
            ParsedDname::parse(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        ParsedDname::skip(parser)?;
        Rtype::skip(parser)?;
        Class::skip(parser)?;
        Ok(())
    }
}

impl<N: ToDname> Compose for Question<N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            target.append_compressed_dname(&self.qname)?;
            self.qtype.compose(target)?;
            self.qclass.compose(target)
        })
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.qname.compose_canonical(target)?;
            self.qtype.compose_canonical(target)?;
            self.qclass.compose_canonical(target)
        })
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

//------------ AsQuestion ----------------------------------------------------

/// A helper trait allowing construction of questions on the fly.
///
/// The trait’s primary user is the [`QuestionBuilder`] type of the message
/// builder system. It’s [`push`] method accepts anything that implements
/// this trait.
///
/// Implementations are provided for [`Question`] values and references. In
/// addition, a tuple of a domain name, record type and class can be used as
/// this trait, saving the detour of constructing a question first. Since
/// the class is pretty much always `Class::In`, a tuple of just a domain
/// name and record type works as well by assuming that class.
///
/// [`Class::In`]: ../iana/class/enum.Class.html#variant.In
/// [`Question`]: struct.Question.html
/// [`QuestionBuilder`]: ../message_builder/struct.QuestionBuilder.html
/// [`push`]: ../message_builder/struct.QuestionBuilder.html#method.push
pub trait AsQuestion {
    /// The domain name used by the qname.
    type Name: ToDname;

    /// Returns a reference to the qname of the question.
    fn qname(&self) -> &Self::Name;

    /// Returns the record type of the question.
    fn qtype(&self) -> Rtype;

    /// Returns the class of the question.
    fn qclass(&self) -> Class;

    /// Produces the encoding of the question.
    fn compose_question<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf>
    where
        Self::Name: Compose,
    {
        target.append_all(|target| {
            target.append_compressed_dname(self.qname())?;
            self.qtype().compose(target)?;
            self.qclass().compose(target)
        })
    }

    /// Produces the canoncial encoding of the question.
    fn compose_question_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf>
    where
        Self::Name: Compose,
    {
        target.append_all(|target| {
            self.qname().compose_canonical(target)?;
            self.qtype().compose_canonical(target)?;
            self.qclass().compose_canonical(target)
        })
    }
}

impl<'a, T: AsQuestion> AsQuestion for &'a T {
    type Name = T::Name;

    fn qname(&self) -> &Self::Name {
        (*self).qname()
    }

    fn qtype(&self) -> Rtype {
        (*self).qtype()
    }

    fn qclass(&self) -> Class {
        (*self).qclass()
    }
}

impl<Name: ToDname> AsQuestion for Question<Name> {
    type Name = Name;

    fn qname(&self) -> &Self::Name {
        Self::qname(self)
    }

    fn qtype(&self) -> Rtype {
        Self::qtype(self)
    }

    fn qclass(&self) -> Class {
        Self::qclass(self)
    }
}

impl<Name: ToDname> AsQuestion for (Name, Rtype, Class) {
    type Name = Name;

    fn qname(&self) -> &Self::Name {
        &self.0
    }
    fn qtype(&self) -> Rtype {
        self.1
    }
    fn qclass(&self) -> Class {
        self.2
    }
}

impl<Name: ToDname> AsQuestion for (Name, Rtype) {
    type Name = Name;

    fn qname(&self) -> &Self::Name {
        &self.0
    }
    fn qtype(&self) -> Rtype {
        self.1
    }
    fn qclass(&self) -> Class {
        Class::In
    }
}
