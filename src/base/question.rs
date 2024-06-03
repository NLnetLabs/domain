//! A single question in a DNS message.
//!
//! This module defines the type `Question` which represents an entry in
//! the question section of a DNS message and the `ComposeQuestion` trait for
//! producing questions on the fly.

use super::cmp::CanonicalOrd;
use super::iana::{Class, Rtype};
use super::name;
use super::name::{ParsedName, ToName};
use super::wire::{Composer, ParseError};
use core::cmp::Ordering;
use core::str::FromStr;
use core::{fmt, hash};
use octseq::builder::ShortBuf;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;

//------------ Question ------------------------------------------------------

/// A question in a DNS message.
///
/// In DNS, a question describes what is requested in a query. It consists
/// of three elements: a domain name, a record type, and a class. This type
/// represents such a question.
///
/// Questions are generic over the domain name type. When read from an
/// actual message, a [`ParsedName`] has to be used because the name part
/// may be compressed.
///
/// [`ParsedName`]: ../name/struct.ParsedName.html
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
            qclass: Class::IN,
        }
    }

    /// Converts the question into the qname.
    pub fn into_qname(self) -> N {
        self.qname
    }
}

/// # Field Access
///
impl<N: ToName> Question<N> {
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

/// # Parsing and Composing
///
impl<Octs> Question<ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Question::new(
            ParsedName::parse(parser)?,
            Rtype::parse(parser)?,
            Class::parse(parser)?,
        ))
    }
}

impl<N: ToName> Question<N> {
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_compressed_name(&self.qname)?;
        self.qtype.compose(target)?;
        self.qclass.compose(target)
    }
}

//--- From and FromStr

impl<N: ToName> From<(N, Rtype, Class)> for Question<N> {
    fn from((name, rtype, class): (N, Rtype, Class)) -> Self {
        Question::new(name, rtype, class)
    }
}

impl<N: ToName> From<(N, Rtype)> for Question<N> {
    fn from((name, rtype): (N, Rtype)) -> Self {
        Question::new(name, rtype, Class::IN)
    }
}

impl<N: FromStr<Err = name::FromStrError>> FromStr for Question<N> {
    type Err = FromStrError;

    /// Parses a question from a string.
    ///
    /// The string should contain a question as the query name, class, and
    /// query type separated by white space. The query name should be first
    /// and in the same form as `Name::from_str` requires. The class and
    /// query type follow the name in either order. If the class is left out,
    /// it is assumed to be IN.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split_whitespace();

        let qname = match s.next() {
            Some(qname) => qname,
            None => return Err(PresentationErrorEnum::MissingQname.into()),
        };
        let qname = N::from_str(qname)?;
        let class_or_qtype = match s.next() {
            Some(value) => value,
            None => {
                return Err(PresentationErrorEnum::MissingClassAndQtype.into())
            }
        };
        let res = match Class::from_str(class_or_qtype) {
            Ok(class) => {
                let qtype = match s.next() {
                    Some(qtype) => qtype,
                    None => {
                        return Err(PresentationErrorEnum::MissingQtype.into())
                    }
                };
                match Rtype::from_str(qtype) {
                    Ok(qtype) => Self::new(qname, qtype, class),
                    Err(_) => {
                        return Err(PresentationErrorEnum::BadQtype.into())
                    }
                }
            }
            Err(_) => {
                let qtype = match Rtype::from_str(class_or_qtype) {
                    Ok(qtype) => qtype,
                    Err(_) => {
                        return Err(PresentationErrorEnum::BadQtype.into())
                    }
                };
                let class = match s.next() {
                    Some(class) => class,
                    None => return Ok(Self::new(qname, qtype, Class::IN)),
                };
                match Class::from_str(class) {
                    Ok(class) => Self::new(qname, qtype, class),
                    Err(_) => {
                        return Err(PresentationErrorEnum::BadClass.into())
                    }
                }
            }
        };
        if s.next().is_some() {
            return Err(PresentationErrorEnum::TrailingData.into());
        }
        Ok(res)
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
    N: ToName,
    NN: ToName,
{
    fn eq(&self, other: &Question<NN>) -> bool {
        self.qname.name_eq(&other.qname)
            && self.qtype == other.qtype
            && self.qclass == other.qclass
    }
}

impl<N: ToName> Eq for Question<N> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<N, NN> PartialOrd<Question<NN>> for Question<N>
where
    N: ToName,
    NN: ToName,
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
    N: ToName,
    NN: ToName,
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

impl<N: ToName> Ord for Question<N> {
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

//------------ ComposeQuestion -----------------------------------------------

/// A helper trait allowing construction of questions on the fly.
///
/// The trait’s primary user is the [`QuestionBuilder`] type of the message
/// builder system. It’s [`push`] method accepts anything that implements
/// this trait.
///
/// Implementations are provided for [`Question`] values and references. In
/// addition, a tuple of a domain name, record type and class can be used as
/// this trait, saving the detour of constructing a question first. Since
/// the class is pretty much always [`Class::IN`], a tuple of just a domain
/// name and record type works as well by assuming that class.
///
/// [`QuestionBuilder`]: super::message_builder::QuestionBuilder
/// [`push`]: super::message_builder::QuestionBuilder::push
pub trait ComposeQuestion {
    fn compose_question<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

impl<'a, Q: ComposeQuestion> ComposeQuestion for &'a Q {
    fn compose_question<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        (*self).compose_question(target)
    }
}

impl<Name: ToName> ComposeQuestion for Question<Name> {
    fn compose_question<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose(target)
    }
}

impl<Name: ToName> ComposeQuestion for (Name, Rtype, Class) {
    fn compose_question<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Question::new(&self.0, self.1, self.2).compose(target)
    }
}

impl<Name: ToName> ComposeQuestion for (Name, Rtype) {
    fn compose_question<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        Question::new(&self.0, self.1, Class::IN).compose(target)
    }
}

//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FromStrError {
    /// The string content was wrongly formatted.
    Presentation(PresentationError),

    /// The buffer is too short to contain the name.
    ShortBuf,
}

//--- From

impl From<name::FromStrError> for FromStrError {
    fn from(err: name::FromStrError) -> FromStrError {
        match err {
            name::FromStrError::Presentation(err) => {
                Self::Presentation(err.into())
            }
            name::FromStrError::ShortBuf => Self::ShortBuf,
        }
    }
}

impl From<PresentationErrorEnum> for FromStrError {
    fn from(err: PresentationErrorEnum) -> Self {
        Self::Presentation(err.into())
    }
}

//--- Display and Error

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FromStrError::Presentation(err) => err.fmt(f),
            FromStrError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {}

//------------ PresentationError ---------------------------------------------

/// An illegal presentation format was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationError(PresentationErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresentationErrorEnum {
    BadName(name::PresentationError),
    MissingQname,
    MissingClassAndQtype,
    MissingQtype,
    BadClass,
    BadQtype,
    TrailingData,
}

//--- From

impl From<PresentationErrorEnum> for PresentationError {
    fn from(err: PresentationErrorEnum) -> Self {
        Self(err)
    }
}

impl From<name::PresentationError> for PresentationError {
    fn from(err: name::PresentationError) -> Self {
        Self(PresentationErrorEnum::BadName(err))
    }
}

//--- Display and Error

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            PresentationErrorEnum::BadName(err) => err.fmt(f),
            PresentationErrorEnum::MissingQname => {
                f.write_str("missing qname")
            }
            PresentationErrorEnum::MissingClassAndQtype => {
                f.write_str("missing class and qtype")
            }
            PresentationErrorEnum::MissingQtype => {
                f.write_str("missing qtype")
            }
            PresentationErrorEnum::BadClass => f.write_str("invalid class"),
            PresentationErrorEnum::BadQtype => f.write_str("invalid qtype"),
            PresentationErrorEnum::TrailingData => {
                f.write_str("trailing data")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PresentationError {}
