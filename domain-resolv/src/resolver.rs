//! The trait defining an abstract resolver.

use std::{error, fmt, io};
use futures::future::Future;
use domain::base::name::ToDname;
use domain::base::message::Message;
use domain::base::question::Question;


//----------- Resolver -------------------------------------------------------

/// A type that acts as a DNS resolver.
///
/// A resolver is anything that tries to answer questions using the DNS. The
/// `query` method takes a single question and returns a future that will
/// eventually resolve into either an answer or an IO error.
pub trait Resolver {
    type Octets: AsRef<[u8]>;

    /// The answer returned by a query.
    ///
    /// This isn’t `Message` directly as it may be useful for the resolver
    /// to provide additional information. For instance, a validating
    /// resolver (a resolver that checks whether DNSSEC signatures are
    /// correct) can supply more information as to why validation failed.
    type Answer: AsRef<Message<Self::Octets>>;

    /// The future resolving into an answer.
    type Query: Future<Output = Result<Self::Answer, Error>>;

    /// Returns a future answering a question.
    ///
    /// The method takes anything that can be converted into a question and
    /// produces a future trying to answer the question.
    fn query<N, Q>(&self, question: Q) -> Self::Query
    where N: ToDname, Q: Into<Question<N>>;
}


//------------ SearchNames ---------------------------------------------------

/// A type that can produce a list of name suffixes.
///
/// Legacy systems have the ability to interpret relative domain names as
/// within the local system. They provide a list of suffixes that can be
/// attached to the name to make it absolute.
///
/// A search resolver is a resolver that provides such a list. This is
/// implemented via an iterator over domain names.
pub trait SearchNames {
    type Name: ToDname;
    type Iter: Iterator<Item = Self::Name>;

    /// Returns an iterator over the search suffixes.
    fn search_iter(&self) -> Self::Iter;
}


//------------ Error ---------------------------------------------------------

/// A resolver query failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    ServFail,
    Io(io::Error)
}

impl Error {
    pub fn is_timeout(&self) -> bool {
        match *self {
            Error::Io(ref err) => err.kind() == io::ErrorKind::TimedOut,
            _ => false
        }
    }
}

impl From<io::Error> for Error {
    fn from (err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::ServFail => write!(f, "server failure"),
            Error::Io(ref err) => err.fmt(f)
        }
    }
}

impl error::Error for Error { }
