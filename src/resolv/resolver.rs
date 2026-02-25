//! The trait defining an abstract resolver.

use crate::base::message::Message;
use crate::base::name::ToName;
use crate::base::question::Question;
use std::future::Future;
use std::io;

//----------- Resolver -------------------------------------------------------

/// A type that acts as a DNS resolver.
///
/// A resolver is anything that tries to answer questions using the DNS. The
/// [`query`] method takes a single question and returns a future that will
/// eventually resolve into either an answer or an IO error.
///
/// [`query`]: Resolver::query
pub trait Resolver {
    type Octets: AsRef<[u8]>;

    /// The answer returned by a query.
    ///
    /// This isn’t [`Message`] directly as it may be useful for the resolver
    /// to provide additional information. For instance, a validating
    /// resolver (a resolver that checks whether DNSSEC signatures are
    /// correct) can supply more information as to why validation failed.
    type Answer: AsRef<Message<Self::Octets>>;

    /// The future resolving into an answer.
    type Query<'a>: Future<Output = Result<Self::Answer, io::Error>> + Send
    where
        Self: 'a;

    /// Returns a future answering a question.
    ///
    /// The method takes anything that can be converted into a question and
    /// produces a future trying to answer the question.
    fn query<'a, N, Q>(&'a self, question: Q) -> Self::Query<'a>
    where
        N: ToName,
        Q: Into<Question<N>>;
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
    type Name: ToName;
    type Iter<'a>: Iterator<Item = Self::Name>
    where
        Self: 'a;

    /// Returns an iterator over the search suffixes.
    fn search_iter<'a>(&'a self) -> Self::Iter<'a>;
}
