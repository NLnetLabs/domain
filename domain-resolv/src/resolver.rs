//! The trait defining an abstract resolver.

use std::io;
use std::net::IpAddr;
use domain_core::name::{Dname, ToDname, ToRelativeDname};
use domain_core::message::Message;
use domain_core::question::Question;
use futures::future::Future;
use crate::lookup::{addr, host, srv};


//----------- Resolver -------------------------------------------------------

/// A type that acts as a DNS resolver.
///
/// A resolver is anything that tries to answer questions using the DNS. The
/// `query` method takes a single question and returns a future that will
/// eventually resolve into either an answer or an IO error.
pub trait Resolver {
    /// The answer returned by a query.
    ///
    /// This isn’t `Message` directly as it may be useful for the resolver
    /// to provide additional information. For instance, a validating
    /// resolver (a resolver that checks whether DNSSEC signatures are
    /// correct) can supply more information as to why validation failed.
    type Answer: AsRef<Message>;

    /// The future resolving into an answer.
    type Query: Future<Item=Self::Answer, Error=io::Error>;

    /// Returns a future answering a question.
    ///
    /// The method takes anything that can be converted into a question and
    /// produces a future trying to answer the question.
    fn query<N, Q>(&self, question: Q) -> Self::Query
    where N: ToDname, Q: Into<Question<N>>;

    fn lookup_addr(&self, addr: IpAddr) -> addr::LookupAddr<Self>
    where Self: Sized {
        addr::lookup_addr(self, addr)
    }

    fn lookup_host<N: ToDname>(&self, name: &N) -> host::LookupHost<Self>
    where Self: Sized {
        host::lookup_host(self, name)
    }

    fn search_host<N>(self, name: N) -> host::SearchHost<Self, N>
    where Self: Sized + SearchNames, N: ToRelativeDname {
        host::search_host(self, name)
    }

    fn lookup_srv<S, N>(
        self, service: S, name: N, fallback_port: u16
    ) -> srv::LookupSrv<Self, S, N>
    where
        Self: Sized,
        S: ToRelativeDname + Clone + Send + 'static,
        N: ToDname + Send + 'static
    {
        srv::lookup_srv(self, service, name, fallback_port)
    }
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
    type Iter: Iterator<Item=Dname>;

    /// Returns an iterator over the search suffixes.
    fn search_iter(&self) -> Self::Iter;
}
