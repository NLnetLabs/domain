//! An asynchronous stub resolver.
//!
//! A resolver is the component in the DNS that answers queries. A stub
//! resolver does so by simply relaying queries to a different resolver
//! chosen from a predefined set. This is how pretty much all user
//! applications use DNS.
//!
//! This module implements a modern, asynchronous stub resolver built on
//! top of [tokio-core].
//!
//! The module provides ways to create a *resolver* that knows how to
//! process DNS *queries*. A query asks for all the resource records
//! associated with a given triple of a domain name, resource record type,
//! and class (known as a *question*). It is a future resolving to a DNS
//! message with the response or an error. Queries can be combined into
//! *lookups* that use the returned resource records to answer more
//! specific enquiries such as all the IP addresses associated with a given
//! host name. The module provides a rich set of common lookups in the
//! [lookup] sub-module.
//!
//! The following gives an introduction into using the resolver. For an
//! introduction into the internal design, please have a look at the [intro]
//! sub-module.
//!
//!
//! # Creating a Resolver
//!
//! The resolver is represented by the [`Resolver`] type. When creating a
//! value of this type, you create all the parts of an actual resolver
//! according to a resolver configuration. Since these parts are handling
//! actual network traffic, the resolver needs a handle to a Tokio reactor
//! into which these parts will be spawned as futures.
//!
//! For the resolver configuration, there’s [`ResolvConf`]. While you can
//! create a value of this type by hand, the more common way is to use your
//! system’s resolver configuration. [`ResolvConf`] implements the `Default`
//! trait doing exactly that by reading `/etc/resolv.conf`.
//!
//! > That probably won’t work on Windows, but, sadly, I have no idea how to
//! > retrieve the resolver configuration there. Some help here would be
//! > very much appreciated.
//!
//! Since using the system configuration is the most common case by far,
//! [`Resolver`]’s `new()` function does just that. So, the easiest way to
//! get a resolver is just this:
//!
//! ```
//! # extern crate domain;
//! # extern crate tokio_core;
//! use domain::resolv::Resolver;
//! use tokio_core::reactor::Core;
//!
//! # fn main() {
//! let core = Core::new().unwrap();
//! let resolv = Resolver::new(&core.handle()).unwrap();
//! # }
//! ```
//!
//! If you do have a configuration, you can use the `from_conf()` function
//! instead.
//!
//!
//! # Using the Resolver: Queries
//!
//! As was mentioned above, the [`Resolver`] doesn’t actually contain the
//! networking parts necessary to answer queries. Instead, it only knows how
//! to contact those parts. Because of this, you can clone the resolver,
//! even pass it to other threads.
//!
//! Oddly, the one thing you can’t do with a resolver is start a query.
//! Instead, you need an intermediary type called [`ResolverTask`]. You’ll
//! get one through [`Resolver::start()`] or, more correctly, you get a future
//! to one through this method. You then chain on your actual query or
//! sequence of queries using combinators such as `Future::and_then()`.
//!
//! The actual query is started through [`ResolverTask::query()`]. It takes a
//! domain name, a resource record type, and a class and returns a future
//! that will resolve into either a [`MessageBuf`] with the response to the
//! query or an [`Error`].
//!
//! As an example, let’s find out the IPv6 addresses for `www.rust-lang.org`:
//!
//! ```
//! extern crate domain;
//! extern crate futures;
//! extern crate tokio_core;
//!
//! use std::str::FromStr;
//! use domain::bits::DNameBuf;
//! use domain::iana::{Class, Rtype};
//! use domain::rdata::Aaaa;
//! use domain::resolv::Resolver;
//! use futures::Future;
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!     let resolv = Resolver::new(&core.handle()).unwrap();
//!
//!     let addrs = resolv.start().and_then(|resolv| {
//!         let name = DNameBuf::from_str("www.rust-lang.org.").unwrap();
//!         resolv.query(name, Rtype::Aaaa, Class::In)
//!     });
//!     let response = core.run(addrs).unwrap();
//!     for record in response.answer().unwrap().limit_to::<Aaaa>() {
//!         println!("{}", record.unwrap());
//!     }
//! }
//! ```
//!
//! Note the final dot at `"www.rust-lang.org."` making it an absolute domain
//! name. Queries don’t know how to deal with relative names and will error
//! out if given one.
//!
//!
//! # Complex Queries: Lookups
//!
//! Most times when you are using DNS you aren’t really interested in a
//! bunch of resource records, though, you want an answer to a more direct
//! question. For instance, if you want to know the IP addresses for a
//! host name, you don’t really care that you have to make a query for the
//! `A` records and one for `AAAA` records for that host name. You want the
//! addresses.
//!
//! This is what lookups do. They take a [`ResolverTask`] and some additional
//! information and turn that into a future of some specific result. So,
//! to do lookups you have to follow the procedure using `start()` as given
//! above but instead of calling `query()` inside the closure, you use one
//! of the lookup functions from the [lookup] sub-module.
//!
//! Using [`lookup_host()`], the process of looking up the IP addresses
//! becomes much easier. To update above’s example:
//!
//! ```
//! extern crate domain;
//! extern crate futures;
//! extern crate tokio_core;
//!
//! use std::str::FromStr;
//! use domain::bits::DNameBuf;
//! use domain::resolv::Resolver;
//! use domain::resolv::lookup::lookup_host;
//! use futures::Future;
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!     let resolv = Resolver::new(&core.handle()).unwrap();
//!
//!     let addrs = resolv.start().and_then(|resolv| {
//!         let name = DNameBuf::from_str("www.rust-lang.org").unwrap();
//!         lookup_host(resolv, name)
//!     });
//!     let response = core.run(addrs).unwrap();
//!     for addr in response.iter() {
//!         println!("{}", addr);
//!     }
//! }
//! ```
//!
//! No more fiddeling with record types and classes and the result can now
//! iterate over IP addresses. And we get both IPv4 and IPv6 addresses to
//! boot.
//!
//! Furthermore, we now can use a relative host name. It will be turned into
//! an absolute name according to the rules set down by the configuration we
//! used when creating the resolver.
//!
//! As an aside, the lookup functions are named after the thing they look
//! up not their result following the example of the standard library. So,
//! when you look for the addresses for the host, you have to use
//! [`lookup_host()`], not [`lookup_addr()`].
//!
//! Have a look at the [lookup] module for all the lookup functions
//! currently available.
//!
//!
//! # The Run Shortcut
//!
//! If you only want to do a DNS lookup and don’t otherwise use tokio, there
//! is a shortcut through the [`Resolver::run()`] associated function. It
//! takes a closure from a [`ResolverTask`] to a future and waits while
//! driving the future to completing. In other words, it takes away all the
//! boiler plate from above:
//!
//! ```
//! extern crate domain;
//!
//! use std::str::FromStr;
//! use domain::bits::DNameBuf;
//! use domain::resolv::Resolver;
//! use domain::resolv::lookup::lookup_host;
//!
//! fn main() {
//!     let response = Resolver::run(|resolv| {
//!         let name = DNameBuf::from_str("www.rust-lang.org").unwrap();
//!         lookup_host(resolv, name)
//!     });
//!     for addr in response.unwrap().iter() {
//!         println!("{}", addr);
//!     }
//! }
//! ```
//!
//!
//! [intro]: intro/index.html
//! [lookup]: lookup/index.html
//! [tokio-core]: https://github.com/tokio-rs/tokio-core
//! [`Error`]: error/enum.Error.html
//! [`MessageBuf`]: ../bits/message/struct.MessageBuf.html
//! [`ResolvConf`]: conf/struct.ResolvConf.html
//! [`Resolver`]: struct.Resolver.html
//! [`Resolver::start()`]: struct.Resolver.html#method.start
//! [`Resolver::run()`]: struct.Resolver.html#method.run
//! [`ResolverTask`]: struct.ResolverTask.html
//! [`ResolverTask::query()`]: struct.ResolverTask.html#method.query
//! [`lookup_addr()`]: lookup/fn.lookup_addr.html
//! [`lookup_host()`]: lookup/fn.lookup_host.html


//============ Sub-modules ===================================================

//--- Re-exports

pub use self::conf::ResolvConf;
pub use self::error::{Error, Result};
pub use self::query::Query;


//--- Public modules

pub mod conf;
pub mod error;
pub mod hosts;
pub mod lookup;


//--- Private modules

mod core;
mod query;
mod request;
mod service;
mod tcp;
mod transport;
mod udp;
mod utils;


//--- Meta-modules for documentation

pub mod intro;


//============ Actual Content ================================================

use std::io;
use std::ops::Deref;
use std::result;
use std::sync::Arc;
use futures::{BoxFuture, Future, lazy};
use futures::task::TaskRc;
use tokio_core::reactor;
use ::bits::DName;
use ::iana::{Class, Rtype};
use self::conf::ResolvOptions;
use self::core::Core;


//------------ Resolver -----------------------------------------------------

/// Access to a resolver.
///
/// This types collects all information in order to be able to start a DNS
/// query on a resolver. You can create a new resolver by calling either
/// the `new()` or `from_conf()` functions passing in a handle to a Tokio
/// reactor core. Either function will spawn everything necessary for a
/// resolver into that core. Existing resolver values can be cloned. Clones
/// will refer to the same resolver.
/// 
/// In order to perform a query, you will have to call the `start()` method
/// to create a future that will resolve into an intermediary value that
/// will than allow calling a `query()` method on it and will also allow
/// more complex operations as a complex future.
///
/// Alternatively, you can use the `run()` associated function to
/// synchronously perfrom a series of queries.
#[derive(Clone, Debug)]
pub struct Resolver {
    core: Arc<Core>
}

impl Resolver {
    /// Creates a new resolver using the system’s default configuration.
    ///
    /// All the components of the resolver will be spawned into the reactor
    /// referenced by `reactor`.
    pub fn new(reactor: &reactor::Handle) -> io::Result<Self> {
        Self::from_conf(reactor, ResolvConf::default())
    }

    /// Creates a new resolver using the given configuration.
    ///
    /// All the components of the resolver will be spawned into the reactor
    /// referenced by `reactor`.
    pub fn from_conf(reactor: &reactor::Handle, conf: ResolvConf)
                     -> io::Result<Self> {
        Core::new(reactor, conf)
             .map(|core| Resolver{core: Arc::new(core)})
    }

    /// Returns a reference to the configuration of this resolver.
    pub fn conf(&self) -> &ResolvConf {
        self.core.conf()
    }

    /// Returns a reference to the configuration options of this resolver.
    pub fn options(&self) -> &ResolvOptions {
        &self.core.conf().options
    }

    /// Starts a resolver future atop this resolver.
    ///
    /// The method returns a future that will resolve into a [ResolverTask]
    /// value that can be used to start queries atop this resolver.
    ///
    /// Since the future will never error, it is generic over the error type.
    ///
    /// [ResolverTask]: struct.ResolverTask.html
    pub fn start<E>(&self) -> BoxFuture<ResolverTask, E>
                 where E: Send + 'static {
        let core = self.core.deref().clone();
        lazy(move || Ok(ResolverTask{core: TaskRc::new(core)})).boxed()
    }
}

/// # Shortcuts
///
impl Resolver {
    /// Synchronously perform a DNS operation atop a standard resolver.
    ///
    /// This associated functions removes almost all boiler plate for the
    /// case that you want to perform some DNS operation on a resolver using
    /// the system’s configuration and wait for the result.
    ///
    /// The only argument is a closure taking a [ResolverTask] for creating
    /// queries and returning a future. Whatever that future resolves to will
    /// be returned.
    pub fn run<R, F>(f: F) -> result::Result<R::Item, R::Error>
               where R: Future, R::Error: From<io::Error> + Send + 'static,
                     F: FnOnce(ResolverTask) -> R {
        let mut reactor = try!(reactor::Core::new());
        let resolver = try!(Resolver::new(&reactor.handle()));
        let fut = resolver.start().and_then(f);
        reactor.run(fut)
    }

    pub fn run_with_conf<R, F>(conf: ResolvConf, f: F)
                               -> result::Result<R::Item, R::Error>
               where R: Future, R::Error: From<io::Error> + Send + 'static,
                     F: FnOnce(ResolverTask) -> R {
        let mut reactor = try!(reactor::Core::new());
        let resolver = try!(Resolver::from_conf(&reactor.handle(), conf));
        let fut = resolver.start().and_then(f);
        reactor.run(fut)
    }

    /// Spawn a query.
    ///
    /// This method is a shortcut for `self.start().and_then(f).boxed()`.
    /// Because of the `boxed()` bit, it requires lots of things to be
    /// `Send + 'static` and because of that isn’t necessarily better than
    /// the longer way.
    ///
    /// I am also not sure if *spawn* is the right name. Probably not since
    /// it actually returns the future.
    pub fn spawn<R, F>(&self, f: F) -> BoxFuture<R::Item, R::Error>
                 where R: Future + Send + 'static,
                       R::Error: From<io::Error> + Send + 'static,
                       F: FnOnce(ResolverTask) -> R + Send + 'static {
        self.start().and_then(f).boxed()
    }
}


//------------ ResolverTask --------------------------------------------------

/// A resolver bound to a futures task.
///
/// You can use this type within a running future to start a query on top
/// of the resolver using the `query()` method.
#[derive(Clone)]
pub struct ResolverTask {
    core: TaskRc<Core>
}

impl ResolverTask {
    /// Start a DNS query on this resolver.
    ///
    /// Returns a future that, if successful, will resolve into a DNS
    /// message containing a response to a query for resource records of type
    /// `rtype` associated with the domain name `name` and class `class`. The
    /// name must be an absolute name or else the query will fail.
    pub fn query<N: DName>(&self, name: N, rtype: Rtype, class: Class)
                           -> Query {
        Query::new(self, name, rtype, class)
    }

    /// Returns an arc reference to the resolver’s config.
    pub fn conf(&self) -> Arc<ResolvConf> {
        self.core.with(|core| core.clone_conf())
    }
}

