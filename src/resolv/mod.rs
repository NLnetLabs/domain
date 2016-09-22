//! An asnychronous stub resolver.
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
//! process DNS *queries*. A query asks a for all the resource records
//! associated with a given triple of a domain name, resource record type,
//! and class (known as a *question*). It is a future resolving to a DNS
//! message with the response or an error. Query can be combined into
//! *lookups* that use the returned resource records to answer more
//! specific questions such as all the IP addresses associated with a given
//! host name. The module provides a rich set of common lookups in the
//! [lookup] sub-module.
//!
//! The following gives an introduction into using the resolver. For an
//! introduction into the internal design, have a look at the [intro]
//! sub-module.
//!
//!
//! # Creating a Resolver
//!
//! The resolver is represented by the [Resolver] type. When creating a value
//! of this type, you create all the parts of an actual resolver according
//! to a resolver configuration. Since these parts are basically networking
//! sockets, the resolver needs a handle to a Tokio reactor where these
//! sockets will live.
//!
//! For the resolver configuration, there’s [ResolvConf]. While you can
//! create a value of this type by hand, the more common way is to use your
//! system’s resolver configuration. [ResolvConf] implements the `Default`
//! trait doing exactly that by reading `/etc/resolv.conf`.
//!
//! > That probably won’t work on Windows, but, sadly, I have no idea how to
//! > retrieve the resolver configuration there. Some help here would be
//! > very much appreciated.
//!
//! Since using the system configuration is the most common case by far,
//! [Resolver]’s `new()` function does just that. So, the easiest way to
//! get a resolver is just this:
//!
//! ```norun
//! use domain::resolv::Resolver;
//! use tokio_core::reactor::Core;
//!
//! let core = Core::new();
//! let resolv = Resolver::new(&core.handle());
//! ```
//!
//! If you do have a configuration, you can use the `from_conf()` function
//! instead.
//!
//!
//! # Using the Resolver: Queries
//!
//! First of all, the [Resolver] value you created doesn’t actually contain
//! the resolver. Instead, it only keeps all the information necessary to
//! start a query using the real resolver living inside the reactor core
//! (this year’s nomination for the category Best Type Name)
//! somewhere. Because of this, you can clone the resolver, even pass it to
//! other threads.
//!
//! Oddly, the one thing you can’t do with a resolver is start a query.
//! Instead, you need an intermediary type called [ResolverTask]. You’ll
//! get one through [Resolver::start()] or, more correctly, you get a future
//! to one through this method. You then chain on your actual query or
//! sequence of queries using combinators such as `Future::and_then()`.
//!
//! The actual query is started through [ResolverTask::query()]. It takes a
//! domain name, a resource record type, and a class and returns a future
//! that will resolve into either a [MessageBuf] with the response to the
//! query or an [Error].
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
//! use domain::iana::{Class, RRType};
//! use domain::rdata::Aaaa;
//! use domain::resolv::Resolver;
//! use futures::Future;
//! use tokio_core::reactor::Core;
//!
//! fn main() {
//!     let mut core = Core::new().unwrap();
//!     let resolv = Resolver::new(&core.handle());
//!
//!     let addrs = resolv.start().and_then(|resolv| {
//!         let name = DNameBuf::from_str("www.rust-lang.org.").unwrap();
//!         resolv.query(name, RRType::Aaaa, Class::In)
//!     });
//!     let response = core.run(addrs).unwrap();
//!     for record in response.answer().unwrap().iter::<Aaaa>() {
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
//! This is what lookups do. They take a [ResolverTask] and some additional
//! information and turn that into a future of some specific result. So,
//! to do lookups you have to follow the procedure using `start()` as given
//! above but instead of calling `query()` inside the closure, you use one
//! of the lookup functions from the [lookup] sub-module.
//!
//! Using [lookup_host()], the process of looking up the IP addresses
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
//!     let resolv = Resolver::new(&core.handle());
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
//! iterater over IP addresses. And we get both IPv4 and IPv6 addresses to
//! boot.
//!
//! Furthermore, we now can use a relative host name. It will be turned into
//! an absolute name according to the rules set down by the configuration we
//! used when creating the resolver.
//!
//! As an aside, the lookup functions are named after the thing they look
//! up not their result following the example of the standard library. So,
//! when you look for the addresses for the host, you have to use
//! [lookup_host()], not [lookup_addr()].
//!
//! Have a look at the [lookup] module for all the lookup functions
//! currently available.
//!
//!
//! # The Run Shortcut
//!
//! If you only want to do a DNS lookup and don’t otherwise use tokio, there
//! is a shortcut through the [Resolver::run()] associated function. It
//! takes a closure from a [ResolverTask] to a future and waits while
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
//! [Error]: error/enum.Error.html
//! [MessageBuf]: ../bits/message/struct.MessageBuf.html
//! [ResolvConf]: conf/struct.ResolvConf.html
//! [Resolver]: struct.Resolver.html
//! [Resolver::start()]: struct.Resolver.html#method.start
//! [Resolver::run()]: struct.Resolver.html#method.run
//! [ResolverTask]: struct.ResolverTask.html
//! [ResolverTask::query()]: struct.ResolverTask.html#method.query
//! [lookup_addr()]: lookup/fn.lookup_addr.html
//! [lookup_host()]: lookup/fn.lookup_host.html


//--- Re-exports

pub use self::conf::ResolvConf;
pub use self::error::{Error, Result};
//pub use self::resolver::{Resolver, ResolverTask, Query};


//--- Public modules

pub mod conf;
pub mod error;
pub mod hosts;
//pub mod lookup;


//--- Private modules

mod pending;
mod request;
mod service;
mod transport;
mod utils;

//mod dgram;
//mod resolver;
//mod stream;
//mod tcp;
//mod udp;


//--- Meta-modules for documentation

pub mod intro;
