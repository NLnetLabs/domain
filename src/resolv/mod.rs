//! An asynchronous stub resolver.
//!
//! A resolver is the component in the DNS that answers queries. A stub
//! resolver does so by simply relaying queries to a different resolver
//! chosen from a predefined set. This is how pretty much all user
//! applications use DNS.
//!
//! This module implements a modern, asynchronous stub resolver built on
//! top of [futures] and [tokio].
//!
//! The module provides ways to create a *resolver* that knows how to
//! process DNS *queries*. A query asks for all the resource records
//! associated with a given triple of a domain name, resource record type,
//! and class (known as a *question*). It is a future resolving to a DNS
//! message with a successful response or an error. Queries can be combined
//! into *lookups* that use the returned resource records to answer more
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
//! ```rust,no_run
//! # extern crate domain;
//! # extern crate tokio_core;
//! use domain::resolv::Resolver;
//! use tokio_core::reactor::Core;
//!
//! # fn main() {
//! let core = Core::new().unwrap();
//! let resolv = Resolver::new(&core.handle());
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
//! The main purpose of the resolver, though, is to start queries. This is
//! done through [`Resolver::query()`]. It takes something that can be
//! turned into a question and returns a future that will resolve into
//! either a [`MessageBuf`] with the response to the query or an [`Error`]. 
//! Conveniently, a triple of a domain name, a resource record type, and a
//! class is something than can be turned into a question, so you don’t need
//! to build the question from hand. (You will have to convert a string into
//! a domain name from hand since that may fail.)
//!
//! As an example, let’s find out the IPv6 addresses for `www.rust-lang.org`:
//!
//! ```rust,no_run
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
//!     let resolv = Resolver::new(&core.handle());
//!
//!     let name = DNameBuf::from_str("www.rust-lang.org.").unwrap();
//!     let addrs = resolv.query((name, Rtype::Aaaa, Class::In));
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
//! Most of the times when you are using DNS you aren’t really interested in a
//! bunch of resource records. You want an answer to a more concrete
//! question. For instance, if you want to know the IP addresses for a
//! host name, you don’t really care that you have to make a query for the
//! `A` records and one for `AAAA` records for that host name. You want the
//! addresses.
//!
//! This is what lookups do. They are functions that take a [`Resolver`]
//! and some additional information and turn that into a future of some
//! specific result.
//!
//! Using [`lookup_host()`], the process of looking up the IP addresses
//! becomes much easier. To update above’s example:
//!
//! ```rust,no_run
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
//!     let name = DNameBuf::from_str("www.rust-lang.org").unwrap();
//!     let addrs = lookup_host(resolv, name);
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
//! takes a closure from a [`Resolver`] to a future and waits while
//! driving the future to completing. In other words, it takes away all the
//! boiler plate from above:
//!
//! ```rust,no_run
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
//! [futures]: https://github.com/alexcrichton/futures-rs
//! [tokio]: https://tokio.rs/
//! [intro]: intro/index.html
//! [lookup]: lookup/index.html
//! [`Error`]: error/enum.Error.html
//! [`MessageBuf`]: ../bits/message/struct.MessageBuf.html
//! [`ResolvConf`]: conf/struct.ResolvConf.html
//! [`Resolver`]: struct.Resolver.html
//! [`Resolver::start()`]: struct.Resolver.html#method.start
//! [`Resolver::run()`]: struct.Resolver.html#method.run
//! [`Resolver::query()`]: struct.Resolver.html#method.query
//! [`lookup_addr()`]: lookup/fn.lookup_addr.html
//! [`lookup_host()`]: lookup/fn.lookup_host.html


//------------ Re-exports ----------------------------------------------------

pub use self::conf::ResolvConf;
pub use self::public::{Query, Resolver};


//------------ Public Modules ------------------------------------------------

pub mod conf;
pub mod error;
pub mod lookup;


//------------ Meta-modules for Documentation --------------------------------

pub mod intro;


//------------ Private Modules -----------------------------------------------

mod channel;
mod public;
mod request;
mod tcp;
mod transport;
mod udp;
