//! An asynchronous stub resolver.
//!
//! A resolver is the component in the DNS that answers queries. A stub
//! resolver does so by simply relaying queries to a different resolver
//! chosen from a predefined set. This is how pretty much all user
//! applications use DNS.
//!
//! This module implements a modern, asynchronous stub resolver. It is
//! built on top of [rotor](https://github.com/tailhook/rotor). It consists
//! of two parts.
//!
//! The `DnsTransport` is a rotor state machine that talks to
//! the upstream resolvers. It can either be composed with other rotor state
//! machines or can be run in a thread of its own.
//!
//! The `Resolver` processes actual queries, called `Task`s. It can do so
//! either synchronously, ie., it will wait until a result or error has been
//! received, or asynchronously through a `ResolverMachine` state machine
//! that can be embedded in another state machine.
//!
//! There are various `Task`s available each performing a different DNS
//! application.
//!
//!
//! # Configuring a Resolver
//!
//! Before you can actually use a resolver, you need to get its configuration.
//! This currently is done through a value of type `ResolvConf`. On Unix
//! systems, the easiest way to get to a working configuration is to steal
//! it from the system’s `/etc/resolv.conf` file. The type understands the
//! contents of this file, so this is easy:
//!
//! ```
//! use domain::resolv::ResolvConf;
//!
//! let conf = ResolvConf::default();
//! println!("Configuration:\n{}", conf);
//! ```
//!
//! Sadly, I have no idea how the resolver is configured in Windows.
//!
//! Note that if your application lives for a long time, the system’s
//! resolver configuraiton can change. Currently, there is no way of
//! reconfiguring a resolver—this is an open issue.
//!
//!
//! # Creating a Resolver
//!
//! Once you have a configuration, you can create a resolver or, more
//! specifically, a DNS transport/resolver pair. There are two options.
//! `DnsTransport::new()` creates returns the `DnsTransport` state machine
//! and a resolver so you can for instance compose that state machine into
//! one bigger machine. Alternatively, you can use `Resolver::spawn()`
//! which starts the DNS transport in a new thread of its own. This is likely
//! what you want if you are not using rotor yourself.
//!
//! ## Creating a Resolver in Its Own Thread
//!
//! This second case looks like this:
//!
//! ```norun
//! use domain::resolv::{Resolver, ResolvConf};
//!
//! let conf = ResolvConf::default();
//! let (join, resolv) = Resolver::spawn(conf).unwrap();
//! ```
//!
//! Now `resolv` is a resolver. You can use it for asking questions. You can
//! also clone it and pass it along to other types that need to ask
//! questions.
//!
//! You also received `join`. It is a `JoinHandle` which you can use for
//! joining the resolver thread. This thread will terminate once the last
//! clone of `resolv` is gone out of scope. Thus, you will have to get rid
//! of `resolv` before calling `join()` on `join`. You can either move
//! `resolv` into a function or simply `drop()` it.
//!
//! ```
//! use std::mem;
//! use domain::resolv::{Resolver, ResolvConf};
//!
//! let conf = ResolvConf::default();
//! let (join, resolv) = Resolver::spawn(conf).unwrap();
//! // Do things with resolv here ...
//! mem::drop(resolv);
//! join.join().unwrap();
//! ```
//!
//!
//! ## Creating a `DnsTransport` State Machine
//!
//! The `DnsTransport::new()` function creates a new rotor state machine
//! using a resolver configuration and a rotor scope. You can then use this
//! state machine for instance with rotor’s `Compose2` type to compose it
//! with your own state machine that does the actual work. Since this is a
//! bit involved, we are not giving an example here. Instead, have a look
//! at the *remoteipd* example in the domain sources.
//!
//!
//! # Making Queries
//!
//! Once you have a `Resolver` you can make queries. There are several kinds
//! of queries available, known as `Tasks`. The most basic task is called
//! `Query` and simply returns all the resource records for a given triple of
//! domain name, resource record type, and class. More complex tasks are
//! available, too, so you don’t have to know all the details for, say,
//! getting all the `SocketAddr`s for a server using SRV queries.
//!
//! When you have decided on your task, you can either query synchronously or
//! asynchronously. Let’s start with the easier case.
//!
//!
//! ## Making Queries Synchronously
//!
//! If you want to wait for the result of your query, you can use
//! `Resolver::sync_task()`. Obviously, you cannot use this function if the
//! `DnsTransport` for the resolver lives in the same thread. To ask for the
//! A records for `example.com`, you’d do something like this:
//!
//! ```norun
//! # use std::mem;
//! # use std::str::FromStr;
//! # use domain::bits::{DName, RRType};
//! # use domain::resolv::{Resolver, ResolvConf, Query};
//! #
//! # let conf = ResolvConf::default();
//! # let (join, resolv) = Resolver::spawn(conf).unwrap();
//! let response = resolv.sync_task(
//!                    Query::new_in(DName::from_str("example.com.").unwrap(),
//!                                  RRType::A)).unwrap();
//! for record in response.answer().unwrap().generic_iter() {
//!     println!("{}", record.unwrap());
//! }
//! # mem::drop(resolv);
//! # join.join().unwrap();
//! ```
//!
//!
//! ## Making Queries Asynchronously
//!
//! TODO

pub use self::conf::ResolvConf;
pub use self::error::{Error, Result};
pub use self::hosts::Hosts;
pub use self::resolver::{DnsTransport, Resolver};
pub use self::tasks::{Query};

pub mod conf;
pub mod error;
pub mod hosts;
pub mod resolver;
pub mod tasks;

mod conn;
mod dispatcher;
mod query;
mod stream;
mod sync;
mod tcp;
mod timeout;
mod udp;


