//! The resolver.
//!
//! This module contains the type [`Resolver`] that represents a resolver.
//! The type is also re-exported at crate level. You are encouraged to use
//! that definition.
//!
//! [`Resolver`]: struct:Resolver.html

use std::{io, ops};
use std::sync::Arc;
use domain_core::bits::{Message, MessageBuilder, Question};
use domain_core::bits::message_builder::OptBuilder;
use domain_core::bits::name::ToDname;
use domain_core::iana::Rcode;
use futures::{Future, FutureExt, TryFutureExt};
use futures_util::compat::TokioDefaultSpawn;
use tokio::prelude::Future as TokioFuture;
use super::conf::{ResolvConf, ResolvOptions};
use super::net::{query_server, ServerList};


//------------ Resolver ------------------------------------------------------

/// Access to a DNS stub resolver.
///
/// This type collects all information making it possible to start DNS
/// queries. You can create a new resoler using the system’s configuration
/// using the [`new()`] associate function or using your own configuration
/// with [`from_conf()`].
///
/// Resolver values can be cloned relatively cheaply as they keep all
/// information behind an arc.
///
/// If you want to run a single query or lookup on a resolver synchronously,
/// you can do so simply by using the [`run()`] or [`run_with_conf()`]
/// associated functions.
///
/// [`new()`]: #method.new
/// [`from_conf()`]: #method.from_conf
/// [`query()`]: #method.query
/// [`run()`]: #method.run
/// [`run_with_conf()`]: #method.run_with_conf
#[derive(Clone, Debug)]
pub struct Resolver(Arc<ResolverInner>);

/// The actual resolver.
#[derive(Debug)]
struct ResolverInner {
    /// Preferred servers.
    preferred: ServerList,

    /// Streaming servers.
    stream: ServerList,

    /// Resolver options.
    options: ResolvOptions,

}


impl Resolver {
    /// Creates a new resolver using the system’s default configuration.
    pub fn new() -> Self {
        Self::from_conf(ResolvConf::default())
    }

    /// Creates a new resolver using the given configuraiton.
    pub fn from_conf(conf: ResolvConf) -> Self {
        Resolver(Arc::new(
            ResolverInner {
                preferred: ServerList::from_conf(&conf, |s| {
                    s.transport.is_preferred()
                }),
                stream: ServerList::from_conf(&conf, |s| {
                    s.transport.is_stream()
                }),
                options: conf.options
            }
        ))
    }

    /// Queries the resolver for an answer to a question.
    pub fn query<N, Q>(
        &self,
        question: Q
    ) -> impl Future<Output = Result<Answer, QueryError>>
    where N: ToDname, Q: Into<Question<N>> {
        // 512 bytes should be enough for a domain name that is at most 255
        // bytes plus whatever EDNS there’ll be.
        let mut msg = MessageBuilder::new_tcp(512);
        msg.push(question).unwrap();

        if self.0.options.recurse {
            msg.header_mut().set_rd(true);
        }

        let mut msg = msg.opt().unwrap();
        // Message size won’t change anymore, so we can update the prelude.
        let len = msg.preview().len() - 2;
        assert!(len <= usize::from(::std::u16::MAX));
        msg.prelude_mut()[0] = (len >> 8) as u8;
        msg.prelude_mut()[1] = len as u8;

        async_query(self.0.clone(), msg)
    }
}

/// # Shortcuts
///
impl Resolver {
    /// Synchronously perform a DNS operation atop a standard resolver.
    ///
    /// This associated functions removes almost all boiler plate for the
    /// case that you want to perform some DNS operation, either a query or
    /// lookup, on a resolver using the system’s configuration and wait for
    /// the result.
    ///
    /// The only argument is a closure taking a reference to a `Resolver`
    /// and returning a future. Whatever that future resolves to will be
    /// returned.
    pub fn run<R, F>(op: F) -> R::Output
    where R: Future, F: FnOnce(&Resolver) -> R {
        Self::run_with_conf(ResolvConf::default(), op)
    }

    /// Synchronously perform a DNS operation atop a configuredresolver.
    ///
    /// This is like [`run()`] but also takes a resolver configuration for
    /// tailor-making your own resolver.
    ///
    /// [`run()`]: #method.run
    pub fn run_with_conf<R, F>(conf: ResolvConf, op: F) -> R::Output
    where R: Future, F: FnOnce(&Resolver) -> R {
        let resolver = Self::from_conf(conf);
        op(&resolver).boxed().unit_error().compat(TokioDefaultSpawn)
            .wait().unwrap()
    }
}



async fn async_query(
    resolver: Arc<ResolverInner>,
    mut message: OptBuilder,
) -> Result<Answer, QueryError> {
    let mut stream = false;
    for _ in 0..resolver.options.attempts {
        let preferred = resolver.preferred.iter();
        if resolver.options.rotate {
            resolver.preferred.rotate();
        }
        for server in preferred {
            println!("trying {:?}", server.addr);
            match await!(query_server(server, message)) {
                (ret_message, Ok(answer)) => {
                    println!("got answer");
                    if answer.is_final() {
                        return Ok(answer)
                    }
                    else if answer.is_truncated() {
                        message = ret_message;
                        stream = true;
                        break;
                    }
                    message = ret_message;
                }
                (ret_message, Err(err)) => {
                    println!("got error {}", err);
                    message = ret_message;
                }
            };
        }
    }
    if stream {
        await!(async_stream_query(resolver, message))
    }
    else {
        Err(QueryError::GivingUp)
    }
}

async fn async_stream_query(
    resolver: Arc<ResolverInner>,
    mut message: OptBuilder,
) -> Result<Answer, QueryError> {
    for _ in 0..resolver.options.attempts {
        let streams = resolver.stream.iter();
        if resolver.options.rotate {
            resolver.stream.rotate();
        }
        for server in streams {
            match await!(query_server(server, message)) {
                (ret_message, Ok(answer)) => {
                    if answer.is_final() {
                        return Ok(answer)
                    }
                    message = ret_message;
                }
                (ret_message, Err(_)) => {
                    message = ret_message;
                }
            };
        }
    }
    Err(QueryError::GivingUp)
}


//--- Default

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}


//------------ Answer --------------------------------------------------------

/// The answer to a question.
///
/// This type is a wrapper around the DNS [`Message`] containing the answer
/// that provides some additional information.
#[derive(Clone, Debug)]
pub struct Answer {
    message: Message,
}

impl Answer {
    /// Returns whether the answer is a final answer to be returned.
    pub fn is_final(&self) -> bool {
        (self.message.header().rcode() == Rcode::NoError
            || self.message.header().rcode() == Rcode::NXDomain)
        && !self.message.header().tc()
    }

    /// Returns whether the answer is truncated.
    pub fn is_truncated(&self) -> bool {
        self.message.header().tc()
    }

    pub fn into_message(self) -> Message {
        self.message
    }
}

impl From<Message> for Answer {
    fn from(message: Message) -> Self {
        Answer { message }
    }
}

impl ops::Deref for Answer {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl AsRef<Message> for Answer {
    fn as_ref(&self) -> &Message {
        &self.message
    }
}


//------------ QueryError ----------------------------------------------------

#[derive(Debug)]
pub enum QueryError {
    GivingUp,
    Io(io::Error)
}
