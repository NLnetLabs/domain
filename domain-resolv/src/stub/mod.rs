/// A stub resolver.
///
/// The most simple resolver possible simply relays all messages to one of a
/// set of pre-configured resolvers that will do the actual work. This is
/// equivalent to what the resolver part of the C library does. This module
/// provides such a stub resolver that emulates this C resolver as closely
/// as possible, in particular in the way it is being configured.
///
/// The main type is [`StubResolver`] that implements the [`Resolver`] trait
/// and thus can be used with the various lookup functions.

pub use self::resolver::StubResolver;

pub mod conf;
pub mod resolver;
mod net;

