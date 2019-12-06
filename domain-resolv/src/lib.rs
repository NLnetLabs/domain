//! Asynchronous DNS resolving.
//!
//! In the DNS, a resolver processes and attempts to answer questions. This
//! crate provides a number of such resolvers – or will be, once it is more
//! complete. In addition, the crate provides higher level abstraction of
//! the information that can be obtained via DNS queries. We call these
//! _lookups_.
//!
//! The various types of resolvers available all implement the [`Resolver`]
//! trait which provides the basic functionality of all resolvers:
//! asynchronously answering questions.
//!
//! The following resolvers are available:
//!
//! *  [`StubResolver`] is the most simple resolver of them all. It is being
//!    configured with a list of upstream resolvers and simply forwards all
//!    queries to those resolvers, expecting them to do all the heavy work.
//!
//!    See the [stub] module for more information on how to use the stub
//!    resolver.
//!
//! The lookups implemented by the crate are generic over the particular
//! resolver, so you can pick the resolver most suitable for your own
//! application or even implement your own specialised resolver. All
//! lookups are implemented as functions in the [lookup] module. For
//! convenience, they are also available as methods on the [`Resolver`]
//! trait.
//!
//! [lookup]: lookup/index.html
//! [stub]: stub/index.html
//! [`Resolver`]: resolver/trait.Resolver.html
//! [`StubResolver`]: stub/struct.StubResolver.html

pub use self::resolver::Resolver;
pub use self::stub::StubResolver;

pub mod lookup;
pub mod resolver;
pub mod stub;

