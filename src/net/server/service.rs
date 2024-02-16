//! The business logic of a DNS server.
//!
//! The [`Service::call()`] function defines how the service should respond to
//! a given DNS request. resulting in a [`ServiceResult`] containing a
//! transaction that yields one or more future DNS responses, and/or a
//! [`ServiceCommand`].
use core::marker::Send;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;
use std::{convert::AsRef, string::String};

use futures_util::stream::FuturesOrdered;
use futures_util::{FutureExt, StreamExt};
use octseq::{OctetsBuilder, ShortBuf};

use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};

use super::message::ContextAwareMessage;

//------------ Service -------------------------------------------------------

/// The result of calling a [`Service`].
///
/// On success [`Service::call()`] results in a [`Transaction`] consisting of
/// one or more [`ServiceResultItem`] futures.
///
/// On failure it instead results in a [`ServiceError`].
pub type ServiceResult<Target, Error, Single> = Result<
    Transaction<ServiceResultItem<Target, Error>, Single>,
    ServiceError<Error>,
>;

/// A single result item from a [`ServiceResult`].
///
/// See [`Service::call()`].
pub type ServiceResultItem<Target, Error> =
    Result<CallResult<Target>, ServiceError<Error>>;

/// [`Service`]s are responsible for determining how to respond to valid DNS
/// requests.
///
/// A request is "valid" if it passed successfully through the underlying
/// server (e.g. [`DgramServer`] or [`StreamServer`]) and [`MiddlewareChain`]
/// stages.
///
/// For an overview of how services fit into the total flow of request and
/// response handling see the [net::server module documentation].
///
/// Each [`Service`] implementation defines a [`call()`] function which takes
/// a [`ContextAwareMessage`] DNS request as input and returns either a
/// [`Transaction`] on success, or a [`ServiceError`] on failure, as output.
///
/// Each [`Transaction`] contains either a single DNS response message, or a
/// stream of DNS response messages (e.g. for a zone transfer). Each response
/// message is returned as a [`Future`] which the underlying server will
/// resolve to a [`CallResult`].
///
/// # Usage
///
/// There are three ways to implement the [`Service`] trait, from most
/// flexible and difficult, to easiest but least flexible:
///
///   1. Implement the trait on a struct.
///   2. Define a function compatible with the trait.
///   3. Define a function compatible with the [`mk_service()`] helper
///      function.
///
/// See [`mk_service()`] for an example of using it to create a [`Service`]
/// impl.
///
/// [`MiddlewareChain`]: crate::net::server::middleware::MiddlewareChain
/// [`DgramServer`]: crate::net::server::dgram::DgramServer
/// [`StreamServer`]: crate::net::server::stream::StreamServer
/// [net::server module documentation]: crate::net::server
/// [`call()`]: Self::call()
/// [`mk_service()`]: crate::net::server::util::mk_service()
pub trait Service<RequestOctets: AsRef<[u8]> = Vec<u8>> {
    type Error: Send + Sync + 'static;
    type Target: Composer + Default + Send + Sync + 'static;
    type Single: Future<Output = ServiceResultItem<Self::Target, Self::Error>>
        + Send;

    #[allow(clippy::type_complexity)]
    fn call(
        &self,
        message: Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Self::Target, Self::Error, Self::Single>;
}

impl<RequestOctets, Error, Target, Single, F> Service<RequestOctets> for F
where
    F: Fn(
        Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Target, Error, Single>,
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Error: Send + Sync + 'static,
    Single: Future<Output = ServiceResultItem<Target, Error>> + Send,
{
    type Error = Error;
    type Target = Target;
    type Single = Single;

    fn call(
        &self,
        message: Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Target, Error, Self::Single> {
        (*self)(message)
    }
}

//------------ ServiceError --------------------------------------------------

/// An error reported by a [`Service`].
#[derive(Debug)]
pub enum ServiceError<T> {
    /// The service declined to handle the request.
    RequestIgnored,

    /// The service was unable to assemble the response.
    ResponseBuilderError,

    /// The service encountered a service-specific error condition.
    ServiceSpecificError(T),

    /// The service is shutting down.
    ShuttingDown,

    /// Some other service error.
    Other(String),
}

impl<T> core::fmt::Display for ServiceError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServiceError::RequestIgnored => {
                write!(f, "RequestIgnored")
            }
            ServiceError::ResponseBuilderError => {
                write!(f, "ResponseBuilderError")
            }
            ServiceError::ServiceSpecificError(_err) => {
                write!(f, "ServiceSpecificError")
            }
            ServiceError::ShuttingDown => {
                write!(f, "ShuttingDown")
            }
            ServiceError::Other(err) => {
                write!(f, "Other({})", err)
            }
        }
    }
}

impl<T> From<PushError> for ServiceError<T> {
    fn from(_err: PushError) -> Self {
        Self::ResponseBuilderError
    }
}

//------------ ServiceCommand ------------------------------------------------

/// Commands a server, usually from a [`Service`], to do something.
#[derive(Copy, Clone, Debug)]
pub enum ServiceCommand {
    #[doc(hidden)]
    /// This command is for internal use only.
    Init,

    /// Command the server to alter its configuration.
    ///
    /// The effect may differ whether handled by a server or (for
    /// connection-oriented transport protocols) a connection handler.
    Reconfigure { idle_timeout: Duration },

    /// Command the connection handler to terminate.
    ///
    /// This command is only for connection handlers for connection-oriented
    /// transport protocols, it should be ignored by servers.
    CloseConnection,

    /// Command the server to terminate.
    Shutdown,
}

//------------ CallResult ----------------------------------------------------

/// The result of processing a DNS request via [`Service::call()`].
///
/// Directions to a server on how to respond to a request.
///
/// In most cases a [`CallResult`] will be a DNS response message.
///
/// If needed a [`CallResult`] can instead, or additionally, contain a
/// [`ServiceCommand`] directing the server or connection handler handling the
/// request to adjust its own configuration, or even to terminate the
/// connection.
pub struct CallResult<Target> {
    response: Option<AdditionalBuilder<StreamTarget<Target>>>,
    command: Option<ServiceCommand>,
}

impl<Target> CallResult<Target>
where
    Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Target::AppendError: Into<ShortBuf>,
{
    /// Construct a [`CallResult`] from a DNS response message.
    #[must_use]
    pub fn new<T: Into<AdditionalBuilder<StreamTarget<Target>>>>(
        response: T,
    ) -> Self {
        Self {
            response: Some(response.into()),
            command: None,
        }
    }

    /// Construct a [`CallResult`] from a [`ServiceCommand`].
    #[must_use]
    pub fn command_only(command: ServiceCommand) -> Self {
        Self {
            response: None,
            command: Some(command),
        }
    }

    /// Add a [`ServiceCommand`] to an existing [`CallResult`].
    #[must_use]
    pub fn with_command(mut self, command: ServiceCommand) -> Self {
        self.command = Some(command);
        self
    }

    /// Get the contained DNS response message, if any.
    #[must_use]
    pub fn get_mut(
        &mut self,
    ) -> Option<&mut AdditionalBuilder<StreamTarget<Target>>> {
        self.response.as_mut()
    }

    /// Get the contained command, if any.
    #[must_use]
    pub fn command(&self) -> Option<ServiceCommand> {
        self.command
    }

    /// Convert the [`CallResult`] into the contained DNS response message and command.
    #[must_use]
    pub fn into_inner(
        self,
    ) -> (
        Option<AdditionalBuilder<StreamTarget<Target>>>,
        Option<ServiceCommand>,
    ) {
        let CallResult { response, command } = self;
        (response, command)
    }
}

//------------ Transaction ---------------------------------------------------

/// Zero or more DNS response futures relating to a single DNS request.
///
/// A transaction is either empty, a single DNS response future, or a stream
/// of DNS response futures.
///
/// # Usage
///
/// Either:
///   - Construct a transaction for a [`single()`] response future, OR
///   - Construct a transaction [`stream()`] and [`push()`] response futures
///     into it.
///
/// Then iterate over the response futures one at a time using [`next()`].
///
/// [`single()`]: Self::single()
/// [`stream()`]: Self::stream()
/// [`push()`]: Self::push()
/// [`next()`]: Self::next()
pub struct Transaction<Item, Single>(TransactionInner<Item, Single>)
where
    Single: Future<Output = Item> + Send;

enum TransactionInner<Item, Single>
where
    Single: Future<Output = Item> + Send,
{
    /// The transaction will result in a single immediate response.
    ///
    /// This variant is for internal use only when aborting Middleware
    /// processing early.
    Immediate(Option<Item>),

    /// The transaction will result in at most a single response future.
    Single(Option<Single>),

    /// The transaction will result in stream of multiple response futures.
    Stream(FuturesOrdered<Pin<Box<dyn Future<Output = Item> + Send>>>),
}

impl<Item, Single> Transaction<Item, Single>
where
    Single: Future<Output = Item> + Send,
{
    /// Construct a transaction for a single immediate response.
    pub(crate) fn immediate(item: Item) -> Self {
        Self(TransactionInner::Immediate(Some(item)))
    }

    /// Construct an empty transaction.
    pub fn empty() -> Self {
        Self(TransactionInner::Single(None))
    }

    /// Construct a transaction for a single response future.
    pub fn single(fut: Single) -> Self {
        Self(TransactionInner::Single(Some(fut)))
    }

    /// Construct a transaction for a stream of response futures.
    ///
    /// Call [`push()`] to add a response future to the stream.
    ///
    /// [`push()`]: Self::push()
    pub fn stream() -> Self {
        Self(TransactionInner::Stream(Default::default()))
    }

    /// Add a response future to a transaction stream.
    ///
    /// # Panics
    ///
    /// This function will panic if this transaction is not a stream.
    pub fn push<T: Future<Output = Item> + Send + 'static>(
        &mut self,
        fut: T,
    ) {
        match &mut self.0 {
            TransactionInner::Stream(stream) => stream.push_back(fut.boxed()),
            _ => unreachable!(),
        }
    }

    /// Take the next response from the transaction, if any.
    ///
    /// This function provides a single way to take futures from the
    /// transaction without needing to handle which type of transaction it is.
    ///
    /// Returns None if there are no (more) responses to take, Some(future)
    /// otherwise.
    pub async fn next(&mut self) -> Option<Item> {
        match &mut self.0 {
            TransactionInner::Immediate(item) => item.take(),

            TransactionInner::Single(opt_fut) => match opt_fut.take() {
                Some(fut) => Some(fut.await),
                None => None,
            },

            TransactionInner::Stream(stream) => stream.next().await,
        }
    }
}
