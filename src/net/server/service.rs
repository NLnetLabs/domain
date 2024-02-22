//! The business logic of a DNS server.
//!
//! The [`Service::call()`] function defines how the service should respond to
//! a given DNS request. resulting in a [`ServiceResult`] containing a
//! transaction that yields one or more future DNS responses, and/or a
//! [`ServiceCommand`].
use core::ops::Deref;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

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
/// There are three ways to implement the [`Service`] trait:
///
///   1. Implement the [`Service`] trait on a struct.
///   2. Define a function compatible with the [`Service`] trait.
///   3. Define a function compatible with [`mk_service()`].
///
/// Whichever approach you choose it is important to minimize the work done
/// before returning from [`Service::call()`], as time spent here blocks the
/// caller. Instead as much work as possible should be delegated to the
/// futures returned as a [`Transaction`].
///
/// # Implementing the [`Service`] trait on a `struct`
///
/// ```
/// use core::future::ready;
/// use core::future::Ready;
/// use domain::base::iana::Class;
/// use domain::base::iana::Rcode;
/// use domain::base::message_builder::AdditionalBuilder;
/// use domain::base::Dname;
/// use domain::base::MessageBuilder;
/// use domain::base::StreamTarget;
/// use domain::net::server::prelude::*;
/// use domain::rdata::A;
///
/// fn mk_answer<T>(
///     msg: &ContextAwareMessage<Message<Vec<u8>>>,
///     builder: MessageBuilder<StreamTarget<Vec<u8>>>,
/// ) -> Result<AdditionalBuilder<StreamTarget<Vec<u8>>>, ServiceError<T>> {
///     let mut answer = builder.start_answer(msg, Rcode::NoError)?;
///     answer.push((
///         Dname::root_ref(),
///         Class::In,
///         86400,
///         A::from_octets(192, 0, 2, 1),
///     ))?;
///     Ok(answer.additional())
/// }
///
/// struct MyService;
///
/// impl Service<Vec<u8>> for MyService {
///     type Error = ();
///     type Target = Vec<u8>;
///     type Single = Ready<ServiceResultItem<Self::Target, Self::Error>>;
///
///     fn call(
///         &self,
///         msg: Arc<ContextAwareMessage<Message<Vec<u8>>>>,
///     ) -> ServiceResult<Self::Target, Self::Error, Self::Single> {
///         let builder = mk_builder_for_target();
///         let additional = mk_answer(&msg, builder)?;
///         let item = ready(Ok(CallResult::new(additional)));
///         let txn = Transaction::single(item);
///         Ok(txn)
///     }
/// }
/// ```
///
/// # Define a function compatible with the [`Service`] trait
///
/// ```
/// use core::future::ready;
/// use core::future::Future;
/// use domain::base::iana::Class;
/// use domain::base::iana::Rcode;
/// use domain::base::name::ToLabelIter;
/// use domain::base::Dname;
/// use domain::net::server::prelude::*;
/// use domain::rdata::A;
///
/// fn name_to_ip<Target>(
///     msg: Arc<ContextAwareMessage<Message<Vec<u8>>>>,
/// ) -> ServiceResult<
///         Target,
///         (),
///         impl Future<Output = ServiceResultItem<Target, ()>>,
///     >
/// where
///     Target: Composer + Octets + FreezeBuilder<Octets = Target> + Default + Send,
///     <Target as octseq::OctetsBuilder>::AppendError: Debug,
/// {
///     let mut out_answer = None;
///     if let Ok(question) = msg.sole_question() {
///         let qname = question.qname();
///         let num_labels = qname.label_count();
///         if num_labels >= 5 {
///             let mut iter = qname.iter_labels();
///             let a = iter.nth(num_labels - 5).unwrap();
///             let b = iter.next().unwrap();
///             let c = iter.next().unwrap();
///             let d = iter.next().unwrap();
///             let a_rec: Result<A, _> = format!("{a}.{b}.{c}.{d}").parse();
///             if let Ok(a_rec) = a_rec {
///                 let builder = mk_builder_for_target();
///                 let mut answer =
///                     builder.start_answer(&msg, Rcode::NoError).unwrap();
///                 answer
///                     .push((Dname::root_ref(), Class::In, 86400, a_rec))
///                     .unwrap();
///                 out_answer = Some(answer);
///             }
///         }
///     }
///
///     if out_answer.is_none() {
///         let builder = mk_builder_for_target();
///         out_answer =
///             Some(builder.start_answer(&msg, Rcode::Refused).unwrap());
///     }
///
///     let additional = out_answer.unwrap().additional();
///     let item = Ok(CallResult::new(additional));
///     Ok(Transaction::single(ready(item)))
/// }
/// ```
///
/// Now when you want to use the service pass it to the server:
///
/// ```ignore
/// let srv = DgramServer::new(sock, buf, name_to_ip);
/// ```
///
/// # Define a function compatible with [`mk_service()`]
///
/// See [`mk_service()`] for an example of how to use it to create a
/// [`Service`] impl from a funciton.
///
/// [`MiddlewareChain`]: crate::net::server::middleware::MiddlewareChain
/// [`DgramServer`]: crate::net::server::dgram::DgramServer
/// [`StreamServer`]: crate::net::server::stream::StreamServer
/// [net::server module documentation]: crate::net::server
/// [`call()`]: Self::call()
/// [`mk_service()`]: crate::net::server::util::mk_service()
pub trait Service<RequestOctets: AsRef<[u8]> = Vec<u8>> {
    /// The type of error returned by [`Service::call()`] on failure.
    type Error: Send + Sync + 'static;

    /// The type of buffer in which [`ServiceResultItem`]s are stored.
    type Target: Composer + Default + Send + Sync + 'static;

    /// The type of future returned by [`Service::call()`] via
    /// [`Transaction::single()`].
    type Single: Future<Output = ServiceResultItem<Self::Target, Self::Error>>
        + Send;

    /// Generate a response to a fully pre-processed request.
    fn call(
        &self,
        message: Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Self::Target, Self::Error, Self::Single>;
}

/// Helper trait impl to treat an [`Arc<impl Service>`] as a [`Service`].
impl<RequestOctets: AsRef<[u8]>, T: Service<RequestOctets>>
    Service<RequestOctets> for Arc<T>
{
    type Error = T::Error;
    type Target = T::Target;
    type Single = T::Single;

    fn call(
        &self,
        message: Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Self::Target, Self::Error, Self::Single> {
        Arc::deref(self).call(message)
    }
}

/// Helper trait impl to treat a function as a [`Service`].
impl<RequestOctets, Error, Target, Single, F> Service<RequestOctets> for F
where
    F: Fn(
        Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Target, Error, Single>,
    RequestOctets: AsRef<[u8]>,
    Error: Send + Sync + 'static,
    Target: Composer + Default + Send + Sync + 'static,
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

/// Command a server to do something.
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
#[derive(Clone, Debug)]
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
    pub fn new(response: AdditionalBuilder<StreamTarget<Target>>) -> Self {
        Self {
            response: Some(response),
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

/// A stream of zero or more DNS response futures relating to a single DNS request.
pub struct TransactionStream<Item> {
    stream: FuturesOrdered<Pin<Box<dyn Future<Output = Item> + Send>>>,
}

impl<Item> TransactionStream<Item> {
    /// Add a response future to a transaction stream.
    pub fn push<T: Future<Output = Item> + Send + 'static>(
        &mut self,
        fut: T,
    ) {
        self.stream.push_back(fut.boxed());
    }

    async fn next(&mut self) -> Option<Item> {
        self.stream.next().await
    }
}

impl<Item> Default for TransactionStream<Item> {
    fn default() -> Self {
        Self {
            stream: Default::default(),
        }
    }
}

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
    PendingStream(
        Pin<Box<dyn Future<Output = TransactionStream<Item>> + Send>>,
    ),

    /// The transaction is a stream of multiple response futures.
    Stream(TransactionStream<Item>),
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

    /// Construct a transaction for a future stream of response futures.
    ///
    /// The given future should build the stream of response futures that will
    /// eventually be resolved by [`Self::next()`].
    ///
    /// This takes a future instead of a [`TransactionStream`] because the
    /// caller may not yet know how many futures they need to push into the
    /// stream and we don't want them to block us while they work that out.
    pub fn stream(
        fut: Pin<Box<dyn Future<Output = TransactionStream<Item>> + Send>>,
    ) -> Self {
        Self(TransactionInner::PendingStream(fut))
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

            TransactionInner::PendingStream(stream_fut) => {
                let mut stream = stream_fut.await;
                let next = stream.next().await;
                self.0 = TransactionInner::Stream(stream);
                next
            }

            TransactionInner::Stream(stream) => stream.next().await,
        }
    }
}
