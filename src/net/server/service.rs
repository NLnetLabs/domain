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

/// Services generate DNS responses according to user defined business logic.
///
/// Each [`Service`] implementation defines a [`call()`] function which takes
/// a [`ContextAwareMessage`] as input and returns either a [`Transaction`] on
/// success, or a [`ServiceError`] on failure, as output.
///
/// Responses are encapsulated inside a [`Transaction`] which is either a
/// single response, or a stream of responses (e.g. for a zone transfer),
/// where each response is a [`Future`] that resolves to a [`CallResult`].
///
/// In the common case a [`CallResult`] is a DNS response message. For some
/// advanced use cases it can instead, or additionally, direct the server
/// handling the request (or a single connection it is handling) to adjust its
/// own configuration, or even to terminate the connection.
///
/// There are three ways to implement the [`Service`] trait, from most
/// flexible and difficult, to easiest but least flexible:
///
///   1. Implement the trait on a struct.
///   2. Define a function compatible with the trait.
///   3. Define a function compatible with the [`mk_service()`] helper
///      function.
///
/// See [`mk_service()`] for an example of using it to create a [`Service`] impl.
///
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

/// Commands that [`Service`]s can send to influence the parent server.
#[derive(Copy, Clone, Debug)]
pub enum ServiceCommand {
    Init,

    Reconfigure {
        idle_timeout: Duration,
    },

    /// Close the connection.
    ///
    /// E.g. in the case where an RFC 5936 AXFR TCP server "believes beyond a
    /// doubt that the AXFR client is attempting abusive behavior".
    CloseConnection,

    Shutdown,
}

//------------ CallResult ----------------------------------------------------

/// The result of processing a DNS request via [`Service::call()`].
pub struct CallResult<Target> {
    pub response: Option<AdditionalBuilder<StreamTarget<Target>>>,
    pub command: Option<ServiceCommand>,
}

/// Directions to a server on how to respond to a request.
///
/// [`CallResult`] supports the following ways to handle a client request:
///
///   - Respond to the client. This is the default case.
///
///   - Respond to the client and adjust the servers handling of requests.
///     This could be required for example to honour a client request EDNS(0)
///     OPT RR that requests that the timeout from server to client be altered.
///
///   - Ignore the client request, e.g. due to policy.
///
///   - Terminate the connection with the client, e.g. due to policy or
///     or because the service is shutting down.
///
/// For reasons of policy it may be necessary to ignore certain client
/// requests without sending a response
impl<Target> CallResult<Target>
where
    Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Target::AppendError: Into<ShortBuf>,
{
    #[must_use]
    pub fn new<T: Into<AdditionalBuilder<StreamTarget<Target>>>>(
        response: T,
    ) -> Self {
        Self {
            response: Some(response.into()),
            command: None,
        }
    }

    #[must_use]
    pub fn command_only(command: ServiceCommand) -> Self {
        Self {
            response: None,
            command: Some(command),
        }
    }

    #[must_use]
    pub fn with_command(mut self, command: ServiceCommand) -> Self {
        self.command = Some(command);
        self
    }
}

//------------ Transaction ---------------------------------------------------

/// A server transaction generating the responses for a request.
pub struct Transaction<Item, Single>(TransactionInner<Item, Single>)
where
    Single: Future<Output = Item> + Send;

enum TransactionInner<Item, Single>
where
    Single: Future<Output = Item> + Send,
{
    /// The transaction will be concluded with a single immediate response.
    Immediate(Option<Item>),

    /// The transaction will be concluded with a single response.
    Single(Option<Single>),

    /// The transaction will results in stream of multiple responses.
    Stream(FuturesOrdered<Pin<Box<dyn Future<Output = Item> + Send>>>),
}

impl<Item, Single> Transaction<Item, Single>
where
    Single: Future<Output = Item> + Send,
{
    pub(crate) fn immediate(item: Item) -> Self {
        Self(TransactionInner::Immediate(Some(item)))
    }

    pub fn single(fut: Single) -> Self {
        Self(TransactionInner::Single(Some(fut)))
    }

    pub fn stream() -> Self {
        Self(TransactionInner::Stream(Default::default()))
    }

    pub fn push<T: Future<Output = Item> + Send + 'static>(
        &mut self,
        fut: T,
    ) {
        match &mut self.0 {
            TransactionInner::Stream(stream) => stream.push_back(fut.boxed()),
            _ => unreachable!(),
        }
    }

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
