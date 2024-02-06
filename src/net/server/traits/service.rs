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

use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};

use super::message::ContextAwareMessage;

//------------ Service -------------------------------------------------------

pub type ServiceResultItem<Target, Error> =
    Result<CallResult<Target>, ServiceError<Error>>;
pub type ServiceResult<Target, Error, Single> = Result<
    Transaction<ServiceResultItem<Target, Error>, Single>,
    ServiceError<Error>,
>;

/// A Service is responsible for generating responses to received DNS messages.
///
/// Each [`Service`] implements a single [`Self::call()`] function which takes a DNS
/// request [`Message`] and returns either a [`Transaction`] on success, or a
/// [`ServiceError`] on failure.
///
/// Responses are encapsulated inside a [`Transaction`] which is either a single response, or a stream of responses (e.g. for a zone
/// transfer), where each response is a [`std::future::Future`] that resolves to a [`CallResult`].
///
/// In the common case a [`CallResult`] is a DNS response message. For some
/// advanced use cases it can instead, or additionally, direct the server
/// handling the request (or a single connection it is handling) to adjust its
/// own configuration, or even to terminate the connection.
///
/// You can either implement the [`Service`] trait directly, or use the blanket
/// impl to turn any function with a compatible signature into a [`Service`]
/// implementation like so:
///
/// ```ignore
/// fn simple_service() -> impl Service<Vec<u8>, Message<Vec<u8>>> {
///     type MyServiceResult = ServiceResult<Vec<u8>, ServiceError<()>>;
///
///     fn query(msg: Message<Vec<u8>>) -> Transaction<
///         impl Future<Output = MyServiceResult>,
///         Once<Pending<MyServiceResult>>,
///     > {
///         Transaction::Single(async move {
///             let res = MessageBuilder::new_vec();
///             let mut answer = res.start_answer(&msg, Rcode::NoError).unwrap();
///             answer
///                 .push((
///                     Dname::root_ref(),
///                     Class::In,
///                     86400,
///                     A::from_octets(192, 0, 2, 1),
///                 ))
///                 .unwrap();
///
///             let mut target = StreamTarget::new_vec();
///             target
///                 .append_slice(&answer.into_message().into_octets())
///                 .map_err(|err| ServiceError::Other(err.to_string()))?;
///             Ok(CallResult::new(target))
///         })
///     }
///
///     |msg| Ok(query(msg))
/// }
///
/// let service: Service = simple_service().into();
/// ```
/// 
/// [`CallResult`]: crate::net::server::traits::service::CallResult
pub trait Service<RequestOctets: AsRef<[u8]> = Vec<u8>> {
    type Error: Send + Sync + 'static;
    type Target: Composer + Default + Send + Sync + 'static;
    type Single: Future<Output = ServiceResultItem<Self::Target, Self::Error>>;

    #[allow(clippy::type_complexity)]
    fn call(
        &self,
        message: Arc<ContextAwareMessage<Message<RequestOctets>>>,
    ) -> ServiceResult<Self::Target, Self::Error, Self::Single>
    where
        <Self as Service<RequestOctets>>::Single: core::marker::Send;
}

impl<F, Error, RequestOctets, Target, Single> Service<RequestOctets> for F
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

#[derive(Debug)]
pub enum ServiceError<T> {
    ServiceSpecificError(T),
    ShuttingDown,
    Other(String),
}

impl<T> core::fmt::Display for ServiceError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
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

//------------ ServiceCommand ------------------------------------------------

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

pub struct CallResult<Target> {
    pub response: AdditionalBuilder<StreamTarget<Target>>,
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
    pub fn new(response: AdditionalBuilder<StreamTarget<Target>>) -> Self {
        Self {
            response,
            command: None,
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
