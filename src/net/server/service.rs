//! The application logic of a DNS server.
//!
//! The [`Service::call`] function defines how the service should respond to a
//! given DNS request. resulting in a [`Transaction`] containing a transaction
//! that yields one or more future DNS responses, and/or a
//! [`ServiceFeedback`].
use core::fmt::Display;
use core::ops::Deref;

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use futures_util::stream::FuturesOrdered;
use futures_util::{FutureExt, StreamExt};

use super::message::Request;
use crate::base::iana::Rcode;
use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::ParseError;
use crate::base::StreamTarget;
use octseq::{OctetsBuilder, ShortBuf};

//------------ Service -------------------------------------------------------

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
/// Each [`Service`] implementation defines a [`call`] function which takes a
/// [`Request`] DNS request as input and returns either a [`Transaction`] on
/// success, or a [`ServiceError`] on failure, as output.
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
///   3. Define a function compatible with [`service_fn`].
///
/// <div class="warning">
///
/// Whichever approach you choose it is important to minimize the work done
/// before returning from [`Service::call`], as time spent here blocks the
/// caller. Instead as much work as possible should be delegated to the
/// futures returned as a [`Transaction`].
///
/// </div>
///
/// # Implementing the [`Service`] trait on a `struct`
///
/// ```
/// use core::future::ready;
/// use core::future::Ready;
///
/// use domain::base::iana::{Class, Rcode};
/// use domain::base::message_builder::AdditionalBuilder;
/// use domain::base::{Dname, Message, MessageBuilder, StreamTarget};
/// use domain::net::server::message::Request;
/// use domain::net::server::service::{
///     CallResult, Service, ServiceError, Transaction
/// };
/// use domain::net::server::util::mk_builder_for_target;
/// use domain::rdata::A;
///
/// fn mk_answer(
///     msg: &Request<Vec<u8>>,
///     builder: MessageBuilder<StreamTarget<Vec<u8>>>,
/// ) -> Result<AdditionalBuilder<StreamTarget<Vec<u8>>>, ServiceError> {
///     let mut answer = builder.start_answer(msg.message(), Rcode::NOERROR)?;
///     answer.push((
///         Dname::root_ref(),
///         Class::IN,
///         86400,
///         A::from_octets(192, 0, 2, 1),
///     ))?;
///     Ok(answer.additional())
/// }
///
/// struct MyService;
///
/// impl Service<Vec<u8>> for MyService {
///     type Target = Vec<u8>;
///     type Future = Ready<Result<CallResult<Self::Target>, ServiceError>>;
///
///     fn call(
///         &self,
///         msg: Request<Vec<u8>>,
///     ) -> Result<Transaction<Self::Target, Self::Future>, ServiceError> {
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
/// use core::fmt::Debug;
/// use core::future::ready;
/// use core::future::Future;
///
/// use domain::base::{Dname, Message};
/// use domain::base::iana::{Class, Rcode};
/// use domain::base::name::ToLabelIter;
/// use domain::base::wire::Composer;
/// use domain::dep::octseq::{OctetsBuilder, FreezeBuilder, Octets};
/// use domain::net::server::message::Request;
/// use domain::net::server::service::{CallResult, ServiceError, Transaction};
/// use domain::net::server::util::mk_builder_for_target;
/// use domain::rdata::A;
///
/// fn name_to_ip<Target>(
///     msg: Request<Vec<u8>>,
/// ) -> Result<
///     Transaction<Target,
///         impl Future<
///             Output = Result<CallResult<Target>, ServiceError>
///         > + Send,
///     >,
///     ServiceError,
/// >
/// where
///     Target: Composer + Octets + FreezeBuilder<Octets = Target> + Default + Send,
///     <Target as OctetsBuilder>::AppendError: Debug,
/// {
///     let mut out_answer = None;
///     if let Ok(question) = msg.message().sole_question() {
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
///                     builder
///                         .start_answer(msg.message(), Rcode::NOERROR)
///                         .unwrap();
///                 answer
///                     .push((Dname::root_ref(), Class::IN, 86400, a_rec))
///                     .unwrap();
///                 out_answer = Some(answer);
///             }
///         }
///     }
///
///     if out_answer.is_none() {
///         let builder = mk_builder_for_target();
///         let answer = builder
///             .start_answer(msg.message(), Rcode::REFUSED)
///             .unwrap();
///         out_answer = Some(answer);
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
/// # Define a function compatible with [`service_fn`]
///
/// See [`service_fn`] for an example of how to use it to create a [`Service`]
/// impl from a funciton.
///
/// [`MiddlewareChain`]:
///     crate::net::server::middleware::chain::MiddlewareChain
/// [`DgramServer`]: crate::net::server::dgram::DgramServer
/// [`StreamServer`]: crate::net::server::stream::StreamServer
/// [net::server module documentation]: crate::net::server
/// [`call`]: Self::call()
/// [`service_fn`]: crate::net::server::util::service_fn()
pub trait Service<RequestOctets: AsRef<[u8]> = Vec<u8>> {
    /// The type of buffer in which response messages are stored.
    type Target;

    /// The type of future returned by [`Service::call`] via
    /// [`Transaction::single`].
    type Future: std::future::Future<
        Output = Result<CallResult<Self::Target>, ServiceError>,
    >;

    /// Generate a response to a fully pre-processed request.
    #[allow(clippy::type_complexity)]
    fn call(
        &self,
        request: Request<RequestOctets>,
    ) -> Result<Transaction<Self::Target, Self::Future>, ServiceError>;
}

/// Helper trait impl to treat an [`Arc<impl Service>`] as a [`Service`].
impl<RequestOctets: AsRef<[u8]>, T: Service<RequestOctets>>
    Service<RequestOctets> for Arc<T>
{
    type Target = T::Target;
    type Future = T::Future;

    fn call(
        &self,
        request: Request<RequestOctets>,
    ) -> Result<Transaction<Self::Target, Self::Future>, ServiceError> {
        Arc::deref(self).call(request)
    }
}

/// Helper trait impl to treat a function as a [`Service`].
impl<RequestOctets, Target, Future, F> Service<RequestOctets> for F
where
    F: Fn(
        Request<RequestOctets>,
    ) -> Result<Transaction<Target, Future>, ServiceError>,
    RequestOctets: AsRef<[u8]>,
    Future: std::future::Future<
        Output = Result<CallResult<Target>, ServiceError>,
    >,
{
    type Target = Target;
    type Future = Future;

    fn call(
        &self,
        request: Request<RequestOctets>,
    ) -> Result<Transaction<Self::Target, Self::Future>, ServiceError> {
        (*self)(request)
    }
}

//------------ ServiceError --------------------------------------------------

/// An error reported by a [`Service`].
#[derive(Debug)]
pub enum ServiceError {
    /// The service was unable to parse the request.
    FormatError,

    /// The service encountered a service-specific error condition.
    InternalError,

    /// The service was unable to assemble the response.
    NotImplemented,

    /// The service declined to handle the request.
    Refused,
}

impl ServiceError {
    /// The DNS RCODE to send back to the client for this error.
    pub fn rcode(&self) -> Rcode {
        match self {
            Self::FormatError => Rcode::FORMERR,
            Self::InternalError => Rcode::SERVFAIL,
            Self::NotImplemented => Rcode::NOTIMP,
            Self::Refused => Rcode::REFUSED,
        }
    }
}

//--- Display

impl Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FormatError => write!(f, "Format error"),
            Self::InternalError => write!(f, "Internal error"),
            Self::NotImplemented => write!(f, "Not implemented"),
            Self::Refused => write!(f, "Refused"),
        }
    }
}

//--- From<PushError>

impl From<PushError> for ServiceError {
    fn from(_: PushError) -> Self {
        Self::InternalError
    }
}

//--- From<ParseError>

impl From<ParseError> for ServiceError {
    fn from(_: ParseError) -> Self {
        Self::FormatError
    }
}

//------------ ServiceFeedback -----------------------------------------------

/// Feedback from a [`Service`] to a server asking it to do something.
#[derive(Copy, Clone, Debug)]
pub enum ServiceFeedback {
    /// Ask the server to alter its configuration. For connection-oriented
    /// servers the changes will only apply to the current connection.
    Reconfigure {
        /// If `Some`, the new idle timeout the [`Service`] would like the
        /// server to use.
        idle_timeout: Option<Duration>,
    },
}

//------------ CallResult ----------------------------------------------------

/// The result of processing a DNS request via [`Service::call`].
///
/// Directions to a server on how to respond to a request.
///
/// In most cases a [`CallResult`] will be a DNS response message.
///
/// If needed a [`CallResult`] can instead, or additionally, contain a
/// [`ServiceFeedback`] directing the server or connection handler handling
/// the request to adjust its own configuration, or even to terminate the
/// connection.
#[derive(Clone, Debug)]
pub struct CallResult<Target> {
    /// Optional response to send back to the client.
    response: Option<AdditionalBuilder<StreamTarget<Target>>>,

    /// Optioanl feedback from the [`Service`] to the server.
    feedback: Option<ServiceFeedback>,
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
            feedback: None,
        }
    }

    /// Construct a [`CallResult`] from a [`ServiceFeedback`].
    #[must_use]
    pub fn feedback_only(command: ServiceFeedback) -> Self {
        Self {
            response: None,
            feedback: Some(command),
        }
    }

    /// Add a [`ServiceFeedback`] to an existing [`CallResult`].
    #[must_use]
    pub fn with_feedback(mut self, feedback: ServiceFeedback) -> Self {
        self.feedback = Some(feedback);
        self
    }

    /// Get the contained feedback, if any.
    #[must_use]
    pub fn feedback(&self) -> Option<ServiceFeedback> {
        self.feedback
    }

    /// Get a mutable reference to the contained DNS response message, if any.
    #[must_use]
    pub fn get_response_mut(
        &mut self,
    ) -> Option<&mut AdditionalBuilder<StreamTarget<Target>>> {
        self.response.as_mut()
    }

    /// Convert the [`CallResult`] into the contained DNS response message and command.
    #[must_use]
    #[allow(clippy::type_complexity)]
    pub fn into_inner(
        self,
    ) -> (
        Option<AdditionalBuilder<StreamTarget<Target>>>,
        Option<ServiceFeedback>,
    ) {
        let CallResult { response, feedback } = self;
        (response, feedback)
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
///   - Construct a transaction for a [`single`] response future, OR
///   - Construct a transaction [`stream`] and [`push`] response futures into
///     it.
///
/// Then iterate over the response futures one at a time using [`next`].
///
/// [`single`]: Self::single()
/// [`stream`]: Self::stream()
/// [`push`]: TransactionStream::push()
/// [`next`]: Self::next()
pub struct Transaction<Target, Future>(TransactionInner<Target, Future>)
where
    Future: std::future::Future<
        Output = Result<CallResult<Target>, ServiceError>,
    >;

impl<Target, Future> Transaction<Target, Future>
where
    Future: std::future::Future<
        Output = Result<CallResult<Target>, ServiceError>,
    >,
{
    /// Construct a transaction for a single immediate response.
    pub(crate) fn immediate(
        item: Result<CallResult<Target>, ServiceError>,
    ) -> Self {
        Self(TransactionInner::Immediate(Some(item)))
    }

    /// Construct an empty transaction.
    pub fn empty() -> Self {
        Self(TransactionInner::Single(None))
    }

    /// Construct a transaction for a single response future.
    pub fn single(fut: Future) -> Self {
        Self(TransactionInner::Single(Some(fut)))
    }

    /// Construct a transaction for a future stream of response futures.
    ///
    /// The given future should build the stream of response futures that will
    /// eventually be resolved by [`Self::next`].
    ///
    /// This takes a future instead of a [`TransactionStream`] because the
    /// caller may not yet know how many futures they need to push into the
    /// stream and we don't want them to block us while they work that out.
    pub fn stream(
        fut: Pin<
            Box<dyn std::future::Future<Output = Stream<Target>> + Send>,
        >,
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
    pub async fn next(
        &mut self,
    ) -> Option<Result<CallResult<Target>, ServiceError>> {
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

//------------ TransactionInner ----------------------------------------------

/// Private inner details of the [`Transaction`] type.
///
/// This type exists to (a) hide the `Immediate` variant from the consumer of
/// this library as it is for internal use only and not something a
/// [`Service`] impl should return, and (b) to control the interface offered
/// to consumers of this type and avoid them having to work with the enum
/// variants directly.
enum TransactionInner<Target, Future>
where
    Future: std::future::Future<
        Output = Result<CallResult<Target>, ServiceError>,
    >,
{
    /// The transaction will result in a single immediate response.
    ///
    /// This variant is for internal use only when aborting Middleware
    /// processing early.
    Immediate(Option<Result<CallResult<Target>, ServiceError>>),

    /// The transaction will result in at most a single response future.
    Single(Option<Future>),

    /// The transaction will result in stream of multiple response futures.
    PendingStream(
        Pin<Box<dyn std::future::Future<Output = Stream<Target>> + Send>>,
    ),

    /// The transaction is a stream of multiple response futures.
    Stream(Stream<Target>),
}

//------------ TransacationStream --------------------------------------------

/// A [`TransactionStream`] of [`Service`] results.
type Stream<Target> =
    TransactionStream<Result<CallResult<Target>, ServiceError>>;

/// A stream of zero or more DNS response futures relating to a single DNS request.
pub struct TransactionStream<Item> {
    /// An ordered sequence of futures that will resolve to responses to be
    /// sent back to the client.
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

    /// Fetch the next message from the stream, if any.
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

impl<Item> std::fmt::Debug for TransactionStream<Item> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TransactionStream").finish()
    }
}
