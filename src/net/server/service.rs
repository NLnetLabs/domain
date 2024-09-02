//! The application logic of a DNS server.
//!
//! The [`Service::call`] function defines how the service should respond to a
//! given DNS request. resulting in a future that yields a stream of one or
//! more future DNS responses, and/or [`ServiceFeedback`].
use core::fmt::Display;
use core::ops::Deref;

use std::time::Duration;
use std::vec::Vec;

use crate::base::iana::Rcode;
use crate::base::message_builder::{AdditionalBuilder, PushError};
use crate::base::wire::ParseError;
use crate::base::StreamTarget;

use super::message::Request;

//------------ Service -------------------------------------------------------

/// The type of item that `Service` implementations stream as output.
pub type ServiceResult<Target> = Result<CallResult<Target>, ServiceError>;

/// `Service`s are responsible for determining how to respond to DNS requests.
///
/// For an overview of how services fit into the total flow of request and
/// response handling see the [`net::server`] module documentation.
///
/// Each `Service` implementation defines a [`call`] function which takes a
/// [`Request`] DNS request as input and returns a future that yields a stream
/// of one or more items each of which is either a [`CallResult`] or
/// [`ServiceError`].
///
/// Most DNS requests result in a single response, with the exception of AXFR
/// and IXFR requests which can result in a stream of responses.
///
/// # Usage
///
/// You can either implement the [`Service`] trait on a struct or use the
/// helper function [`service_fn`] to turn a function into a [`Service`].
///
/// # Implementing the `Service` trait on a `struct`
///
/// ```
/// use core::future::ready;
/// use core::future::Ready;
/// use core::pin::Pin;
///
/// use std::task::{Context, Poll};
///
/// use futures::stream::{once, Once, Stream};
///
/// use domain::base::iana::{Class, Rcode};
/// use domain::base::message_builder::AdditionalBuilder;
/// use domain::base::{Name, Message, MessageBuilder, StreamTarget};
/// use domain::net::server::message::Request;
/// use domain::net::server::service::{CallResult, Service, ServiceResult};
/// use domain::net::server::util::mk_builder_for_target;
/// use domain::rdata::A;
///
/// fn mk_answer(
///     msg: &Request<Vec<u8>>,
///     builder: MessageBuilder<StreamTarget<Vec<u8>>>,
/// ) -> AdditionalBuilder<StreamTarget<Vec<u8>>> {
///     let mut answer = builder
///         .start_answer(msg.message(), Rcode::NOERROR)
///         .unwrap();
///     answer.push((
///         Name::root_ref(),
///         Class::IN,
///         86400,
///         A::from_octets(192, 0, 2, 1),
///     )).unwrap();
///     answer.additional()
/// }
///
/// fn mk_response_stream(msg: &Request<Vec<u8>>)
///   -> Once<Ready<ServiceResult<Vec<u8>>>>
/// {
///     let builder = mk_builder_for_target();
///     let additional = mk_answer(msg, builder);
///     let item = Ok(CallResult::new(additional));
///     once(ready(item))
/// }
///
/// //------------ A synchronous service example ------------------------------
/// struct MySyncService;
///
/// impl Service<Vec<u8>> for MySyncService {
///     type Target = Vec<u8>;
///     type Stream = Once<Ready<ServiceResult<Self::Target>>>;
///     type Future = Ready<Self::Stream>;
///     
///     fn call(
///         &self,
///         msg: Request<Vec<u8>>,
///     ) -> Self::Future {
///         ready(mk_response_stream(&msg))
///     }
/// }
///
/// //------------ An anonymous async block service example -------------------
/// struct MyAsyncBlockService;
///
/// impl Service<Vec<u8>> for MyAsyncBlockService {
///     type Target = Vec<u8>;
///     type Stream = Once<Ready<ServiceResult<Self::Target>>>;
///     type Future = Pin<Box<dyn std::future::Future<Output = Self::Stream>>>;
///
///     fn call(
///         &self,
///         msg: Request<Vec<u8>>,
///     ) -> Self::Future {
///         Box::pin(async move { mk_response_stream(&msg) })
///     }
/// }
///
/// //------------ A named Future service example -----------------------------
/// struct MyFut(Request<Vec<u8>>);
///
/// impl std::future::Future for MyFut {
///     type Output = Once<Ready<ServiceResult<Vec<u8>>>>;
///
///     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
///         Poll::Ready(mk_response_stream(&self.0))
///     }
/// }
///
/// struct MyNamedFutureService;
///
/// impl Service<Vec<u8>> for MyNamedFutureService {
///     type Target = Vec<u8>;
///     type Stream = Once<Ready<ServiceResult<Self::Target>>>;
///     type Future = MyFut;
///     
///     fn call(&self, msg: Request<Vec<u8>>) -> Self::Future { MyFut(msg) }
/// }
/// ```
///
/// The above are minimalist examples to illustrate what you need to do, but
/// lacking any actual useful behaviour. They also only demonstrate returning
/// a response stream containing a single immediately available value via
/// `futures::stream::Once` and `std::future::Ready`.
///
/// In your own [`Service`] impl you would implement actual business logic
/// returning single or multiple responses synchronously or asynchronously as
/// needed.
///
/// # Advanced usage
///
/// The [`Service`] trait takes two generic types which in most cases you
/// don't need to specify as the defaults will be fine.
///
/// For more advanced cases you may need to override these defaults.
///
/// - `RequestMeta`: If implementing a [middleware] `Service` you may need to
///   supply your own `RequestMeta` type. `RequestMeta` is intended to enable
///   middleware `Service` impls to express strongly typed support for
///   middleware specific data that can be consumed by upstream middleware, or
///   even by your application service. For example a middleware `Service` may
///   detect that the request is signed using a particular key and communicate
///   the name of the key to any upstream `Service` that needs to know the
///   name of the key used to sign the request.
///
/// - `RequestOctets`: By specifying your own `RequestOctets` type you can use
///   a type other than `Vec<u8>` to transport request bytes through your
///   application.
///
/// [`DgramServer`]: crate::net::server::dgram::DgramServer
/// [`StreamServer`]: crate::net::server::stream::StreamServer
/// [middleware]: crate::net::server::middleware
/// [`net::server`]: crate::net::server
/// [`call`]: Self::call()
/// [`service_fn`]: crate::net::server::util::service_fn()
pub trait Service<
    RequestOctets: AsRef<[u8]> + Send + Sync = Vec<u8>,
    RequestMeta: Clone + Default = (),
>
{
    /// The underlying byte storage type used to hold generated responses.
    type Target;

    /// The type of stream that the service produces.
    type Stream: futures::stream::Stream<Item = ServiceResult<Self::Target>>
        + Unpin;

    /// The type of future that will yield the service result stream.
    type Future: core::future::Future<Output = Self::Stream>;

    /// Generate a response to a fully pre-processed request.
    fn call(
        &self,
        request: Request<RequestOctets, RequestMeta>,
    ) -> Self::Future;
}

//--- impl Service for Deref

/// Helper trait impl to treat a [`Deref<Target = impl Service>`] as a [`Service`].
impl<RequestOctets, RequestMeta, T, U> Service<RequestOctets, RequestMeta>
    for U
where
    RequestOctets: Unpin + Send + Sync + AsRef<[u8]>,
    T: ?Sized + Service<RequestOctets, RequestMeta>,
    U: Deref<Target = T> + Clone,
    RequestMeta: Clone + Default,
{
    type Target = T::Target;
    type Stream = T::Stream;
    type Future = T::Future;

    fn call(
        &self,
        request: Request<RequestOctets, RequestMeta>,
    ) -> Self::Future {
        (**self).call(request)
    }
}

//------------ ServiceError --------------------------------------------------

/// An error reported by a `Service`.
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

/// Feedback from a `Service` to a server asking it to do something.
#[derive(Copy, Clone, Debug)]
pub enum ServiceFeedback {
    /// Ask the server to alter its configuration. For connection-oriented
    /// servers the changes will only apply to the current connection.
    Reconfigure {
        /// If `Some`, the new idle timeout the `Service` would like the
        /// server to use.
        idle_timeout: Option<Duration>,
    },

    /// Ask the server to wait much longer for responses than it usually would
    /// in order to ensure that an entire set of related response messages are
    /// all sent back to the caller rather than being dropped if the outgoing
    /// queue is full.
    BeginTransaction,

    /// Signal to the server that the transaction that we began has ended.
    EndTransaction,
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

    /// Optional feedback from the `Service` to the server.
    feedback: Option<ServiceFeedback>,
}

impl<Target> CallResult<Target> {
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
    pub fn response(
        &self,
    ) -> Option<&AdditionalBuilder<StreamTarget<Target>>> {
        self.response.as_ref()
    }

    /// Get a mutable reference to the contained DNS response message, if any.
    #[must_use]
    pub fn response_mut(
        &mut self,
    ) -> Option<&mut AdditionalBuilder<StreamTarget<Target>>> {
        self.response.as_mut()
    }

    /// Convert the [`CallResult`] into the contained DNS response message and command.
    #[must_use]
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
