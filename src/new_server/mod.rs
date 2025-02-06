//! Responding to DNS requests.
//!
//! # Architecture
//!
//! A _transport_ implements a network interface allowing it to receive DNS
//! requests and return DNS responses.  Transports can be implemented on UDP,
//! TCP, TLS, etc., and users can implement their own transports.
//!
//! A _service_ implements the business logic of handling a DNS request and
//! building a DNS response.  A service can be composed of multiple _layers_,
//! each of which can inspect the request and prepare part of the response.
//! Many common layers are already implemented, but users can define more.

#![cfg(feature = "unstable-server-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-server-transport")))]

use core::{future::Future, ops::ControlFlow};

mod impls;

pub mod exchange;
pub use exchange::Exchange;
use exchange::OutgoingResponse;

pub mod transport;

pub mod layers;

//----------- Service --------------------------------------------------------

/// A (multi-threaded) DNS service, that computes responses for requests.
///
/// Given a DNS request message, a service computes an appropriate response.
/// Services are usually wrapped in a network transport that receives requests
/// and returns the service's responses.
///
/// Use [`LocalService`] for a single-threaded equivalent.
///
/// # Layering
///
/// Additional functionality can be added to a service by prefixing it with
/// service layers, usually in a tuple.  A number of blanket implementations
/// are provided to simplify this.
pub trait Service: LocalService + Sync {
    /// Respond to a DNS request.
    ///
    /// The returned [`Future`] is thread-safe; it implements [`Send`].  Use
    /// [`LocalService::respond_local()`] if this is not necessary.
    fn respond(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> impl Future<Output = ()> + Send;
}

//----------- LocalService ---------------------------------------------------

/// A (single-threaded) DNS service, that computes responses for requests.
///
/// Given a DNS request message, a service computes an appropriate response.
/// Services are usually wrapped in a network transport that receives requests
/// and returns the service's responses.
///
/// Use [`Service`] for a multi-threaded equivalent.
///
/// # Layering
///
/// Additional functionality can be added to a service by prefixing it with
/// service layers, usually in a tuple.  A number of blanket implementations
/// are provided to simplify this.
pub trait LocalService {
    /// Respond to a DNS request.
    ///
    /// The returned [`Future`] is thread-local; it does not implement
    /// [`Send`].  Use [`Service::respond()`] for a thread-safe alternative.
    fn respond_local(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> impl Future<Output = ()>;
}

//----------- ServiceLayer ---------------------------------------------------

/// A (multi-threaded) layer wrapping a DNS [`Service`].
///
/// A layer can be wrapped around a service, inspecting the requests sent to
/// it and transforming the responses returned by it.
///
/// Use [`LocalServiceLayer`] for a single-threaded equivalent.
///
/// # Combinations
///
/// Layers can be combined (usually in a tuple) into larger layers.  A number
/// of blanket implementations are provided to simplify this.
pub trait ServiceLayer: LocalServiceLayer + Sync {
    /// Process an incoming DNS request.
    ///
    /// The returned [`Future`] is thread-safe; it implements [`Send`].  Use
    /// [`LocalServiceLayer::process_local_incoming()`] if this is not
    /// necessary.
    fn process_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> impl Future<Output = ControlFlow<()>> + Send;

    /// Process an outgoing DNS response.
    ///
    /// The returned [`Future`] is thread-safe; it implements [`Send`].  Use
    /// [`LocalServiceLayer::process_local_outgoing()`] if this is not
    /// necessary.
    fn process_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) -> impl Future<Output = ()> + Send;
}

//----------- LocalServiceLayer ----------------------------------------------

/// A (single-threaded) layer wrapping a DNS [`Service`].
///
/// A layer can be wrapped around a service, inspecting the requests sent to
/// it and transforming the responses returned by it.
///
/// Use [`ServiceLayer`] for a multi-threaded equivalent.
///
/// # Combinations
///
/// Layers can be combined (usually in a tuple) into larger layers.  A number
/// of blanket implementations are provided to simplify this.
pub trait LocalServiceLayer {
    /// Process an incoming DNS request.
    ///
    /// The returned [`Future`] is thread-local; it does not implement
    /// [`Send`].  Use [`ServiceLayer::process_incoming()`] for a thread-safe
    /// alternative.
    fn process_local_incoming(
        &self,
        exchange: &mut Exchange<'_>,
    ) -> impl Future<Output = ControlFlow<()>>;

    /// Process an outgoing DNS response.
    ///
    /// The returned [`Future`] is thread-local; it does not implement
    /// [`Send`].  Use [`ServiceLayer::process_outgoing()`] for a thread-safe
    /// alternative.
    fn process_local_outgoing(
        &self,
        response: OutgoingResponse<'_, '_>,
    ) -> impl Future<Output = ()>;
}
