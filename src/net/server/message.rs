//! Support for working with DNS messages in servers.
use core::time::Duration;

use std::sync::{Arc, Mutex};

use tokio::time::Instant;

use crate::base::Message;

//------------ UdpTransportContext -------------------------------------------

/// Request context for a UDP transport.
#[derive(Clone, Debug, Default)]
pub struct UdpTransportContext {
    /// Optional maximum response size hint.
    max_response_size_hint: Arc<Mutex<Option<u16>>>,
}

impl UdpTransportContext {
    /// Creates a new UDP specific transport context.
    pub fn new(max_response_size_hint: Option<u16>) -> Self {
        let max_response_size_hint =
            Arc::new(Mutex::new(max_response_size_hint));

        Self {
            max_response_size_hint,
        }
    }
}

impl UdpTransportContext {
    /// Optional maximum response size hint.
    ///
    /// `None` if the server had no specific configuration regarding maximum
    /// allowed response size, `Some(n)` otherwise where `n` is the maximum
    /// number of bytes allowed for the response message.
    ///
    /// The [`EdnsMiddlewareSvc`] may adjust this limit.
    ///
    /// The [`MandatoryMiddlewareSvc`] enforces this limit.
    ///
    /// [`EdnsMiddlewareSvc`]:
    ///     crate::net::server::middleware::edns::EdnsMiddlewareSvc
    /// [`MandatoryMiddlewareSvc`]:
    ///     crate::net::server::middleware::mandatory::MandatoryMiddlewareSvc
    pub fn max_response_size_hint(&self) -> Option<u16> {
        *self.max_response_size_hint.lock().unwrap()
    }

    /// Sets the maximum response hint.
    pub fn set_max_response_size_hint(
        &self,
        max_response_size_hint: Option<u16>,
    ) {
        *self.max_response_size_hint.lock().unwrap() = max_response_size_hint;
    }
}

//------------ NonUdpTransportContext ----------------------------------------

/// Request context for a non-UDP transport.
#[derive(Clone, Copy, Debug)]
pub struct NonUdpTransportContext {
    /// Optional indication of any idle timeout relevant to the request.
    idle_timeout: Option<Duration>,
}

impl NonUdpTransportContext {
    /// Creates a new non-UDP specific transport context.
    pub fn new(idle_timeout: Option<Duration>) -> Self {
        Self { idle_timeout }
    }
}

impl NonUdpTransportContext {
    /// Optional indication of any idle timeout relevant to the request.
    ///
    /// A connection idle timeout such as the [RFC 7766 section 6.2.3] TCP
    /// idle timeout or edns-tcp-keepalive timeout [RFC 7828].
    ///
    /// This is provided by the server to indicate what the current timeout
    /// setting in effect is.
    ///
    /// The [`EdnsMiddlewareSvc`] may report this timeout value back to
    /// clients capable of interpreting it.
    ///
    /// [RFC 7766 section 6.2.3]:
    ///     https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
    /// [RFC 78828]: https://www.rfc-editor.org/rfc/rfc7828
    ///
    /// [`EdnsMiddlewareSvc`]:
    ///     crate::net::server::middleware::edns::EdnsMiddlewareSvc
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }
}

//------------ TransportSpecificContext --------------------------------------

/// Transport dependent context.
///
/// Knowing the context of a request may be needed in order to process it
/// correctly. Some kinds of contextual information are only available for
/// certain transport types.
///
/// Context values may be adjusted by processors in the middleware chain
/// and/or by the [`Service`] that receives the request, in order to influence
/// the behaviour of other processors, the service or the server.
///
/// [`Service`]: crate::net::server::service::Service
#[derive(Debug, Clone)]
pub enum TransportSpecificContext {
    /// Context for a UDP transport.
    Udp(UdpTransportContext),

    /// Context for a non-UDP transport.
    NonUdp(NonUdpTransportContext),
}

impl TransportSpecificContext {
    /// Was the message received over a UDP transport?
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }

    /// Was the message received over a non-UDP transport?
    pub fn is_non_udp(&self) -> bool {
        matches!(self, Self::NonUdp(_))
    }
}

//--- impl From<UdpTransportContext>

impl From<UdpTransportContext> for TransportSpecificContext {
    fn from(ctx: UdpTransportContext) -> Self {
        Self::Udp(ctx)
    }
}

//--- impl From<NonUdpTransportContext>

impl From<NonUdpTransportContext> for TransportSpecificContext {
    fn from(ctx: NonUdpTransportContext) -> Self {
        Self::NonUdp(ctx)
    }
}

//------------ Request -------------------------------------------------------

/// A DNS message with additional properties describing its context.
///
/// DNS messages don't exist in isolation, they are received from somewhere or
/// created by something. This type wraps a message with additional context
/// about its origins so that decisions can be taken based not just on the
/// message itself but also on the circumstances surrounding its creation and
/// delivery.
#[derive(Debug)]
pub struct Request<Octs, Metadata = ()>
where
    Octs: AsRef<[u8]> + Send + Sync,
{
    /// The network address of the connected client.
    client_addr: std::net::SocketAddr,

    /// The instant when the request was received.
    received_at: Instant,

    /// The message that was received.
    message: Arc<Message<Octs>>,

    /// Properties of the request specific to the server and transport
    /// protocol via which it was received.
    transport_specific: TransportSpecificContext,

    /// The number of bytes to be reserved when generating a response to this
    /// request so that needed additional data can be added to to the
    /// generated response.
    ///
    /// Note: This is only a hint to code that considers this value, it is
    /// still possible to generate responses that ignore this value.
    num_reserved_bytes: u16,

    /// user defined metadata to associate with the request.
    ///
    /// For example this could be used to pass data from one [middleware]
    /// [`Service`] impl to another.
    ///
    /// [middleware]: crate::net::server::middleware
    /// [`Service`]: crate::net::server::service::Service
    metadata: Metadata,
}

impl<Octs, Metadata> Request<Octs, Metadata>
where
    Octs: AsRef<[u8]> + Send + Sync,
{
    /// Creates a new request wrapper around a message along with its context.
    pub fn new(
        client_addr: std::net::SocketAddr,
        received_at: Instant,
        message: Message<Octs>,
        transport_specific: TransportSpecificContext,
        metadata: Metadata,
    ) -> Self {
        Self {
            client_addr,
            received_at,
            message: Arc::new(message),
            transport_specific,
            num_reserved_bytes: 0,
            metadata,
        }
    }

    /// When was this message received?
    pub fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Get a reference to the transport specific context
    pub fn transport_ctx(&self) -> &TransportSpecificContext {
        &self.transport_specific
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Read access to the inner message
    pub fn message(&self) -> &Arc<Message<Octs>> {
        &self.message
    }

    /// Request that an additional number of bytes be reserved in the response
    /// to this message.
    pub fn reserve_bytes(&mut self, len: u16) {
        self.num_reserved_bytes += len;
        tracing::trace!(
            "Reserved {len} bytes: total now = {}",
            self.num_reserved_bytes
        );
    }

    /// The number of bytes to reserve when generating a response to this
    /// message.
    pub fn num_reserved_bytes(&self) -> u16 {
        self.num_reserved_bytes
    }

    /// Set user defined metadata to associate with this request.
    pub fn with_new_metadata<T>(self, new_metadata: T) -> Request<Octs, T> {
        Request::<Octs, T> {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: self.message,
            transport_specific: self.transport_specific,
            num_reserved_bytes: self.num_reserved_bytes,
            metadata: new_metadata,
        }
    }

    /// Get the user defined metadata associated with this request.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

//--- Clone

impl<Octs, Metadata> Clone for Request<Octs, Metadata>
where
    Octs: AsRef<[u8]> + Send + Sync,
    Metadata: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: Arc::clone(&self.message),
            transport_specific: self.transport_specific.clone(),
            num_reserved_bytes: self.num_reserved_bytes,
            metadata: self.metadata.clone(),
        }
    }
}
