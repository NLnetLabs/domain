//! DNS server related metrics.

//------------ ServerMetrics -------------------------------------------------

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// Metrics common to all provided DNS server implementations.
///
/// Server metrics should track values that cannot be known and exposed by the
/// [`Service`] implementation.
///
/// [`Service`]: crate::net::server::service::Service
#[derive(Debug, Default)]
pub struct ServerMetrics {
    pub(super) num_connections: Option<AtomicUsize>,

    pub(super) num_inflight_requests: AtomicUsize,

    pub(super) num_pending_writes: AtomicUsize,

    pub(super) num_received_requests: AtomicUsize,

    pub(super) num_sent_responses: AtomicUsize,
}

impl ServerMetrics {
    /// Constructs initial metrics for a connection-less server.
    pub fn connection_less() -> Self {
        Self {
            num_connections: None,
            ..Default::default()
        }
    }

    /// Constructs initial metrics for a connection-oriented server.
    pub fn connection_oriented() -> Self {
        Self {
            num_connections: Some(AtomicUsize::new(0)),
            ..Default::default()
        }
    }

    /// The number of current connections, if applicable.
    ///
    /// This will be None for connection-less servers such as [`DgramServer`].
    ///
    /// [`DgramServer`]: crate::net::server::dgram::DgramServer
    pub fn num_connections(&self) -> Option<usize> {
        self.num_connections
            .as_ref()
            .map(|atomic| atomic.load(Ordering::Relaxed))
    }

    /// The number of requests received but not yet responded to.
    pub fn num_inflight_requests(&self) -> usize {
        self.num_inflight_requests.load(Ordering::Relaxed)
    }

    /// The number of responses generated but not yet sent back to the client.
    pub fn num_pending_writes(&self) -> usize {
        self.num_pending_writes.load(Ordering::Relaxed)
    }

    /// The number of DNS requests received.
    pub fn num_received_requests(&self) -> usize {
        self.num_received_requests.load(Ordering::Relaxed)
    }

    /// The number of DNS responses sent.
    pub fn num_sent_responses(&self) -> usize {
        self.num_sent_responses.load(Ordering::Relaxed)
    }
}
