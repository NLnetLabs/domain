//! DNS server related metrics.

//------------ ServerMetrics -------------------------------------------------

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// Metrics common to all provided DNS server implementations.
#[derive(Debug)]
pub struct ServerMetrics {
    pub(super) num_connections: Option<AtomicUsize>,

    pub(super) num_inflight_requests: AtomicUsize,

    pub(super) num_pending_writes: AtomicUsize,
}

impl ServerMetrics {
    /// Constructs initial metrics for a connection-less server.
    pub fn connection_less() -> Self {
        Self {
            num_connections: None,
            num_inflight_requests: AtomicUsize::new(0),
            num_pending_writes: AtomicUsize::new(0),
        }
    }

    /// Constructs initial metrics for a connection-oriented server.
    pub fn connection_oriented() -> Self {
        Self {
            num_connections: Some(AtomicUsize::new(0)),
            num_inflight_requests: AtomicUsize::new(0),
            num_pending_writes: AtomicUsize::new(0),
        }
    }

    /// The number of current connections, if applicable.
    ///
    /// This will be None for connection-less servers such as [`DgramServer`].
    ///
    /// [`DgramServer`]: servers::dgram::server::DgramServer
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
}
