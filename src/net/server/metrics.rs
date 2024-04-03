//! DNS server related metrics.

//------------ ServerMetrics -------------------------------------------------

use std::sync::atomic::{AtomicUsize, Ordering};

/// Metrics common to all provided DNS server implementations.
///
/// Server metrics should track values that cannot be known and exposed by the
/// [`Service`] implementation.
///
/// [`Service`]: crate::net::server::service::Service
#[derive(Debug, Default)]
pub struct ServerMetrics {
    /// The number of connections currently being handled.
    num_connections: Option<AtomicUsize>,

    /// The number of requests received but still pending responses.
    num_inflight_requests: AtomicUsize,

    /// The number of responses waiting to be written back to the client.
    num_pending_writes: AtomicUsize,

    /// The total number of requests received since this metric collection was created.
    num_received_requests: AtomicUsize,

    /// The total number of responses sent since this metric collection was created.
    num_sent_responses: AtomicUsize,
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
}

impl ServerMetrics {
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

    /// Set the number of current connections metric.
    pub fn set_num_connections(&self, new_value: usize) {
        if let Some(num_connections) = &self.num_connections {
            num_connections.store(new_value, Ordering::Relaxed);
        }
    }

    /// Increment the number of current connections metric.
    pub fn inc_num_connections(&self) {
        if let Some(num_connections) = &self.num_connections {
            num_connections.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Decrement the number of current connections metric.
    pub fn dec_num_connections(&self) {
        if let Some(num_connections) = &self.num_connections {
            num_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl ServerMetrics {
    /// The number of requests received but not yet responded to.
    pub fn num_inflight_requests(&self) -> usize {
        self.num_inflight_requests.load(Ordering::Relaxed)
    }

    /// Set the number of inflight requests metric.
    pub fn set_num_inflight_requests(&self, new_value: usize) {
        self.num_inflight_requests
            .store(new_value, Ordering::Relaxed);
    }

    /// Increment the number of inflight requests metric.
    pub fn inc_num_inflight_requests(&self) {
        self.num_inflight_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the number of inflight requests metric.
    pub fn dec_num_inflight_requests(&self) {
        self.num_inflight_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServerMetrics {
    /// The number of responses generated but not yet sent back to the client.
    pub fn num_pending_writes(&self) -> usize {
        self.num_pending_writes.load(Ordering::Relaxed)
    }

    /// Set the number of inflight requests metric.
    pub fn set_num_pending_writes(&self, new_value: usize) {
        self.num_pending_writes.store(new_value, Ordering::Relaxed);
    }

    /// Increment the number of pending writes metric.
    pub fn inc_num_pending_writes(&self) {
        self.num_pending_writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the number of pending writes metric.
    pub fn dec_num_pending_writes(&self) {
        self.num_pending_writes.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServerMetrics {
    /// The number of DNS requests received.
    pub fn num_received_requests(&self) -> usize {
        self.num_received_requests.load(Ordering::Relaxed)
    }

    /// Set the number of received requests metric.
    pub fn set_num_received_requests(&self, new_value: usize) {
        self.num_received_requests
            .store(new_value, Ordering::Relaxed);
    }

    /// Increment the number of received requests metric.
    pub fn inc_num_received_requests(&self) {
        self.num_received_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the number of received requests metric.
    pub fn dec_num_received_requests(&self) {
        self.num_received_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServerMetrics {
    /// The number of DNS responses sent.
    pub fn num_sent_responses(&self) -> usize {
        self.num_sent_responses.load(Ordering::Relaxed)
    }

    /// Set the number of sent resposnes metric.
    pub fn set_num_sent_responses(&self, new_value: usize) {
        self.num_sent_responses.store(new_value, Ordering::Relaxed);
    }

    /// Increment the number of sent responses metric.
    pub fn inc_num_sent_responses(&self) {
        self.num_sent_responses.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the number of sent responses metric.
    pub fn dec_num_sent_responses(&self) {
        self.num_sent_responses.fetch_sub(1, Ordering::Relaxed);
    }
}
