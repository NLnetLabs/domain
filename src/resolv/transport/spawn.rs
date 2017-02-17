//! The `spawn_transport()` function for starting transport and what it needs.

use tokio_core::reactor;
use super::super::channel::Channel;
use super::super::conf::ServerConf;
use super::super::request::TransportHandle;
use super::super::conf::ServerMode;
use super::{single, sequential, multiplex};


//------------ spawn_transport -----------------------------------------------

/// Spawns a new transport and returns a handle to it.
///
/// The transport will be spawned into `reactor` which will also be used by
/// both the transport and the underlying channel given by `channel`. The
/// strategy for dispatching messages is given through `mode`. Any additional
/// information that the transport may need is taken from `conf`.
///
/// The function returns a transport handle for dispatching requests to the
/// newly spawned transport.
pub fn spawn_transport<C>(reactor: &reactor::Handle, channel: C,
                          mode: TransportMode, conf: &ServerConf)
                          -> TransportHandle
                       where C : Channel + 'static {
    let (tx, rx) = TransportHandle::channel();
    match mode {
        TransportMode::SingleRequest
            => single::Transport::spawn(rx, channel, reactor, conf),
        TransportMode::Sequential
            => sequential::Transport::spawn(rx, channel, reactor, conf),
        TransportMode::Multiplex
            => multiplex::Transport::spawn(rx, channel, reactor, conf)
    }
    tx
}


//------------ TransportMode -------------------------------------------------

/// The mode a transport will operate in.
///
/// This is essientally `conf::ServerMode` stripped off the the variants that
/// a real transport can’t have.
#[derive(Clone, Copy, Debug)]
pub enum TransportMode {
    SingleRequest,
    Sequential,
    Multiplex,
}

impl TransportMode {
    /// Returns the `TransportMode` for a given `ServerMode`.
    ///
    /// Since `ServerMode` has both a `None` and a `Default` variant,
    /// this function takes the service mode to use by default and returns
    /// an option for the `None` case.
    pub fn resolve(mode: ServerMode, default: Option<Self>) -> Option<Self> {
        match mode {
            ServerMode::None => None,
            ServerMode::Default => default,
            ServerMode::SingleRequest => Some(TransportMode::SingleRequest),
            ServerMode::Sequential => Some(TransportMode::Sequential),
            ServerMode::Multiplex => Some(TransportMode::Multiplex)
        }
    }
}

