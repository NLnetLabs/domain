//! Helper types for connection-based transports.

use std::net::SocketAddr;
use std::sync::mpsc;
use resolv::conf::ResolvConf;
use super::query::Query;
use super::sync::{RotorSender, SharedNotifier};


//------------ ConnTransportSeed --------------------------------------------

/// The seed for connection-based transports.
pub struct ConnTransportSeed {
    /// Address of the other side,
    pub addr: SocketAddr,

    /// Configuration.
    pub conf: ResolvConf,

    /// The receiving end of the command queue.
    pub commands: mpsc::Receiver<Query>,

    /// A sending end of the query queue.
    pub queries: RotorSender<Query>,

    /// A place to put a notifier.
    pub notifier: SharedNotifier
}

impl ConnTransportSeed {
    pub fn new(conf: ResolvConf, addr: SocketAddr,
               queries: RotorSender<Query>)
               -> (ConnTransportSeed, mpsc::Sender<Query>) {
        let (tx, rx) = mpsc::channel();
        (ConnTransportSeed { conf: conf, addr: addr, commands: rx,
                             queries: queries,
                             notifier: SharedNotifier::new() },
         tx)
    }

    pub fn notifier(&self) -> SharedNotifier {
        self.notifier.clone()
    }
}

