//! The core of the resolver.

use std::fmt;
use std::io;
use std::sync::Arc;
use tokio_core::reactor;
use super::conf::{ResolvConf, ResolvOptions};
use super::request::ServiceHandle;
use super::tcp::tcp_service;
use super::udp::udp_service;


//------------ Core ---------------------------------------------------------

/// The resolver core.
///
/// This type collects the sender sides of the channels to all the services
/// of this resolver plus an arc with the config.
#[derive(Clone)]
pub struct Core {
    udp: Vec<ServiceHandle>,
    tcp: Vec<ServiceHandle>,
    conf: Arc<ResolvConf>,
}

impl Core {
    /// Creates a new resolver core using the given reactor and config.
    pub fn new(reactor: &reactor::Handle, conf: ResolvConf)
               -> io::Result<Self> {
        let mut udp = Vec::new();
        let mut tcp = Vec::new();

        for server in &conf.servers {
            if let Some(service) = try!(udp_service(reactor.clone(),
                                                    &server)) {
                udp.push(service);
            }
            if let Some(service) = try!(tcp_service(reactor.clone(),
                                                    &server)) {
                tcp.push(service);
            }
        }

        Ok(Core {
            udp: udp,
            tcp: tcp,
            conf: Arc::new(conf)
        })
    }

    /// Returns a reference to the list of UDP service handles.
    pub fn udp(&self) -> &[ServiceHandle] {
        &self.udp
    }

    /// Returns a reference to the list of TCP service handles.
    pub fn tcp(&self) -> &[ServiceHandle] {
        &self.tcp
    }

    /// Returns a reference to the configuration of this core.
    pub fn conf(&self) -> &ResolvConf {
        &self.conf
    }

    /// Returns a reference to the configuration options of this core.
    pub fn options(&self) -> &ResolvOptions {
        &self.conf.options
    }

    /// Returns a clone of the configuration.
    pub fn clone_conf(&self) -> Arc<ResolvConf> {
        self.conf.clone()
    }
}


//--- Debug

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.conf.fmt(f)
    }
}

