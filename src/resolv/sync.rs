//! A simple, synchronous resolver.

use super::conf::{ResolvConf, ResolvOptions};
use super::hosts::Hosts;


#[derive(Clone, Debug)]
pub struct Resolver {
    conf: ResolvConf,
    hosts: Hosts,
}

/// # Management
///
impl Resolver {
    pub fn new() -> Resolver {
        Resolver::from_conf(ResolvConf::default())
    }

    pub fn from_conf(conf: ResolvConf) -> Self {
        Resolver {
            conf: conf,
            hosts: Hosts::default()
        }
    }

    pub fn conf(&self) -> &ResolvConf { &self.conf }
    pub fn conf_mut(&mut self) -> &mut ResolvConf { &mut self.conf }

    pub fn options(&self) -> &ResolvOptions { &self.conf.options }
    pub fn options_mut(&mut self) -> &mut ResolvOptions {
        &mut self.conf.options
    }

    pub fn hosts(&self) -> &Hosts { &self.hosts }
    pub fn hosts_mut(&mut self) -> &mut Hosts { &mut self.hosts }
}

/// # Queries
///
impl Resolver {
    pub fn resolve_general(name: &str, rtype: RRType);
    pub fn resolve_address(name: &str);
    pub fn resolve_hostname(addr: &IpAddr);
    pub fn resolve_service(name: &str);
}


#[derive(Clone, Debug)]
pub enum Answer {
    Complete(Response),
    Timeout,
    Error(Error),
}

//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;

}
