use std::{io, ops};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::vec::Vec;
use tokio::time::timeout;
use super::conf::{ResolvConf, ServerConf, Transport};
use super::resolver::{Answer, QueryMessage};

mod tcp;
mod udp;


//------------ ServerInfo ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerInfo {
    /// The basic server configuration.
    conf: ServerConf,

    /// Whether this server supports EDNS.
    ///
    /// We start out with assuming it does and unset it if we get a FORMERR.
    edns: Arc<AtomicBool>,
}

impl ServerInfo {
    pub fn conf(&self) -> &ServerConf {
        &self.conf
    }

    pub fn does_edns(&self) -> bool {
        self.edns.load(Ordering::Relaxed)
    }
        
    pub fn disable_edns(&self) {
        self.edns.store(false, Ordering::Relaxed);
    }

    pub fn prepare_message(&self, query: &mut QueryMessage) {
        query.rewind();
        if self.does_edns() {
            query.opt(|opt| {
                // These are the values that Unbound uses.
                // XXX Perhaps this should be configurable.
                opt.set_udp_payload_size(
                    match self.conf.addr {
                        SocketAddr::V4(_) => 1472,
                        SocketAddr::V6(_) => 1232
                    }
                );
                Ok(())
            }).unwrap();
        }
    }

    pub async fn query(
        &self, query: &QueryMessage
    ) -> Result<Answer, io::Error> {
        let res = match self.conf.transport {
            Transport::Udp => {
               timeout(
                   self.conf.request_timeout,
                   udp::query(query, self.conf.addr, self.conf.recv_size)
                ).await
            }
            Transport::Tcp => {
               timeout(
                   self.conf.request_timeout,
                   tcp::query(query, self.conf.addr)
                ).await
            }
        };
        match res {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(err)) => Err(err),
            Err(_) => {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "request timed out"
                ))
            }
        }
    }
}

impl From<ServerConf> for ServerInfo {
    fn from(conf: ServerConf) -> Self {
        ServerInfo {
            conf,
            edns: Arc::new(AtomicBool::new(true))
        }
    }
}

impl<'a> From<&'a ServerConf> for ServerInfo {
    fn from(conf: &'a ServerConf) -> Self {
        conf.clone().into()
    }
}


//------------ ServerList ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerList {
    /// The actual list of servers.
    servers: Vec<ServerInfo>,

    /// Where to start accessing the list.
    ///
    /// In rotate mode, this value will always keep growing and will have to
    /// be used modulo `servers`’s length.
    ///
    /// When it eventually wraps around the end of usize’s range, there will
    /// be a jump in rotation. Since that will happen only oh-so-often, we
    /// accept that in favour of simpler code.
    start: Arc<AtomicUsize>,
}

impl ServerList {
    pub fn from_conf<F>(conf: &ResolvConf, filter: F) -> Self
    where F: Fn(&ServerConf) -> bool {
        ServerList {
            servers: {
                conf.servers.iter().filter(|f| filter(*f))
                    .map(Into::into).collect()
            },
            start: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    pub fn counter(&self, rotate: bool) -> ServerListCounter {
        let res = ServerListCounter::new(self);
        if rotate {
            self.rotate()
        }
        res
    }

    pub fn iter(&self) -> ServerListIter {
        ServerListIter::new(self)
    }

    pub fn rotate(&self) {
        self.start.fetch_add(1, Ordering::SeqCst);
    }
}

impl<'a> IntoIterator for &'a ServerList {
    type Item = &'a ServerInfo;
    type IntoIter = ServerListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl ops::Deref for ServerList {
    type Target = [ServerInfo];

    fn deref(&self) -> &Self::Target {
        self.servers.as_ref()
    }
}


//------------ ServerListCounter ---------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerListCounter {
    cur: usize,
    end: usize,
}

impl ServerListCounter {
    fn new(list: &ServerList) -> Self {
        if list.servers.is_empty() {
            return ServerListCounter { cur: 0, end: 0 };
        }

        // We modulo the start value here to prevent hick-ups towards the
        // end of usize’s range.
        let start = list.start.load(Ordering::Relaxed) % list.servers.len();
        ServerListCounter {
            cur: start,
            end: start + list.servers.len(),
        }
    }

    pub fn next(&mut self) -> bool {
        let next = self.cur + 1;
        if next < self.end {
            self.cur = next;
            true
        }
        else {
            false
        }
    }

    pub fn info<'a>(&self, list: &'a ServerList) -> &'a ServerInfo {
        &list[self.cur % list.servers.len()]
    }
}



//------------ ServerListIter ------------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerListIter<'a> {
    servers: &'a ServerList,
    counter: ServerListCounter,
}

impl<'a> ServerListIter<'a> {
    fn new(list: &'a ServerList) -> Self {
        ServerListIter {
            servers: list,
            counter: ServerListCounter::new(list)
        }
    }
}

impl<'a> Iterator for ServerListIter<'a> {
    type Item = &'a ServerInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter.next() {
            Some(self.counter.info(self.servers))
        }
        else {
            None
        }
    }
}

