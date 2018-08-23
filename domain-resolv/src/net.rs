//! Networking.
//!
//! This private module takes care of all the asynchronous networking. It is a
//! bit messy currently due to having to deal with compatibility between
//! futures 0.1 and 0.3 for tokio.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use domain_core::bits::Message;
use domain_core::bits::message_builder::OptBuilder;
use futures::future::TryFutureExt;
use futures_util::compat::Future01CompatExt;
use tokio::io::{read_exact, write_all};
use tokio::net::{TcpStream, UdpSocket};
use tokio::timer::Delay;
use super::conf::{ResolvConf, ServerConf, Transport};
use super::resolver::Answer;


//------------ Module Configuration ------------------------------------------

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;


//------------ Async Networking Functions ------------------------------------

pub async fn query_server(
    server: &ServerConf,
    mut message: OptBuilder
) -> (OptBuilder, Result<Answer, io::Error>) {
    message.set_udp_payload_size(server.recv_size);
    message.header_mut().set_random_id();
    let res = {
        let fut = _query_server(server.transport, server.addr, &message);
        await!(fut.try_join(delay(Instant::now() + server.request_timeout)))
    };
    (message, res.unwrap_err())
}

/// The future for the timeout.
///
/// The weird return type is to trick `TryFutureExt::try_join` into returning
/// as soon as the first future completes.
async fn delay(instant: Instant) -> Result<(), Result<Answer, io::Error>> {
    // Delay completes with Ok(()) when the timeout is reached or some error
    // when things go awry. We deal with the latter by also just timing out.
    // So, however Delay completes, a timeout error is the response.
    await!(Delay::new(instant).compat());
    Err(Err(
        io::Error::new(
            io::ErrorKind::TimedOut,
            "timed out"
        )
    ))
}

/// The future for actually querying a server.
///
/// Separatedly takes the transport and (remote) address instead of the
/// complete server config to avoid having two references as arguments which
/// would require lifetime parameters which currently crashes rustc.
///
/// The weird return type is to trick `TryFutureExt::try_join` into returning
/// as soon as the first future completes.
async fn _query_server(
    transport: Transport,
    addr: SocketAddr,
    message: &OptBuilder
) -> Result<(), Result<Answer, io::Error>> {
    let res = match transport {
        Transport::Udp => await!(query_udp_server(addr, &message)),
        Transport::Tcp => await!(query_tcp_server(addr, &message)),
    };
    Err(res)
}

/// The future for querying a UDP server.
async fn query_udp_server(
    addr: SocketAddr,
    message: &OptBuilder
) -> Result<Answer, io::Error> {
    let sock = bind_udp(addr.is_ipv4())?;
    println!("got socket");
    sock.connect(&addr)?;
    println!("connected socket");
    let (mut sock, _) = await!(
        sock.send_dgram(&message.preview()[2..], &addr) .compat()
    )?;
    println!("sent message");
    loop {
        let buf = vec![0; 4096]; // XXX Or what?
        let (the_sock, mut buf, size, _addr) = await!(
            sock.recv_dgram(buf).compat()
        )?;
        println!("received message");
        sock = the_sock;
        buf.truncate(size);
        let answer = match Message::from_bytes(buf.into()) {
            Ok(msg) => msg,
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::Other, "short buf"))
            }
        };
        println!("parsed message");
        // XXX Check question.
        if is_answer(message, &answer) {
            return Ok(answer.into())
        }
        println!("not an answer");
    }
}

/// Creates a bound UDP socket.
///
/// We are supposed to pick a random local port for socket for extra
/// protection. So we try just that here.
fn bind_udp(v4: bool) -> Result<UdpSocket, io::Error> {
    let mut i = 0;
    loop {
        let local = if v4 { ([0u8; 4], 0).into() }
                    else { ([0u16; 8], 0).into() };
        match UdpSocket::bind(&local) {
            Ok(sock) => return Ok(sock),
            Err(err) => {
                if i == RETRY_RANDOM_PORT {
                    return Err(err);
                }
                else {
                    i += 1
                }
            }
        }
    }
}

/// The future that queries a TCP server.
async fn query_tcp_server(
    addr: SocketAddr,
    message: &OptBuilder
) -> Result<Answer, io::Error> {
    let sock = await!(TcpStream::connect(&addr).compat())?;
    let (mut sock, _) = await!(write_all(sock, message.preview()).compat())?;
    loop {
        let (res_sock, buf) = await!(read_exact(sock, [0u8; 2]).compat())?;
        let len = (buf[0] as usize) << 8 | buf[1] as usize;
        let (res_sock, buf) = await!(
            read_exact(res_sock, vec![0u8; len]).compat()
        )?;
        let answer = Message::from_bytes(buf.into()).map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "short buf")
        })?;
        if is_answer(message, &answer) {
            return Ok(answer.into())
        }
        sock = res_sock;
    }
}


fn is_answer(request: &OptBuilder, response: &Message) -> bool {
    // XXX Also compare the questions, but we need to figure out how to do
    //     that for those two types.
    println!("{} {}", request.header().id(), response.header().id());
    request.header().id() == response.header().id()
}


//------------ ServerList ----------------------------------------------------

#[derive(Debug)]
pub struct ServerList {
    /// The actual list of servers.
    servers: Vec<ServerConf>,

    /// Where to start accessing the list.
    ///
    /// This value will always keep growing and will have to be used module
    /// `servers`’s length.
    ///
    /// When it eventually wraps around the end of usize’s range, there will
    /// be a jump in rotation. Since that will happen only oh-so-often, we
    /// accept that in favour of simpler code.
    start: AtomicUsize,
}

impl ServerList {
    pub fn from_conf<F>(conf: &ResolvConf, filter: F) -> Self
    where F: Fn(&ServerConf) -> bool {
        ServerList {
            servers: {
                conf.servers.iter().filter(|f| filter(*f))
                    .map(Clone::clone).collect()
            },
            start: AtomicUsize::new(0),
        }
    }

    pub fn iter(&self) -> ServerListIter {
        ServerListIter::new(self)
    }

    pub fn rotate(&self) {
        self.start.fetch_add(1, Ordering::SeqCst);
    }
}

impl<'a> IntoIterator for &'a ServerList {
    type Item = &'a ServerConf;
    type IntoIter = ServerListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ ServerListIter ------------------------------------------------

#[derive(Clone, Debug)]
pub struct ServerListIter<'a> {
    servers: &'a [ServerConf],
    cur: usize,
    end: usize,
}

impl<'a> ServerListIter<'a> {
    fn new(list: &'a ServerList) -> Self {
        // We modulo the start value here to prevent hick-ups towards the
        // end of usize’s range.
        let start = list.start.load(Ordering::Relaxed) % list.servers.len();
        ServerListIter {
            servers: list.servers.as_ref(),
            cur: start,
            end: start + list.servers.len(),
        }
    }
}

impl<'a> Iterator for ServerListIter<'a> {
    type Item = &'a ServerConf;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == self.end {
            None
        }
        else {
            let res = &self.servers[self.cur % self.servers.len()];
            self.cur += 1;
            Some(res)
        }
    }
}

