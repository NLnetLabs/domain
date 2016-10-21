extern crate domain;
extern crate futures;
extern crate tokio_core;

use std::net::SocketAddr;
use std::str::FromStr;
use futures::Future;
use tokio_core::reactor::Core;
use domain::server::transport::{UdpTransport, TcpTransport};
use domain::server::service::MockService;


fn main() {
    let addr = SocketAddr::from_str("0.0.0.0:8053").unwrap();
    let mut core = Core::new().unwrap();
    let udp = UdpTransport::bind(&addr, &core.handle(), MockService).unwrap();
    let tcp = TcpTransport::bind(&addr, &core.handle(), MockService).unwrap();
    println!("Starting server at {}", addr);
    core.run(udp.join(tcp).map(|_| ())).unwrap()
}
