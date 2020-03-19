extern crate futures;
extern crate native_tls;
extern crate tokio;
extern crate tokio_tls;
extern crate domain_core;
extern crate domain_resolv;

use std::io;
use std::str::FromStr;

use futures::Future;
use native_tls::TlsConnector;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use domain_core::name::Dname;
use domain_resolv::{Resolver, StubResolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut runtime = Runtime::new()?;
    let addr = StubResolver::new().lookup_host(
        &Dname::<Vec<u8>>::from_str("www.rust-lang.org").unwrap()
    );
    let addr = addr.and_then(|addr| {
        addr.port_iter(443).next()
            .ok_or(
                io::Error::new(
                    io::ErrorKind::Other,
                    "failed to resolve www.rust-lang.org"
                )
            )
    });
    let socket = addr.and_then(|addr| {
        TcpStream::connect(&addr)
    });
    let cx = TlsConnector::builder().build()?;
    let cx = tokio_tls::TlsConnector::from(cx);

    let tls_handshake = socket.and_then(move |socket| {
        cx.connect("www.rust-lang.org", socket).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })
    });
    let request = tls_handshake.and_then(|socket| {
        tokio::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _)| {
        tokio::io::read_to_end(socket, Vec::new())
    });

    let (_, data) = runtime.block_on(response)?;
    println!("{}", String::from_utf8_lossy(&data));
    Ok(())
}

