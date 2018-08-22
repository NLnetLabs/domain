/*
//! Download and print the Rust homepage.
//!
//! This is the [toy HTTP+TLS client] example from the [futures tutorial]
//! extended to use our resolver.
//!
//! [toy HTTP+TLS client]: https://tokio.rs/docs/getting-started/tls/
//! [futures tutorial]: https://tokio.rs/docs/getting-started/futures/

extern crate futures;
extern crate native_tls;
extern crate tokio_core;
extern crate tokio_io;
extern crate tokio_tls;
extern crate domain;

use std::io;
use std::str::FromStr;

use futures::Future;
use native_tls::TlsConnector;
use tokio_core::net::TcpStream;
use tokio_core::reactor::Core;
use tokio_tls::TlsConnectorExt;
use domain::bits::DNameBuf;
use domain::resolv::Resolver;
use domain::resolv::lookup::lookup_host;

#[allow(unknown_lints, string_lit_as_bytes)]
*/
fn main() {
/*
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let resolver = Resolver::new(&handle);
    let addr = lookup_host(resolver, DNameBuf::from_str("www.rust-lang.org")
                                              .unwrap()).map_err(Into::into);
    let cx = TlsConnector::builder().unwrap().build().unwrap();
    let socket = addr.and_then(|addr| {
        TcpStream::connect(&addr.port_iter(443).next().unwrap(), &handle)
    });

    let tls_handshake = socket.and_then(|socket| {
        let tls = cx.connect_async("www.rust-lang.org", socket);
        tls.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e)
        })
    });
    let request = tls_handshake.and_then(|socket| {
        tokio_io::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _request)| {
        tokio_io::io::read_to_end(socket, Vec::new())
    });

    let (_socket, data) = core.run(response).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
*/
}
