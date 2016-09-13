//! Download and print the Rust homepage.
//!
//! This is the [Hello, World!] example from the [futures tutorial] extended
//! to use our resolver.
//!
//! [Hello, World!]: https://github.com/alexcrichton/futures-rs/blob/master/TUTORIAL.md#hello-world
//! [futures tutorial]: https://github.com/alexcrichton/futures-rs/blob/master/TUTORIAL.md

extern crate futures;
extern crate tokio_core;
extern crate tokio_tls;
extern crate domain;

use std::str::FromStr;

use futures::Future;
use tokio_core::reactor::Core;
use tokio_core::net::TcpStream;
use tokio_tls::ClientContext;
use domain::bits::DNameBuf;
use domain::resolv::Resolver;
use domain::resolv::lookup::lookup_host;

fn main() {
    let mut core = Core::new().unwrap();

    let resolver = Resolver::default(&core.handle());
    let addr = resolver.start().and_then(|resolv| {
        lookup_host(resolv, DNameBuf::from_str("www.rust-lang.org").unwrap())
    });

    let socket_handle = core.handle();
    let socket = addr.and_then(|addr| {
        TcpStream::connect(&addr.port_iter(443).next().unwrap(),
                           &socket_handle)
    });

    let tls_handshake = socket.and_then(|socket| {
        let cx = ClientContext::new().unwrap();
        cx.handshake("www.rust-lang.org", socket)
    });
    let request = tls_handshake.and_then(|socket| {
        tokio_core::io::write_all(socket, "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        ".as_bytes())
    });
    let response = request.and_then(|(socket, _)| {
        tokio_core::io::read_to_end(socket, Vec::new())
    });

    let (_, data) = core.run(response).unwrap();
    println!("{}", String::from_utf8_lossy(&data));
}
