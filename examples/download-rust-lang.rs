use std::str::FromStr;

use domain::base::name::Dname;
use domain::resolv::StubResolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let resolver = StubResolver::new();
    let addr = match resolver
        .lookup_host(
            &Dname::<Vec<u8>>::from_str("www.rust-lang.org").unwrap(),
        )
        .await
    {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("DNS query failed: {}", err);
            return;
        }
    };
    let addr = match addr.port_iter(80).next() {
        Some(addr) => addr,
        None => {
            eprintln!("Failed to resolve www.rust-lang.org");
            return;
        }
    };
    let mut socket = match TcpStream::connect(&addr).await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("Failed to connect to {}: {}", addr, err);
            return;
        }
    };
    if let Err(err) = socket
        .write_all(
            "\
            GET / HTTP/1.0\r\n\
            Host: www.rust-lang.org\r\n\
            \r\n\
        "
            .as_bytes(),
        )
        .await
    {
        eprintln!("Failed to send request: {}", err);
        return;
    };
    let mut response = Vec::new();
    if let Err(err) = socket.read_to_end(&mut response).await {
        eprintln!("Failed to read response: {}", err);
        return;
    }

    println!("{}", String::from_utf8_lossy(&response));
}
