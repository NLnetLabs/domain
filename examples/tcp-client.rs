use domain::base::Dname;
use domain::base::Rtype::Aaaa;
use domain::base::{MessageBuilder, StaticCompressor, StreamTarget};
use domain::net::client::octet_stream::Connection;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    // Create DNS request message
    // Create a message builder wrapping a compressor wrapping a stream
    // target.
    let mut msg = MessageBuilder::from_target(StaticCompressor::new(
        StreamTarget::new_vec(),
    ))
    .unwrap();
    msg.header_mut().set_rd(true);
    let mut msg = msg.question();
    msg.push((Dname::<Vec<u8>>::vec_from_str("example.com").unwrap(), Aaaa))
        .unwrap();
    let mut msg = msg.as_builder_mut().clone();

    let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);

    let tcp = match TcpStream::connect(server_addr).await {
        Err(err) => {
            println!("TCP connection failed with {}", err);
            return;
        }
        Ok(tcp) => tcp,
    };

    let conn = Connection::new().unwrap();
    let conn_run = conn.clone();

    tokio::spawn(async move {
        conn_run.run(tcp).await;
    });

    let mut query = conn.query(&mut msg).await.unwrap();
    let reply = query.get_result().await;
    println!("reply: {:?}", reply);
}
