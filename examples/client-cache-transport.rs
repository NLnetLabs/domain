//! Example of using the `domain::net::client::cache` module.
use domain::base::{MessageBuilder, Name, Rtype};
use domain::net::client::cache;
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::{dgram, dgram_stream, multi_stream, stream};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Create DNS request message.
    //
    // Transports currently take a `RequestMessage` as their input to be able
    // to add options along the way.
    //
    // In the future, it will also be possible to pass in a message or message
    // builder directly as input but for now it needs to be converted into a
    // `RequestMessage` manually.
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    msg.header_mut().set_ad(true);
    let mut msg = msg.question();
    msg.push((Name::vec_from_str("example.com").unwrap(), Rtype::AAAA))
        .unwrap();
    let req = RequestMessage::new(msg).unwrap();

    // Destination for UDP and TCP
    let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);

    let mut stream_config = stream::Config::new();
    stream_config.set_response_timeout(Duration::from_millis(100));
    let multi_stream_config =
        multi_stream::Config::from(stream_config.clone());

    // Create a new UDP+TCP transport connection. Pass the destination address
    // and port as parameter.
    let mut dgram_config = dgram::Config::new();
    dgram_config.set_max_parallel(1);
    dgram_config.set_read_timeout(Duration::from_millis(1000));
    dgram_config.set_max_retries(1);
    dgram_config.set_udp_payload_size(Some(1400));
    let dgram_stream_config = dgram_stream::Config::from_parts(
        dgram_config.clone(),
        multi_stream_config.clone(),
    );
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (udptcp_conn, transport) = dgram_stream::Connection::with_config(
        udp_connect,
        tcp_connect,
        dgram_stream_config.clone(),
    );

    // Start the run function in a separate task. The run function will
    // terminate when all references to the connection have been dropped.
    // Make sure that the task does not accidentally get a reference to the
    // connection.
    tokio::spawn(async move {
        transport.run().await;
        println!("UDP+TCP run exited");
    });

    // Create a cached transport.
    let mut cache_config = cache::Config::new();
    cache_config.set_max_cache_entries(100); // Just an example.
    let cache = cache::Connection::with_config(udptcp_conn, cache_config);

    // Send a request message.
    let mut request = cache.send_request(req.clone());

    // Get the reply
    println!("Waiting for cache reply");
    let reply = request.get_response().await;
    println!("Cache reply: {reply:?}");

    // Send the request message again.
    let mut request = cache.send_request(req.clone());

    // Get the reply
    println!("Wating for cached reply");
    let reply = request.get_response().await;
    println!("Cached reply: {reply:?}");
}
