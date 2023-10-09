use domain::base::Dname;
use domain::base::Rtype::Aaaa;
use domain::base::{Message, MessageBuilder, StaticCompressor, StreamTarget};
use domain::net::client::multi_stream;
use domain::net::client::octet_stream;
use domain::net::client::query::QueryMessage3;
use domain::net::client::redundant;
use domain::net::client::tcp_factory::TcpConnFactory;
use domain::net::client::tls_factory::TlsConnFactory;
use domain::net::client::udp;
use domain::net::client::udp_tcp;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

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

    let msg = Message::from_octets(
        msg.as_target().as_target().as_dgram_slice().to_vec(),
    )
    .unwrap();

    println!("request msg: {:?}", msg.as_slice());

    // Destination for UDP and TCP
    let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);

    // Create a new UDP+TCP transport connection. Pass the destination address
    // and port as parameter.
    let udptcp_conn = udp_tcp::Connection::new(server_addr).unwrap();

    // Create a clone for the run function. Start the run function on a
    // separate task.
    let conn_run = udptcp_conn.clone();
    tokio::spawn(async move {
        conn_run.run().await;
    });

    // Send a query message.
    let mut query = udptcp_conn.query(&msg).await.unwrap();

    // Get the reply
    let reply = query.get_result().await;
    println!("UDP+TCP reply: {:?}", reply);

    // Create a factory of TCP connections. Pass the destination address and
    // port as parameter.
    let tcp_factory = TcpConnFactory::new(server_addr);

    // A muli_stream transport connection sets up new TCP connections when
    // needed.
    let tcp_conn = multi_stream::Connection::<Vec<u8>>::new().unwrap();

    // Start the run function as a separate task. The run function receives
    // the factory as a parameter.
    let conn_run = tcp_conn.clone();
    tokio::spawn(async move {
        conn_run.run(tcp_factory).await;
    });

    // Send a query message.
    let mut query = tcp_conn.query(&msg).await.unwrap();

    // Get the reply
    let reply = query.get_result().await;
    println!("TCP reply: {:?}", reply);

    // Some TLS boiler plate for the root certificates.
    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
        |ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        },
    ));

    // TLS config
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    // Currently the only support TLS connections are the ones that have a
    // valid certificate. Use a well known public resolver.
    let server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 853);

    // Create a new TLS connection factory. We pass the TLS config, the name of
    // the remote server and the destination address and port.
    let tls_factory =
        TlsConnFactory::new(client_config, "dns.google", server_addr);

    // Again create a multi_stream transport connection.
    let tls_conn = multi_stream::Connection::new().unwrap();

    // Can start the run function.
    let conn_run = tls_conn.clone();
    tokio::spawn(async move {
        conn_run.run(tls_factory).await;
    });

    let mut query = tls_conn.query(&msg).await.unwrap();
    let reply = query.get_result().await;
    println!("TLS reply: {:?}", reply);

    // Create a transport connection for redundant connections.
    let redun = redundant::Connection::new().unwrap();

    // Start the run function on a separate task.
    let redun_run = redun.clone();
    tokio::spawn(async move {
        redun_run.run().await;
    });

    // Add the previously created transports.
    redun.add(Box::new(udptcp_conn)).await.unwrap();
    redun.add(Box::new(tcp_conn)).await.unwrap();
    redun.add(Box::new(tls_conn)).await.unwrap();

    // Start a few queries.
    for _i in 1..10 {
        let mut query = redun.query(&msg).await.unwrap();
        let reply = query.get_result().await;
        println!("redundant connection reply: {:?}", reply);
    }

    // Create a new UDP transport connection. Pass the destination address
    // and port as parameter. This transport does not retry over TCP if the
    // reply is truncated.
    let udp_conn = udp::Connection::new(server_addr).unwrap();

    // Send a query message.
    let mut query = udp_conn.query(&msg).await.unwrap();

    // Get the reply
    let reply = query.get_result().await;
    println!("UDP reply: {:?}", reply);

    // Create a single TCP transport connection. This is usefull for a
    // single request or a small burst of requests.
    let tcp_conn = TcpStream::connect(server_addr).await.unwrap();

    let tcp = octet_stream::Connection::new().unwrap();
    let tcp_worker = tcp.clone();

    tokio::spawn(async move {
        tcp_worker.run(tcp_conn).await;
        println!("run terminated");
    });

    // Send a query message.
    let mut query = tcp.query(&msg).await.unwrap();

    // Get the reply
    let reply = query.get_result().await;
    println!("TCP reply: {:?}", reply);
}
