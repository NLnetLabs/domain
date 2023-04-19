use domain::base::Dname;
use domain::base::Rtype::Aaaa;
use domain::base::{MessageBuilder, StaticCompressor, StreamTarget};
use domain::net::client::octet_stream::Connection;
use rustls::{ClientConfig, ServerName};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

    let server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 853);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }),
    );
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let tls_connection = TlsConnector::from(client_config);

    let tcp = TcpStream::connect(server_addr).await.unwrap();

    let server_name = ServerName::try_from("dns.google").unwrap();
    let tls = tls_connection.connect(server_name, tcp).await.unwrap();

    let conn = Connection::new().unwrap();
    let conn_run = conn.clone();

    tokio::spawn(async move {
        conn_run.run(tls).await;
    });

    let mut query = conn.query(&mut msg).await.unwrap();
    let reply = query.get_result().await;
    println!("reply: {:?}", reply);
}
