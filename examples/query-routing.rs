use domain::base::Name;
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::{dgram_stream, redundant};
use domain::net::server::adapter::{
    ClientTransportToSingleService, SingleServiceToService,
};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::qname_router::QnameRouter;
use domain::net::server::single_service::ReplyMessage;
use domain::net::server::stream::StreamServer;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::vec::Vec;
use tokio::net::{TcpSocket, UdpSocket};
use tracing_subscriber::EnvFilter;

//----------- main() ---------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    eprintln!("Test with commands such as:");
    eprintln!("  dnsi query --server ::1 -p 8053 ietf.org");
    eprintln!("  dnsi query --server ::1 -p 8053 nlnetlabs.nl");
    eprintln!("  dnsi query --server ::1 -p 8053 google.com");
    eprintln!("Enabled tracing with 'RUST_LOG=trace' before the command");

    // -----------------------------------------------------------------------
    // Setup logging. You can override the log level by setting environment
    // variable RUST_LOG, e.g. RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    // Start building the query router plus upstreams.
    let mut qr: QnameRouter<Vec<u8>, Vec<u8>, ReplyMessage> =
        QnameRouter::new();

    // Queries to the root go to 2606:4700:4700::1111 and 1.1.1.1.
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(transport.run());
    let server_addr = SocketAddr::new(
        IpAddr::from_str("2606:4700:4700::1111").unwrap(),
        53,
    );
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let server_addr =
        SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let conn_service = ClientTransportToSingleService::new(redun);
    qr.add(Name::<Vec<u8>>::from_str(".").unwrap(), conn_service);

    // Queries to .com go to 2001:4860:4860::8888 and 8.8.8.8.
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(transport.run());
    let server_addr = SocketAddr::new(
        IpAddr::from_str("2001:4860:4860::8888").unwrap(),
        53,
    );
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let conn_service = ClientTransportToSingleService::new(redun);
    qr.add(Name::<Vec<u8>>::from_str("com").unwrap(), conn_service);

    // Queries to .nl go to 2620:fe::9 and 9.9.9.9.
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(transport.run());
    let server_addr =
        SocketAddr::new(IpAddr::from_str("2620:fe::9").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let server_addr =
        SocketAddr::new(IpAddr::from_str("9.9.9.9").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let tcp_connect = TcpConnect::new(server_addr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(transport.run());
    redun.add(Box::new(conn)).await.unwrap();
    let conn_service = ClientTransportToSingleService::new(redun);
    qr.add(Name::<Vec<u8>>::from_str("nl").unwrap(), conn_service);

    let srv = SingleServiceToService::new(qr);
    let srv = MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(srv);
    let my_svc = Arc::new(srv);

    let udpsocket = UdpSocket::bind("[::1]:8053").await.unwrap();
    let buf = Arc::new(VecBufSource);
    let srv = DgramServer::new(udpsocket, buf.clone(), my_svc.clone());
    let udp_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Run a DNS server on TCP port 8053 on ::1. Test it like so:
    //    dnsi query -t --server 127.0.0.1 -p 8053 google.com
    let v6socket = TcpSocket::new_v6().unwrap();
    v6socket.set_reuseaddr(true).unwrap();
    v6socket.bind("[::1]:8053".parse().unwrap()).unwrap();
    let v6listener = v6socket.listen(1024).unwrap();
    let buf = Arc::new(VecBufSource);
    let srv = StreamServer::new(v6listener, buf.clone(), my_svc.clone());
    let tcp_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Keep the services running in the background

    udp_join_handle.await.unwrap();
    tcp_join_handle.await.unwrap();
}
