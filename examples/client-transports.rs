use domain::base::MessageBuilder;
/// Using the `domain::net::client` module for sending a query.
use domain::base::Name;
use domain::base::Rtype;
use domain::net::client::cache;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::protocol::{TcpConnect, TlsConnect, UdpConnect};
use domain::net::client::redundant;
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::stream;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

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
    let req = RequestMessage::new(msg);

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

    // Send a query message.
    let mut request = udptcp_conn.send_request(req.clone());

    // Get the reply
    println!("Wating for UDP+TCP reply");
    let reply = request.get_response().await;
    println!("UDP+TCP reply: {reply:?}");

    // The query may have a reference to the connection. Drop the query
    // when it is no longer needed.
    drop(request);

    // Create a cached transport.
    let mut cache_config = cache::Config::new();
    cache_config.set_max_cache_entries(100); // Just an example.
    let cache =
        cache::Connection::with_config(udptcp_conn.clone(), cache_config);

    // Send a request message.
    let mut request = cache.send_request(req.clone());

    // Get the reply
    println!("Wating for cache reply");
    let reply = request.get_response().await;
    println!("Cache reply: {reply:?}");

    // Send the request message again.
    let mut request = cache.send_request(req.clone());

    // Get the reply
    println!("Wating for cached reply");
    let reply = request.get_response().await;
    println!("Cached reply: {reply:?}");

    #[cfg(feature = "unstable-validator")]
    do_validator(udptcp_conn.clone(), req.clone()).await;

    // Create a new TCP connections object. Pass the destination address and
    // port as parameter.
    let tcp_connect = TcpConnect::new(server_addr);

    // A muli_stream transport connection sets up new TCP connections when
    // needed.
    let (tcp_conn, transport) = multi_stream::Connection::with_config(
        tcp_connect,
        multi_stream_config.clone(),
    );

    // Get a future for the run function. The run function receives
    // the connection stream as a parameter.
    tokio::spawn(async move {
        transport.run().await;
        println!("multi TCP run exited");
    });

    // Send a query message.
    let mut request = tcp_conn.send_request(req.clone());

    // Get the reply. A multi_stream connection does not have any timeout.
    // Wrap get_result in a timeout.
    println!("Wating for multi TCP reply");
    let reply =
        timeout(Duration::from_millis(500), request.get_response()).await;
    println!("multi TCP reply: {reply:?}");

    drop(request);

    // Some TLS boiler plate for the root certificates.
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    // TLS config
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Currently the only support TLS connections are the ones that have a
    // valid certificate. Use a well known public resolver.
    let google_server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 853);

    // Create a new TLS connections object. We pass the TLS config, the name of
    // the remote server and the destination address and port.
    let tls_connect = TlsConnect::new(
        client_config,
        "dns.google".try_into().unwrap(),
        google_server_addr,
    );

    // Again create a multi_stream transport connection.
    let (tls_conn, transport) = multi_stream::Connection::with_config(
        tls_connect,
        multi_stream_config,
    );

    // Start the run function.
    tokio::spawn(async move {
        transport.run().await;
        println!("TLS run exited");
    });

    let mut request = tls_conn.send_request(req.clone());
    println!("Wating for TLS reply");
    let reply =
        timeout(Duration::from_millis(500), request.get_response()).await;
    println!("TLS reply: {reply:?}");

    drop(request);

    // Create a transport connection for redundant connections.
    let (redun, transp) = redundant::Connection::new();

    // Start the run function on a separate task.
    let run_fut = transp.run();
    tokio::spawn(async move {
        run_fut.await;
        println!("redundant run terminated");
    });

    // Add the previously created transports.
    redun.add(Box::new(udptcp_conn)).await.unwrap();
    redun.add(Box::new(tcp_conn)).await.unwrap();
    redun.add(Box::new(tls_conn)).await.unwrap();

    // Start a few queries.
    for i in 1..10 {
        let mut request = redun.send_request(req.clone());
        let reply = request.get_response().await;
        if i == 2 {
            println!("redundant connection reply: {reply:?}");
        }
    }

    drop(redun);

    // Create a new datagram transport connection. Pass the destination address
    // and port as parameter. This transport does not retry over TCP if the
    // reply is truncated. This transport does not have a separate run
    // function.
    let udp_connect = UdpConnect::new(server_addr);
    let dgram_conn =
        dgram::Connection::with_config(udp_connect, dgram_config);

    // Send a message.
    let mut request = dgram_conn.send_request(req.clone());
    //
    // Get the reply
    let reply = request.get_response().await;
    println!("Dgram reply: {reply:?}");

    // Create a single TCP transport connection. This is usefull for a
    // single request or a small burst of requests.
    let tcp_conn = match TcpStream::connect(server_addr).await {
        Ok(conn) => conn,
        Err(err) => {
            println!(
                "TCP Connection to {server_addr} failed: {err}, exiting",
            );
            return;
        }
    };

    let (tcp, transport) = stream::Connection::new(tcp_conn);
    tokio::spawn(async move {
        transport.run().await;
        println!("single TCP run terminated");
    });

    // Send a request message.
    let mut request = tcp.send_request(req);

    // Get the reply
    let reply = request.get_response().await;
    println!("TCP reply: {reply:?}");

    drop(tcp);
}

#[cfg(feature = "unstable-validator")]
async fn do_validator<Octs, SR>(conn: SR, req: RequestMessage<Octs>)
where
    Octs: AsRef<[u8]>
        + Clone
        + std::fmt::Debug
        + domain::dep::octseq::Octets
        + domain::dep::octseq::OctetsFrom<Vec<u8>>
        + Send
        + Sync
        + 'static,
    <Octs as domain::dep::octseq::OctetsFrom<Vec<u8>>>::Error:
        std::fmt::Debug,
    SR: Clone + SendRequest<RequestMessage<Octs>> + Send + Sync + 'static,
{
    // Create a validating transport
    let anchor_file = std::fs::File::open("examples/root.key").unwrap();
    let ta =
        domain::validator::anchor::TrustAnchors::from_reader(anchor_file)
            .unwrap();
    let vc = std::sync::Arc::new(
        domain::validator::context::ValidationContext::new(ta, conn.clone()),
    );
    let val_conn = domain::net::client::validator::Connection::new(conn, vc);

    // Send a query message.
    let mut request = val_conn.send_request(req);

    // Get the reply
    println!("Wating for Validator reply");
    let reply = request.get_response().await;
    println!("Validator reply: {:?}", reply);
}
