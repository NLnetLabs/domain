#![cfg(feature = "net")]

use domain::stelline::client::do_client_simple;
use domain::stelline::client::CurrStepValue;
use domain::stelline::connect::Connect;
use domain::stelline::connection::Connection;
use domain::stelline::dgram::Dgram;
use domain::stelline::parse_stelline::parse_file;
// use domain::net::client::clock::{Clock, FakeClock};
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::redundant;
use domain::net::client::request::{
    GetResponse as _, RequestMessage, RequestMessageMulti,
};
use domain::net::client::stream;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;

const TEST_FILE: &str = "test-data/client/basic.rpl";

#[test]
fn dgram() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let conn = Dgram::new(stelline.clone(), step_value.clone());
        let dgram = dgram::Connection::new(conn);

        do_client_simple(&stelline, &step_value, dgram).await;
    });
}

#[test]
fn single() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let conn = Connection::new(stelline.clone(), step_value.clone());
        let (octstr, transport) =
            stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::new(conn);
        tokio::spawn(async move {
            transport.run().await;
        });

        do_client_simple(&stelline, &step_value, octstr).await;
    });
}

#[test]
fn multi() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let multi_conn = Connect::new(stelline.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        do_client_simple(&stelline, &step_value, ms).await;
    });
}

#[test]
fn dgram_stream() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let conn = Dgram::new(stelline.clone(), step_value.clone());
        let multi_conn = Connect::new(stelline.clone(), step_value.clone());
        let (ds, tran) = dgram_stream::Connection::new(conn, multi_conn);
        tokio::spawn(async move {
            tran.run().await;
            println!("dgram_stream conn run terminated");
        });

        do_client_simple(&stelline, &step_value, ds).await;
    });
}

#[test]
fn redundant() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let multi_conn = Connect::new(stelline.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        // Redundant add previous connection.
        let (redun, transp) = redundant::Connection::new();
        let run_fut = transp.run();
        tokio::spawn(async move {
            run_fut.await;
            println!("redundant conn run terminated");
        });

        redun.add(Box::new(ms.clone())).await.unwrap();

        do_client_simple(&stelline, &step_value, redun).await;
    });
}

#[test]
#[ignore]
// Connect directly to the internet. Disabled by default.
fn tcp() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let stelline = parse_file(file, TEST_FILE);
        let step_value = Arc::new(CurrStepValue::new());

        let server_addr =
            SocketAddr::new(IpAddr::from_str("9.9.9.9").unwrap(), 53);

        let tcp_conn = match TcpStream::connect(server_addr).await {
            Ok(conn) => conn,
            Err(err) => {
                panic!(
                    "TCP Connection to {server_addr} failed: {err}, exiting"
                );
            }
        };

        let (tcp, transport) = stream::Connection::<
            _,
            RequestMessageMulti<Vec<u8>>,
        >::new(tcp_conn);
        tokio::spawn(async move {
            transport.run().await;
            println!("single TCP run terminated");
        });

        do_client_simple(&stelline, &step_value, tcp).await;
    });
}

/// Regression test: Ensure responses are not lost when a stream closes.
#[test]
fn stream_immediate_eof() {
    use domain::base::{iana::Rcode, MessageBuilder, Name, Rtype};
    use domain::rdata::A;
    use futures_util::FutureExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // Query and response for `a.b.c. IN A`
    let domain_name: Name<Vec<u8>> = "a.b.c.".parse().unwrap();
    let mut query = MessageBuilder::new_vec().question();
    query.push((&domain_name, Rtype::A)).unwrap();

    let mut response = MessageBuilder::new_stream_vec()
        .start_answer(&query.as_message(), Rcode::NOERROR)
        .unwrap();
    response
        .push((&domain_name, 3600, A::new(Ipv4Addr::LOCALHOST)))
        .unwrap();

    let response = response.finish().into_target();
    let query = RequestMessage::new(query).unwrap();

    tokio_test::block_on(async move {
        let (client, mut server) = tokio::io::duplex(response.len());
        tokio::spawn(async move {
            // Read the entire query to avoid breaking the client's write half.
            let len = server.read_u16().await.unwrap();
            let _ = server.read_exact(&mut vec![0; len as usize]).await;

            // Write the entire response in one shot. This is important so that
            // we can be sure the client sees the response and EOF at the same time.
            server
                .write_all(&response)
                .now_or_never()
                .expect("write should not return pending")
                .expect("client dead?");
            drop(server);
        });

        let (conn, transport) = stream::Connection::<
            _,
            RequestMessageMulti<Vec<u8>>,
        >::new(client);

        tokio::spawn(async move {
            transport.run().await;
            println!("single stream run terminated");
        });

        let resp = conn.get_request(query).get_response().await;
        let answer = resp.expect("request should yield a response");
        assert!(answer.no_error());
    });
}
