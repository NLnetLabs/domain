#![cfg(feature = "net")]
mod net;

use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::client::{closure_do_client, do_client};
use crate::net::deckard::connect::Connect;
use crate::net::deckard::connection::Connection;
use crate::net::deckard::dgram::Dgram;
use crate::net::deckard::parse_deckard::parse_file;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::redundant;
use domain::net::client::stream;
use std::fs::File;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpStream;

const TEST_FILE: &str = "test-data/basic.rpl";

#[test]
fn dgram() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let conn = Dgram::new(deckard.clone(), step_value.clone());
        let octstr = Arc::new(dgram::Connection::new(conn));

        do_client(&deckard, octstr, &step_value).await;
    });
}

#[test]
fn single() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let conn = Connection::new(deckard.clone(), step_value.clone());
        let (octstr, transport) = stream::Connection::new(conn);
        tokio::spawn(async move {
            transport.run().await;
        });

        do_client(&deckard, octstr, &step_value).await;
    });
}

#[test]
fn multi() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        do_client(&deckard, ms.clone(), &step_value).await;
    });
}

#[test]
fn dgram_stream() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let conn = Dgram::new(deckard.clone(), step_value.clone());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ds, tran) = dgram_stream::Connection::new(conn, multi_conn);
        tokio::spawn(async move {
            tran.run().await;
            println!("dgram_stream conn run terminated");
        });

        do_client(&deckard, ds, &step_value).await;
    });
}

#[test]
fn redundant() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        // Redundant add previous connection.
        let redun = redundant::Connection::new(None).unwrap();
        let run_fut = redun.run();
        tokio::spawn(async move {
            run_fut.await;
            println!("redundant conn run terminated");
        });
        redun.add(Box::new(ms.clone())).await.unwrap();

        do_client(&deckard, redun, &step_value).await;
    });
}

#[test]
#[ignore]
// Connect directly to the internet. Disabled by default.
fn tcp() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let server_addr =
            SocketAddr::new(IpAddr::from_str("9.9.9.9").unwrap(), 53);

        let tcp_conn = match TcpStream::connect(server_addr).await {
            Ok(conn) => conn,
            Err(err) => {
                println!(
                    "TCP Connection to {server_addr} failed: {err}, exiting"
                );
                return;
            }
        };

        let (tcp, transport) = stream::Connection::new(tcp_conn);
        tokio::spawn(async move {
            transport.run().await;
            println!("single TCP run terminated");
        });

        do_client(&deckard, tcp, &CurrStepValue::new()).await;
    });
}

#[test]
#[ignore]
// Connect directly to the internet. Disabled by default.
fn tcp_async_fn() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let server_addr =
            SocketAddr::new(IpAddr::from_str("9.9.9.9").unwrap(), 53);

        let tcp_conn = match TcpStream::connect(server_addr).await {
            Ok(conn) => conn,
            Err(err) => {
                println!(
                    "TCP Connection to {server_addr} failed: {err}, exiting"
                );
                return;
            }
        };

        let (tcp, transport) = stream::Connection::new(tcp_conn);
        tokio::spawn(async move {
            transport.run().await;
            println!("single TCP run terminated");
        });

        closure_do_client(&deckard, &CurrStepValue::new(), |req| {
            tcp.request(req)
        })
        .await;
    })
}
