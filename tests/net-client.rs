#![cfg(feature = "net")]
mod net;

use crate::net::deckard::client::do_client;
use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::connect::Connect;
use crate::net::deckard::connection::Connection;
use crate::net::deckard::dgram::Dgram;
use crate::net::deckard::parse_deckard::parse_file;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::redundant;
use domain::net::client::stream;
use net::deckard::client::Dispatcher;
use std::fs::File;
use std::future::ready;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::pin::Pin;
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

        let client_factory = |_entry: &_| {
            let conn = Dgram::new(deckard.clone(), step_value.clone());
            let dgram = dgram::Connection::new(conn);
            let conn =
                Dispatcher::Dgram::<dgram::Connection<_>, ()>(Some(dgram));
            Box::pin(ready(conn)) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &step_value).await;
    });
}

#[test]
fn single() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());

        let client_factory = |_entry: &_| {
            let conn = Connection::new(deckard.clone(), step_value.clone());
            let (octstr, transport) = stream::Connection::new(conn);
            tokio::spawn(async move {
                transport.run().await;
            });

            let conn =
                Dispatcher::Dgram::<stream::Connection<_>, ()>(Some(octstr));
            Box::pin(ready(conn)) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &step_value).await;
    });
}

#[test]
fn multi() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());

        let client_factory = |_entry: &_| {
            let multi_conn =
                Connect::new(deckard.clone(), step_value.clone());
            let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
            tokio::spawn(async move {
                ms_tran.run().await;
                println!("multi conn run terminated");
            });

            let conn = Dispatcher::Dgram::<multi_stream::Connection<_>, ()>(
                Some(ms),
            );
            Box::pin(ready(conn)) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &step_value).await;
    });
}

#[test]
fn dgram_stream() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());

        let client_factory = |_entry: &_| {
            let conn = Dgram::new(deckard.clone(), step_value.clone());
            let multi_conn =
                Connect::new(deckard.clone(), step_value.clone());
            let (ds, tran) = dgram_stream::Connection::new(conn, multi_conn);
            tokio::spawn(async move {
                tran.run().await;
                println!("dgram_stream conn run terminated");
            });

            let conn = Dispatcher::Dgram::<dgram_stream::Connection<_, _>, ()>(
                Some(ds),
            );
            Box::pin(ready(conn)) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &step_value).await;
    });
}

#[test]
fn redundant() {
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());

        let client_factory = |_entry: &_| {
            let multi_conn =
                Connect::new(deckard.clone(), step_value.clone());
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

            let redun_fut = async move {
                redun.add(Box::new(ms.clone())).await.unwrap();
                Dispatcher::Dgram::<redundant::Connection<_>, ()>(Some(redun))
            };

            Box::pin(redun_fut) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &step_value).await;
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

        let client_factory = |_entry: &_| {
            let conn_fut = async move {
                let tcp_conn = match TcpStream::connect(server_addr).await {
                    Ok(conn) => conn,
                    Err(err) => {
                        panic!(
                            "TCP Connection to {server_addr} failed: {err}, exiting"
                        );
                    }
                };

                let (tcp, transport) = stream::Connection::new(tcp_conn);
                tokio::spawn(async move {
                    transport.run().await;
                    println!("single TCP run terminated");
                });

                Dispatcher::Stream::<(), stream::Connection<_>>(Some(tcp))
            };

            Box::pin(conn_fut) as Pin<Box<dyn Future<Output = _>>>
        };

        do_client(&deckard, client_factory, &CurrStepValue::new()).await;
    });
}
