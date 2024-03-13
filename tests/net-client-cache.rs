#![cfg(feature = "net")]
mod net;

use crate::net::deckard::client::do_client;
use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::connect::Connect;
use crate::net::deckard::parse_deckard::parse_file;
use domain::base::{Dname, MessageBuilder, Rtype::Aaaa};
use domain::net::client::cache;
// use domain::net::client::clock::{Clock, FakeClock};
use domain::net::client::multi_stream;
use domain::net::client::redundant;
use domain::net::client::request::{
    Error::NoTransportAvailable, RequestMessage, SendRequest,
};
use net::deckard::client::SingleClientFactory;
use rstest::rstest;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::instrument;

const TEST_FILE_AD: &str = "test-data/client-cache/cache_ad.rpl";
const TEST_FILE_TRANSPORT_ERROR: &str =
    "test-data/client-cache/cache_transport_error.rpl";

async fn async_test_cache(filename: &str) {
    let file = File::open(filename).unwrap();
    let deckard = parse_file(&file, filename);

    let step_value = Arc::new(CurrStepValue::new());
    let multi_conn = Connect::new(deckard.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
        println!("multi conn run terminated");
    });
    // let clock = FakeClock::new();
    let cached = cache::Connection::new(ms); //_with_time(ms, clock.clone());
    let client_factory = SingleClientFactory::new(cached);

    do_client(&deckard, &step_value, client_factory /*, &clock*/).await;
}

async fn async_test_no_cache(filename: &str) {
    let file = File::open(filename).unwrap();
    let deckard = parse_file(&file, filename);

    let step_value = Arc::new(CurrStepValue::new());
    let multi_conn = Connect::new(deckard.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
        println!("multi conn run terminated");
    });

    // let clock = FakeClock::new();
    let client_factory = SingleClientFactory::new(ms);

    do_client(&deckard, &step_value, client_factory /*, &clock*/).await;
}

#[tokio::test]
#[should_panic]
async fn test_ad_no_cache() {
    async_test_no_cache(TEST_FILE_AD).await;
}

#[tokio::test(start_paused = true)]
async fn test_transport_error() {
    // Transport errors should be cached. Create an empty redundant transport
    // and manually issue a query to trigger a transport error. Then add a
    // transport and issue a new query.
    let file = File::open(TEST_FILE_TRANSPORT_ERROR).unwrap();
    let deckard = parse_file(&file, TEST_FILE_TRANSPORT_ERROR);

    let step_value = Arc::new(CurrStepValue::new());
    let (redun, redun_tran) = redundant::Connection::new();
    tokio::spawn(async move {
        redun_tran.run().await;
        println!("redundant conn run terminated");
    });
    // let clock = FakeClock::new();
    let cached = cache::Connection::new(redun.clone()); //_with_time(redun.clone(), clock.clone());

    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    let mut msg = msg.question();
    msg.push((Dname::vec_from_str("example.com").unwrap(), Aaaa))
        .unwrap();
    let req = RequestMessage::new(msg);

    let mut request = cached.send_request(req.clone());
    let reply = request.get_response().await;

    println!("got {reply:?}");

    if let Err(NoTransportAvailable) = reply {
        // This is what we expect.
    } else {
        panic!("Bad result {reply:?}");
    }

    let multi_conn = Connect::new(deckard.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
        println!("multi conn run terminated");
    });
    redun.add(Box::new(ms)).await.unwrap();

    let mut request = cached.send_request(req);
    let reply = request.get_response().await;

    if let Err(NoTransportAvailable) = reply {
        // This is what we expect.
    } else {
        panic!("Bad result {reply:?}");
    }

    let client_factory = SingleClientFactory::new(redun);
    do_client(&deckard, &step_value, client_factory /*, &clock*/).await;
}

#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn test_all(
    #[files("test-data/client-cache/*.rpl")] rpl_file: PathBuf,
) {
    async_test_cache(rpl_file.to_str().unwrap()).await;
}
