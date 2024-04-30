#![cfg(feature = "net")]
mod net;

use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use net::stelline::client::do_client_simple;
use net::stelline::client::CurrStepValue;
use net::stelline::connect::Connect;
use net::stelline::parse_stelline::parse_file;

use rstest::rstest;
use tracing::instrument;

// use domain::net::client::clock::{Clock, FakeClock};
use domain::base::{MessageBuilder, Name, Rtype};
use domain::net::client::request::Error::NoTransportAvailable;
use domain::net::client::request::{RequestMessage, SendRequest};
use domain::net::client::{cache, multi_stream, redundant};

const TEST_FILE_AD: &str = "test-data/client-cache/cache_ad.rpl";
const TEST_FILE_TRANSPORT_ERROR: &str =
    "test-data/client-cache/cache_transport_error.rpl";

async fn async_test_cache(filename: &str) {
    let file = File::open(filename).unwrap();
    let stelline = parse_file(&file, filename);

    let step_value = Arc::new(CurrStepValue::new());
    let multi_conn = Connect::new(stelline.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
        println!("multi conn run terminated");
    });
    // let clock = FakeClock::new();
    let cached = cache::Connection::new(ms); //_with_time(ms, clock.clone());

    do_client_simple(&stelline, &step_value, cached /*, &clock*/).await;
}

async fn async_test_no_cache(filename: &str) {
    let file = File::open(filename).unwrap();
    let stelline = parse_file(&file, filename);

    let step_value = Arc::new(CurrStepValue::new());
    let multi_conn = Connect::new(stelline.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
        println!("multi conn run terminated");
    });

    // let clock = FakeClock::new();

    do_client_simple(&stelline, &step_value, ms /*, &clock*/).await;
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
    let stelline = parse_file(&file, TEST_FILE_TRANSPORT_ERROR);

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
    msg.push((Name::vec_from_str("example.com").unwrap(), Rtype::AAAA))
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

    let multi_conn = Connect::new(stelline.clone(), step_value.clone());
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

    do_client_simple(&stelline, &step_value, redun /*, &clock*/).await;
}

#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn test_all(
    #[files("test-data/client-cache/*.rpl")] rpl_file: PathBuf,
) {
    async_test_cache(rpl_file.to_str().unwrap()).await;
}
