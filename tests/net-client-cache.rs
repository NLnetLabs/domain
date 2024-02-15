#![cfg(feature = "net")]
mod net;

use crate::net::deckard::client::do_client;
use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::connect::Connect;
use crate::net::deckard::parse_deckard::parse_file;
use domain::base::{Dname, MessageBuilder, Rtype::Aaaa};
use domain::net::client::cache;
use domain::net::client::multi_stream;
use domain::net::client::redundant;
use domain::net::client::request::{
    Error::NoTransportAvailable, RequestMessage, SendRequest,
};
use domain::net::client::time::FakeTime;
use std::fs::File;
use std::sync::Arc;

const TEST_FILE_AD: &str = "test-data/client-cache/cache_ad.rpl";
const TEST_FILE_AD_REV: &str = "test-data/client-cache/cache_ad_rev.rpl";
const TEST_FILE_DO_NSEC: &str = "test-data/client-cache/cache_do_nsec.rpl";
const TEST_FILE_DO_NSEC3: &str = "test-data/client-cache/cache_do_nsec3.rpl";
const TEST_FILE_DO_Q_RRSIG: &str = "test-data/client-cache/cache_do_q_rrsig.rpl";
const TEST_FILE_DO_Q_NSEC: &str = "test-data/client-cache/cache_do_q_nsec.rpl";
const TEST_FILE_RD: &str = "test-data/client-cache/cache_rd.rpl";
const TEST_FILE_RD_REV: &str = "test-data/client-cache/cache_rd_rev.rpl";
const TEST_FILE_CD: &str = "test-data/client-cache/cache_cd.rpl";
const TEST_FILE_CD_REV: &str = "test-data/client-cache/cache_cd_rev.rpl";
const TEST_FILE_CASE: &str = "test-data/client-cache/cache_case.rpl";
const TEST_FILE_AA: &str = "test-data/client-cache/cache_aa.rpl";
const TEST_FILE_NXDOMAIN: &str = "test-data/client-cache/cache_nxdomain.rpl";
const TEST_FILE_NODATA: &str = "test-data/client-cache/cache_nodata.rpl";
const TEST_FILE_DELEGATION: &str = "test-data/client-cache/cache_delegation.rpl";
const TEST_FILE_BROKEN_NODATA: &str = "test-data/client-cache/cache_broken_nodata.rpl";
const TEST_FILE_REFUSED: &str = "test-data/client-cache/cache_refused.rpl";
const TEST_FILE_TRANSPORT_ERROR: &str = "test-data/client-cache/cache_transport_error.rpl";
const TEST_FILE_TTL: &str = "test-data/client-cache/cache_ttl.rpl";
const TEST_FILE_TTL_SECTIONS: &str = "test-data/client-cache/cache_ttl_sections.rpl";
const TEST_FILE_CHAOS: &str = "test-data/client-cache/cache_chaos.rpl";
const TEST_FILE_NOTIFY: &str = "test-data/client-cache/cache_notify.rpl";

/*
fn test_cache(filename: &str) {
    tokio_test::block_on(async {
        let file = File::open(filename).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });
        let cached = cache::Connection::<_, FakeTime>::new_with_time(ms);

        do_client(&deckard, cached, &step_value).await;
    });
}
*/

async fn async_test_cache(filename: &str) {
        let file = File::open(filename).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });
        let cached = cache::Connection::<_, FakeTime>::new_with_time(ms);

        do_client(&deckard, cached, &step_value).await;
}

/*
fn test_no_cache(filename: &str) {
    tokio_test::block_on(async {
        let file = File::open(filename).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        do_client(&deckard, ms, &step_value).await;
    });
}
*/

async fn async_test_no_cache(filename: &str) {
        let file = File::open(filename).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let multi_conn = Connect::new(deckard.clone(), step_value.clone());
        let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
        tokio::spawn(async move {
            ms_tran.run().await;
            println!("multi conn run terminated");
        });

        do_client(&deckard, ms, &step_value).await;
}

#[tokio::test]
async fn test_ad() {
    async_test_cache(TEST_FILE_AD).await;
}

#[tokio::test]
#[should_panic]
async fn test_ad_no_cache() {
    async_test_no_cache(TEST_FILE_AD).await;
}

#[tokio::test]
async fn test_ad_rev() {
    async_test_cache(TEST_FILE_AD_REV).await;
}

#[tokio::test]
async fn test_do_nsec() {
    async_test_cache(TEST_FILE_DO_NSEC).await;
}

#[tokio::test]
async fn test_do_nsec3() {
    async_test_cache(TEST_FILE_DO_NSEC3).await;
}

#[tokio::test]
async fn test_do_q_rrsig() {
    async_test_cache(TEST_FILE_DO_Q_RRSIG).await;
}

#[tokio::test]
async fn test_do_q_nsec() {
    async_test_cache(TEST_FILE_DO_Q_NSEC).await;
}

#[tokio::test]
async fn test_rd() {
    async_test_cache(TEST_FILE_RD).await;
}

#[tokio::test]
async fn test_rd_rev() {
    async_test_cache(TEST_FILE_RD_REV).await;
}

#[tokio::test]
async fn test_cd() {
    async_test_cache(TEST_FILE_CD).await;
}

#[tokio::test]
async fn test_cd_rev() {
    async_test_cache(TEST_FILE_CD_REV).await;
}

#[tokio::test]
async fn test_aa() {
    async_test_cache(TEST_FILE_AA).await;
}

#[tokio::test]
async fn test_case() {
    async_test_cache(TEST_FILE_CASE).await;
}

#[tokio::test]
async fn test_nxdomain() {
    async_test_cache(TEST_FILE_NXDOMAIN).await;
}

#[tokio::test]
async fn test_nodata() {
    async_test_cache(TEST_FILE_NODATA).await;
}

#[tokio::test]
async fn test_delegation() {
    async_test_cache(TEST_FILE_DELEGATION).await;
}

#[tokio::test]
async fn test_broken_nodata() {
    async_test_cache(TEST_FILE_BROKEN_NODATA).await;
}

#[tokio::test]
async fn test_refused() {
    async_test_cache(TEST_FILE_REFUSED).await;
}

/*
#[test]
fn test_transport_error() {
    // Transport errors should be cached. Create an empty redundant transport
    // and manually issue a query to trigger a transport error. Then add a
    // transport and issue a new query.
    tokio_test::block_on(async {
        let file = File::open(TEST_FILE_TRANSPORT_ERROR).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let (redun, redun_tran) = redundant::Connection::new();
        tokio::spawn(async move {
            redun_tran.run().await;
            println!("redundant conn run terminated");
        });
        let cached =
            cache::Connection::<_, FakeTime>::new_with_time(redun.clone());

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

        do_client(&deckard, redun, &step_value).await;
    });
}
*/

#[tokio::test]
async fn test_transport_error() {
    // Transport errors should be cached. Create an empty redundant transport
    // and manually issue a query to trigger a transport error. Then add a
    // transport and issue a new query.
        let file = File::open(TEST_FILE_TRANSPORT_ERROR).unwrap();
        let deckard = parse_file(file);

        let step_value = Arc::new(CurrStepValue::new());
        let (redun, redun_tran) = redundant::Connection::new();
        tokio::spawn(async move {
            redun_tran.run().await;
            println!("redundant conn run terminated");
        });
        let cached =
            cache::Connection::<_, FakeTime>::new_with_time(redun.clone());

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

        do_client(&deckard, redun, &step_value).await;
}

#[tokio::test]
async fn test_ttl() {
    async_test_cache(TEST_FILE_TTL).await;
}

#[tokio::test]
async fn test_ttl_sections() {
    async_test_cache(TEST_FILE_TTL_SECTIONS).await;
}

#[tokio::test]
async fn test_chaos() {
    async_test_cache(TEST_FILE_CHAOS).await;
}

#[tokio::test]
async fn test_notify() {
    async_test_cache(TEST_FILE_NOTIFY).await;
}
