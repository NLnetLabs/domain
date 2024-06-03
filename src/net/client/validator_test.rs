#![cfg(test)]

use std::fs::File;
use std::path::PathBuf;
use std::string::ToString;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::vec::Vec;

use crate::stelline::client::do_client_simple;
use crate::stelline::client::CurrStepValue;
use crate::stelline::connect::Connect;
use crate::stelline::parse_stelline::parse_file;
use crate::stelline::parse_stelline::Config;

use mock_instant::MockClock;
use rstest::rstest;
use tracing::instrument;

// use domain::net::client::clock::{Clock, FakeClock};
use crate::base::scan::IterScanner;
use crate::net::client::{multi_stream, validator};
use crate::rdata::dnssec::Timestamp;
use crate::validator::anchor::TrustAnchors;
use crate::validator::context::ValidationContext;

use lazy_static::lazy_static;

lazy_static! {
    static ref LOCK: Mutex<()> = Mutex::new(());
}

async fn async_test_validator(filename: &str) {
    #[allow(clippy::await_holding_lock)]
    let _locked = LOCK.lock().unwrap();

    let file = File::open(filename).unwrap();
    let stelline = parse_file(&file, filename);

    let ta = parse_server_config(&stelline.config);

    let step_value = Arc::new(CurrStepValue::new());
    let multi_conn = Connect::new(stelline.clone(), step_value.clone());
    let (ms, ms_tran) = multi_stream::Connection::new(multi_conn);
    tokio::spawn(async move {
        ms_tran.run().await;
    });

    let vc = Arc::new(ValidationContext::new(ta, ms.clone()));

    // let clock = FakeClock::new();
    let validator = validator::Connection::new(ms, vc); //_with_time(ms, clock.clone());

    do_client_simple(&stelline, &step_value, validator /*, &clock*/).await;
}

#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn validator_test_all(
    #[files("test-data/validator/*.rpl")] rpl_file: PathBuf,
) {
    async_test_validator(rpl_file.to_str().unwrap()).await;
}

fn parse_server_config(config: &Config) -> TrustAnchors {
    let mut in_server_block = false;
    let mut ta = TrustAnchors::empty();

    for line in config.lines() {
        if line.starts_with("server:") {
            in_server_block = true;
        } else if in_server_block {
            if !line.starts_with(|c: char| c.is_whitespace()) {
                in_server_block = false;
            } else if let Some((setting, value)) = line.trim().split_once(':')
            {
                // Trim off whitespace and trailing comments.
                let setting = setting.trim();
                let value = value
                    .split_once('#')
                    .map_or(value, |(value, _rest)| value)
                    .trim();

                match (setting, value) {
                    ("val-override-date", v) => {
                        let time = vec![v.trim_matches('"').to_string()];
                        type TestScanner = IterScanner<
                            std::vec::IntoIter<std::string::String>,
                            Vec<u8>,
                        >;
                        let mut scanner = TestScanner::new(time.into_iter());
                        let ts = Timestamp::scan(&mut scanner).unwrap();
                        MockClock::set_system_time(Duration::from_secs(
                            ts.into_int() as u64,
                        ));
                    }
                    ("val-override-timestamp", v) => {
                        let time = v.trim_matches('"');
                        MockClock::set_system_time(Duration::from_secs(
                            time.parse::<u64>().unwrap(),
                        ));
                    }
                    ("trust-anchor", a) => {
                        ta.add_u8(a.trim_matches('"').as_bytes()).unwrap();
                    }
                    _ => {
                        eprintln!("Ignoring unknown server setting '{setting}' with value: {value}");
                    }
                }
            }
        }
    }

    ta
}
