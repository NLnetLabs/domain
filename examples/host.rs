extern crate domain;

use std::env;
use std::str::FromStr;
use domain::bits::DNameBuf;
use domain::resolv::{ResolvConf, Resolver};
use domain::resolv::tasks::SearchHost;


//------------ Main Function ------------------------------------------------

fn main() {
    let name = match env::args().nth(1) {
        None => {
            println!("Usage: host <hostname>");
            return;
        }
        Some(name) => name
    };
    let name = match DNameBuf::from_str(&name) {
        Err(err) => {
            println!("Not a domain name: {}", err);
            return
        }
        Ok(name) => name
    };
    let conf = ResolvConf::default();
    let (join, resolver) = Resolver::spawn(conf.clone()).unwrap();
    match resolver.sync_task(SearchHost::new(&name.clone(), &conf)) {
        Ok(result) => {
            if name != result.canonical_name() {
                println!("{} is an alias for {}",
                         name, result.canonical_name());
            }
            for addr in result.iter() {
                println!("{} has address {}", result.canonical_name(), addr);
            }
        },
        Err(err) => {
            println!("Error: {}", err);
        }
    }
    drop(resolver);
    join.join().unwrap();
}
