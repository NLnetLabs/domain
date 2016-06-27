extern crate domain;

use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use domain::bits::DNameBuf;
use domain::resolv::{ResolvConf, Resolver};
use domain::resolv::tasks::{LookupAddr, SearchHost};


fn forward(resolver: Resolver, name: DNameBuf, conf: &ResolvConf) {
    match resolver.sync_task(SearchHost::new(&name.clone(), conf)) {
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
}

fn reverse(resolver: Resolver, addr: IpAddr) {
    match resolver.sync_task(LookupAddr::new(addr)) {
        Ok(result) => {
            println!("Host {} has domain name pointer {}", addr, result);
        },
        Err(err) => {
            println!("Error: {}", err);
        }
    }
}

fn main() {
    let name = match env::args().nth(1) {
        None => {
            println!("Usage: host <hostname>");
            return;
        }
        Some(name) => name
    };

    let conf = ResolvConf::default();
    let (join, resolver) = Resolver::spawn(conf.clone()).unwrap();
 
    if let Ok(addr) = IpAddr::from_str(&name) {
        reverse(resolver, addr)
    }
    else if let Ok(name) = DNameBuf::from_str(&name) {
        forward(resolver, name, &conf)
    }
    else {
        println!("Not a domain name: {}", name)
    }

    join.join().unwrap();
}
