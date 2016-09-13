extern crate domain;

use std::env;
//use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use domain::bits::DNameBuf;
use domain::resolv::{ResolvConf, Resolver};
use domain::resolv::lookup::{lookup_addr, lookup_host};


fn forward(name: DNameBuf, conf: ResolvConf) {
    match Resolver::run(conf, |resolv| lookup_host(resolv, &name)) {
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
            println!("Error: {:?}", err);
        }
    }
}

fn reverse(addr: IpAddr, conf: ResolvConf) {
    match Resolver::run(conf, |resolv| lookup_addr(resolv, addr)) {
        Ok(result) => {
            for name in result.iter() {
                println!("Host {} has domain name pointer {}", addr, name);
            }
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
    /*
    let mut conf = ResolvConf::new();
    let data = "nameserver 8.8.8.8\n\
                options use-vc\n".to_string();
    conf.parse(&mut io::Cursor::new(data)).unwrap();
    */
 
    if let Ok(addr) = IpAddr::from_str(&name) {
        reverse(addr, conf)
    }
    else if let Ok(name) = DNameBuf::from_str(&name) {
        forward(name, conf)
    }
    else {
        println!("Not a domain name: {}", name)
    }
}
