extern crate domain;

use std::env;
//use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use domain::bits::DNameBuf;
use domain::resolv::{Resolver, ResolvConf};
use domain::resolv::conf::TransportMode;
use domain::resolv::lookup::{lookup_addr, lookup_host};


fn forward(name: DNameBuf, conf: ResolvConf) {
    match Resolver::run_with_conf(conf, |resolv| lookup_host(resolv, &name)) {
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
    match Resolver::run_with_conf(conf, |resolv| lookup_addr(resolv, addr)) {
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

fn set_tcp_mode(conf: &mut ResolvConf, mode: TransportMode) {
    for server in &mut conf.servers {
        server.tcp = mode;
    }
}

fn parse_queryopt(conf: &mut ResolvConf, arg: &str) {
    match arg {
        "+vc" => conf.options.use_vc = true,
        "+tcpsgl" => set_tcp_mode(conf, TransportMode::SingleRequest),
        "+tcpseq" => set_tcp_mode(conf, TransportMode::Sequential),
        "+tcpmul" => set_tcp_mode(conf, TransportMode::Multiplex),
        _ => {
            println!("Warning: ignoring unknown query option {}", arg);
        }
    }
}

fn main() {
    let mut conf = ResolvConf::default();
    let mut names = Vec::new();
    for arg in env::args().skip(1) {
        if arg.starts_with('+') {
            parse_queryopt(&mut conf, &arg)
        }
        else {
            names.push(arg)
        }
    }
    if names.is_empty() {
        println!("Usage: host [OPTIONS] <hostname>");
        return;
    }

    for name in names {
        if let Ok(addr) = IpAddr::from_str(&name) {
            reverse(addr, conf.clone())
        }
        else if let Ok(name) = DNameBuf::from_str(&name) {
            forward(name, conf.clone())
        }
        else {
            println!("Not a domain name: {}", name)
        }
    }
}
