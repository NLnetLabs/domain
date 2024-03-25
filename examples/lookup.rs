use domain::base::name::UncertainDname;
use domain::resolv::StubResolver;
use std::env;
use std::net::IpAddr;
use std::str::FromStr;

async fn forward(resolver: &StubResolver, name: UncertainDname<Vec<u8>>) {
    let answer = match name {
        UncertainDname::Absolute(ref name) => {
            resolver.lookup_host(name).await
        }
        UncertainDname::Relative(ref name) => {
            resolver.search_host(name).await
        }
    };
    match answer {
        Ok(answer) => {
            if let UncertainDname::Relative(_) = name {
                println!("Found answer for {}", answer.qname());
            }
            let canon = answer.canonical_name();
            if canon != answer.qname() {
                println!("{} is an alias for {canon}", answer.qname());
            }
            for addr in answer.iter() {
                println!("{canon} has address {addr}");
            }
        }
        Err(err) => {
            println!("Query failed: {err}");
        }
    }
}

async fn reverse(resolver: &StubResolver, addr: IpAddr) {
    match resolver.lookup_addr(addr).await {
        Ok(answer) => {
            for name in answer.iter() {
                println!("Host {addr} has domain name pointer {name}");
            }
        }
        Err(err) => println!("Query failed: {err}"),
    }
}

#[tokio::main]
async fn main() {
    let names: Vec<_> = env::args().skip(1).collect();
    if names.is_empty() {
        println!("Usage: lookup <hostname_or_addr> [...]");
        return;
    }

    let resolver = StubResolver::new();
    for name in names {
        if let Ok(addr) = IpAddr::from_str(&name) {
            reverse(&resolver, addr).await;
        } else if let Ok(name) = UncertainDname::from_str(&name) {
            forward(&resolver, name).await;
        } else {
            println!("Not a domain name: {name}");
        }
    }
}
