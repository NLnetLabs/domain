extern crate futures;
extern crate domain_core;
extern crate domain_resolv;
extern crate tokio;

use std::env;
use std::net::IpAddr;
use std::str::FromStr;
use domain_core::bits::name::UncertainDname;
use domain_resolv::Resolver;
use domain_resolv::lookup::{lookup_addr, lookup_host, search_host};
use futures::{future, stream};
use futures::future::{Either, Future};
use futures::stream::Stream;
use tokio::runtime::Runtime;


fn forward(
    resolver: &Resolver,
    name: UncertainDname
) -> impl Future<Item=(), Error=()> {
    match name {
        UncertainDname::Absolute(name) => {
            Either::A(lookup_host(resolver, &name))
        }
        UncertainDname::Relative(name) => {
            Either::B(search_host(resolver, name))
        }
    }
    .then(move |answer| {
        match answer {
            Ok(answer) => {
                if answer.canonical_name() != answer.qname() {
                    println!(
                        "{} is an alias for {}",
                        answer.qname(),
                        answer.canonical_name()
                    );
                }
                for addr in answer.iter() {
                    println!(
                        "{} has address {}",
                        answer.canonical_name(),
                        addr
                    );
                }
                Ok(())
            }
            Err(err) => {
                println!("Query failed: {}", err);
                Ok(())
            }
        }
    })
}


fn reverse(
    resolver: &Resolver,
    addr: IpAddr
) -> impl Future<Item=(), Error=()> {
    lookup_addr(&resolver, addr)
    .map_err(|err| {
        println!("Query failed: {}", err);
        ()
    })
    .and_then(move |answer| {
        for name in answer.iter() {
            println!("Host {} has domain name pointer {}", addr, name);
        }
        Ok(())
    })
}


fn main() -> Result<(), Box<std::error::Error>> {
    let names: Vec<_> = env::args().skip(1).collect();
    if names.is_empty() {
        Err("Usage: lookup <hostname_or_addr> [...]")?;
    }

    let resolver = Resolver::new();
    let mut runtime = Runtime::new()?;

    let _ = runtime.block_on(
        stream::iter_ok(names).and_then(move |name| {
            if let Ok(addr) = IpAddr::from_str(&name) {
                Either::A(reverse(&resolver, addr))
            }
            else if let Ok(name) = UncertainDname::from_str(&name) {
                Either::B(Either::A(forward(&resolver, name)))
            }
            else {
                println!("Not a domain name: {}", name);
                Either::B(Either::B(future::ok(())))
            }
        }).into_future()
    );
    Ok(())
}

