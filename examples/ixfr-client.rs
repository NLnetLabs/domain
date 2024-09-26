/// Using the `domain::net::client` module for sending a query.
use core::str::FromStr;

use std::vec::Vec;

use tokio::net::TcpStream;

use domain::base::Name;
use domain::base::Rtype;
use domain::base::{MessageBuilder, Serial, Ttl};
use domain::net::client::request::SendRequestMulti;
use domain::net::client::request::{RequestMessage, RequestMessageMulti};
use domain::net::client::stream;
use domain::rdata::Soa;

#[path = "common/serve-utils.rs"]
mod common;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!(
            "Usage: {} <ip addr:port> <zone name> <SOA serial>",
            args[0]
        );
        eprintln!("E.g.:  {} 127.0.0.1:8053 example.com 2020080302", args[0]);
        std::process::exit(1);
    }

    let server_addr = &args[1];
    let qname = Name::<Vec<u8>>::from_str(&args[2]).unwrap();
    let soa_serial: u32 = args[3].parse().unwrap();

    eprintln!("Requesting IXFR from {server_addr} for zone {qname} from serial {soa_serial}");

    let tcp_conn = TcpStream::connect(server_addr).await.unwrap();
    let (tcp, transport) = stream::Connection::<
        RequestMessage<Vec<u8>>,
        RequestMessageMulti<Vec<u8>>,
    >::new(tcp_conn);
    tokio::spawn(async move {
        transport.run().await;
        println!("single TSIG TCP run terminated");
    });

    let mname = Name::<Vec<u8>>::from_str("mname").unwrap();
    let rname = Name::<Vec<u8>>::from_str("rname").unwrap();
    let ttl = Ttl::from_secs(3600);
    let soa = Soa::new(mname, rname, Serial(soa_serial), ttl, ttl, ttl, ttl);

    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_rd(true);
    msg.header_mut().set_ad(true);
    let mut msg = msg.question();
    msg.push((&qname, Rtype::IXFR)).unwrap();
    let mut msg = msg.authority();
    msg.push((&qname, 3600, soa)).unwrap();
    let req = RequestMessageMulti::new(msg.clone()).unwrap();

    let mut request = SendRequestMulti::send_request(&tcp, req);

    // Get the reply
    let mock_req = msg.into_message();
    while let Some(reply) = request.get_response().await.unwrap() {
        common::print_dig_style_response(&mock_req, &reply, false);
    }
}
