use std::net::SocketAddr;

use domain::new_base::name::RevName;
use domain::new_base::{QClass, QType, Question};
use domain::new_client::exchange::{Allocator, Exchange, ParsedMessage};
use domain::new_client::{Client, UdpClient, UdpConfig};

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut bump = bumpalo::Bump::new();
    let alloc = Allocator::new(&mut bump);

    let mut request = ParsedMessage::default();
    request.flags.request_recursion(true);
    let name = b"\x00\x03org\x07example\x03www";
    let name = unsafe { RevName::from_bytes_unchecked(name) };
    request
        .questions
        .push(Question::new(name, QType::A, QClass::IN));

    let mut exchange = Exchange {
        alloc,
        request,
        response: ParsedMessage::default(),
        metadata: Vec::new(),
    };

    let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();
    let client = UdpClient::new(addr, UdpConfig::default());

    client.request(&mut exchange).await.unwrap();

    println!("{:#?}", exchange.response);
}
