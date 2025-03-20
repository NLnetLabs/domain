use std::net::SocketAddr;
use std::time::SystemTime;

use domain::new_base::name::RevName;
use domain::new_base::name::RevNameBuf;
use domain::new_base::wire::ParseBytesByRef;
use domain::new_base::Message;
use domain::new_base::QClass;
use domain::new_base::QType;
use domain::new_base::Question;
use domain::new_client::exchange::Allocator;
use domain::new_client::exchange::Exchange;
use domain::new_client::exchange::ParsedMessage;
use domain::new_client::UdpConfig;
use domain::new_client::{Client, UdpClient};

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut bump = bumpalo::Bump::new();
    let alloc = Allocator::new(&mut bump);

    let mut request = ParsedMessage::default();
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

    let result = client.request(&mut exchange).await.unwrap();
    let msg = Message::parse_bytes_by_ref(&result).unwrap();

    println!("{}", msg.header)
}
