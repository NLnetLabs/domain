use std::net::SocketAddr;
use std::time::Duration;

use domain::new_base::name::RevName;
use domain::new_base::{QClass, QType, Question};
use domain::new_client::exchange::{Allocator, Exchange, ParsedMessage};
use domain::new_client::tcp::{TcpClient, TcpConfig};
use domain::new_client::udp::{UdpClient, UdpConfig};
use domain::new_client::Client;
use tokio::join;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    env_logger::init();
    let metrics = tokio::runtime::Handle::current().metrics();

    let example = b"\x00\x03org\x07example";
    let nlnetlabs = b"\x00\x02nl\x09nlnetlabs";

    let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

    println!("\n=== UDP ===");
    let client = UdpClient::new(addr, UdpConfig::default());
    let res = send_request(example, &client).await;
    println!("{}", res);

    println!("\n=== TCP ===");
    let stream = TcpStream::connect(addr).await.unwrap();
    let client = TcpClient::new(stream, TcpConfig::default());

    let n = metrics.num_alive_tasks();
    println!("Runtime has {} alive tasks", n);

    let res = join!(
        send_request(example, &client),
        send_request(nlnetlabs, &client),
    );
    println!("{}", res.0);
    println!("{}", res.1);

    drop(client);

    // Give tokio a bit of time to exit the background task
    tokio::time::sleep(Duration::from_secs(1)).await;
    let n = metrics.num_alive_tasks();
    println!("Runtime has {} alive tasks", n);
}

async fn send_request(name: &[u8], client: &impl Client) -> String {
    let mut bump = bumpalo::Bump::new();
    let alloc = Allocator::new(&mut bump);

    let mut request = ParsedMessage::default();
    request.flags.request_recursion(true);
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

    client.request(&mut exchange).await.unwrap();

    // TODO: Nicer output format
    format!("{:?}", exchange.response)
}
