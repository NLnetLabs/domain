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
    let google = b"\x00\x03com\x06google";

    let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

    println!("\n=== UDP ===");
    let client = UdpClient::new(addr, UdpConfig::default());
    let res = send_request(example, &client).await;
    println!("{}", res);

    println!("\n=== TCP ===");
    let stream = TcpStream::connect(addr).await.unwrap();
    let client = TcpClient::new(stream, TcpConfig::default());

    let res = join!(
        send_request(example, &client),
        send_request(nlnetlabs, &client),
        send_request(google, &client),
    );
    println!("{}\n", res.0);
    println!("{}\n", res.1);
    println!("{}\n", res.2);

    drop(client);

    println!("Waiting to see whether tokio will stop the task");
    // Give tokio a bit of time to exit the background task
    tokio::time::sleep(Duration::from_secs(1)).await;
    let n = metrics.num_alive_tasks();
    println!("Runtime has {} alive tasks", n);
}

async fn send_request(name: &[u8], client: &impl Client) -> String {
    let mut request = ParsedMessage::default();
    request.flags.request_recursion(true);
    let name = unsafe { RevName::from_bytes_unchecked(name) };
    request
        .questions
        .push(Question::new(name, QType::A, QClass::IN));

    let mut bump = bumpalo::Bump::new();
    let mut exchange = Exchange::new(&mut bump);
    exchange.request = request;

    client.request(&mut exchange).await.unwrap();

    // TODO: Nicer output format
    format!("{:?}", exchange.response)
}
