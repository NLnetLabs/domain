use std::net::SocketAddr;
use std::time::Duration;

use domain::new_base::build::{BuilderContext, MessageBuilder};
use domain::new_base::name::{RevName, RevNameBuf};
use domain::new_base::parse::SplitMessageBytes;
use domain::new_base::wire::U16;
use domain::new_base::{
    Header, HeaderFlags, QClass, QType, Question, Record,
};
// use domain::new_client::redundant::RedundantClient;
use domain::new_client::tcp::{TcpClient, TcpConfig};
use domain::new_client::udp::{UdpClient, UdpConfig};
use domain::new_client::{Client, ExtendedMessageBuilder};
use domain::new_rdata::RecordData;
use tokio::join;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    env_logger::init();
    let metrics = tokio::runtime::Handle::current().metrics();

    let mut args = std::env::args();
    let _ = args.next().unwrap();
    let protocol = args.next().unwrap_or("all".into()).to_lowercase();

    let example = b"\x00\x03org\x07example";
    let nlnetlabs = b"\x00\x02nl\x09nlnetlabs";
    let google = b"\x00\x03com\x06google";

    let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

    if protocol == "all" || protocol == "udp" {
        println!("\n=== UDP ===");
        let client = UdpClient::new(addr, UdpConfig::default());
        let res = send_request(example, &client).await;
        println!("{}", res);
    }

    if protocol == "all" || protocol == "tcp" {
        println!("\n=== TCP ===");
        let stream = TcpStream::connect(addr).await.unwrap();
        let client = TcpClient::new(stream);

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

    if protocol == "all" || protocol == "tcp-timeout" {
        println!("\n=== TCP WITH TIMEOUT ===");
        let stream = TcpStream::connect(addr).await.unwrap();
        let client = TcpClient::with_config(
            stream,
            TcpConfig {
                idle_timeout: Some(Duration::from_millis(500)),
                ..Default::default()
            },
        );

        let res = join!(
            send_request(example, &client),
            send_request(nlnetlabs, &client),
        );
        println!("{}\n", res.0);
        println!("{}\n", res.1);
        tokio::time::sleep(Duration::from_secs(1)).await;

        let res = send_request(google, &client).await;
        println!("{res}\n");

        drop(client);
    }

    // if protocol == "all" || protocol == "redundant" {
    //     let client = RedundantClient::new();
    //     client.add_client(UdpClient::new(addr, UdpConfig::default()));
    //     client.add_client(UdpClient::new(
    //         "9.9.9.9:53".parse().unwrap(),
    //         UdpConfig::default(),
    //     ));

    //     let res = join!(
    //         send_request(example, &client),
    //         send_request(nlnetlabs, &client),
    //     );
    //     println!("{}\n", res.0);
    //     println!("{}\n", res.1);
    // }
}

async fn send_request(name: &[u8], client: &impl Client) -> String {
    let mut buffer = vec![0u8; 65536];
    let mut context = BuilderContext::default();

    let mut builder = MessageBuilder::new(&mut buffer, &mut context);
    *builder.header_mut() = Header {
        id: U16::new(0),
        flags: *HeaderFlags::default().request_recursion(true),
        counts: Default::default(),
    };

    let name = unsafe { RevName::from_bytes_unchecked(name) };
    builder
        .build_question(&Question::new(name, QType::A, QClass::IN))
        .unwrap()
        .unwrap()
        .commit();

    let request = ExtendedMessageBuilder {
        builder,
        edns_record: None,
    };

    match client.request(request).await {
        Ok(msg) => {
            let mut s = msg.header.to_string();

            let mut offset = 0;

            for _ in 0..msg.header.counts.questions.get() {
                let (_question, rest) =
                    Question::<RevNameBuf>::split_message_bytes(
                        &msg.contents,
                        offset,
                    )
                    .unwrap();
                offset = rest;
            }

            for _ in 0..msg.header.counts.answers.get() {
                let (answer, rest) = Record::<
                    RevNameBuf,
                    RecordData<'_, RevNameBuf>,
                >::split_message_bytes(
                    &msg.contents, offset
                )
                .unwrap();
                s.push('\n');
                s.push_str(&format!("{:?}", answer));
                offset = rest;
            }
            s
        }
        Err(err) => format!("Error: {:?}", err),
    }
}
