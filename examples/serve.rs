use bytes::Bytes;
use domain::{
    base::{
        iana::{Class, Rcode},
        Dname, Message, MessageBuilder,
    },
    rdata::A,
    serve::{
        server::{Request, TcpServer},
        Server,
    },
};

// Helper fn to create a dummy response to send back to the client
fn mk_answer(req: &Request) -> Message<Bytes> {
    let res = MessageBuilder::new_bytes();
    let mut answer = res
        .start_answer(req.query_message(), Rcode::NoError)
        .unwrap();
    answer
        .push((
            Dname::root_ref(),
            Class::In,
            86400,
            A::from_octets(192, 0, 2, 1),
        ))
        .unwrap();
    answer.into_message()
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let mut srv = Server::Tcp(TcpServer::new().unwrap());

    loop {
        eprintln!("Getting request...");
        let req = srv.get_request().await.unwrap();

        tokio::task::spawn(async move {
            let msg = mk_answer(&req);
            req.reply(msg).await.unwrap();
        });
    }
}
