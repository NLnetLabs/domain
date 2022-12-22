use bytes::Bytes;
use domain::{
    base::{
        iana::{Class, Rcode},
        Dname, Message, MessageBuilder,
    },
    rdata::A,
    serve::server::TcpServer,
};

// Helper fn to create a dummy response to send back to the client
fn mk_answer(msg: &Message<Bytes>) -> Message<Bytes> {
    let res = MessageBuilder::new_bytes();
    let mut answer = res.start_answer(msg, Rcode::NoError).unwrap();
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
    let mut srv = TcpServer::new().unwrap();

    loop {
        eprintln!("Getting request...");
        srv.get_request(|req| Ok(mk_answer(&req.query_message())))
            .await
            .unwrap();
    }
}
