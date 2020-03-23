use std::io;
use std::net::SocketAddr;
use domain::base::message::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::stub::resolver::{Answer, QueryMessage};


pub async fn query(
    query: &QueryMessage, addr: SocketAddr
) -> Result<Answer, io::Error> {
    let mut sock = TcpStream::connect(&addr).await?;
    sock.write_all(query.as_target().as_stream_slice()).await?;

    // This loop can be infinite because we have a timeout on this whole
    // thing, anyway.
    loop {
        let mut buf = Vec::new();
        let len = sock.read_u16().await? as u64;
        AsyncReadExt::take(&mut sock, len).read_to_end(&mut buf).await?;
        if let Ok(answer) = Message::from_octets(buf.into()) {
            if answer.is_answer(&query.as_message()) {
                return Ok(answer.into())
            }
            // else try with the next message.
        }
        else {
            return Err(io::Error::new(io::ErrorKind::Other, "short buf"))
        }
    }
}

