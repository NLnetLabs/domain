use std::io;
use std::net::SocketAddr;
use domain::base::message::Message;
use tokio::net::UdpSocket;
use crate::stub::resolver::{Answer, QueryMessage};

//------------ Module Configuration ------------------------------------------

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;


pub async fn query(
    query: &QueryMessage, addr: SocketAddr, recv_size: usize
) -> Result<Answer, io::Error> {
    let mut sock = bind(addr.is_ipv4()).await?;
    sock.connect(addr).await?;
    let sent = sock.send(query.as_target().as_dgram_slice()).await?;
    if sent != query.as_target().as_dgram_slice().len() {
        return Err(io::Error::new(io::ErrorKind::Other, "short UDP send"))
    }
    loop {
        let mut buf = vec![0; recv_size]; // XXX use uninitialized memore here.
        let len = sock.recv(&mut buf).await?;
        buf.truncate(len);
        
        // We ignore garbage since there is a timer on this whole thing.
        let answer = match Message::from_octets(buf.into()) {
            Ok(answer) => answer,
            Err(_) => continue,
        };
        if !answer.is_answer(&query.as_message()) {
            continue
        }
        return Ok(answer.into())
    }
}

async fn bind(v4: bool) -> Result<UdpSocket, io::Error> {
    let mut i = 0;
    loop {
        let local: SocketAddr = if v4 { ([0u8; 4], 0).into() }
                    else { ([0u16; 8], 0).into() };
        match UdpSocket::bind(&local).await {
            Ok(sock) => return Ok(sock),
            Err(err) => {
                if i == RETRY_RANDOM_PORT {
                    return Err(err);
                }
                else {
                    i += 1
                }
            }
        }
    }
}

