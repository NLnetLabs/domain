//! Provide server-side of datagram protocols

use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::parse_deckard::Deckard;
use crate::net::deckard::server::do_server;
use domain::base::Message;
use domain::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramSend,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Clone, Debug)]
pub struct Dgram {
    deckard: Deckard,
    step_value: Arc<CurrStepValue>,
}

impl Dgram {
    pub fn new(deckard: Deckard, step_value: Arc<CurrStepValue>) -> Self {
        Self {
            deckard,
            step_value,
        }
    }
}

impl AsyncConnect for Dgram {
    type Connection = DgramConnection;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send,
        >,
    >;
    fn connect(&self) -> Self::Fut {
        let deckard = self.deckard.clone();
        let step_value = self.step_value.clone();
        Box::pin(async move { Ok(DgramConnection::new(deckard, step_value)) })
    }
}

pub struct DgramConnection {
    deckard: Deckard,
    step_value: Arc<CurrStepValue>,

    sender: mpsc::Sender<Message<Vec<u8>>>,
    receiver: Arc<Mutex<mpsc::Receiver<Message<Vec<u8>>>>>,
}

impl DgramConnection {
    fn new(deckard: Deckard, step_value: Arc<CurrStepValue>) -> Self {
        let (sender, receiver) = mpsc::channel(2);
        Self {
            deckard,
            step_value,
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
}
impl AsyncDgramRecv for DgramConnection {
    type Fut =
        Pin<Box<dyn Future<Output = Result<Vec<u8>, std::io::Error>> + Send>>;
    fn recv(&self, buf: Vec<u8>) -> Self::Fut {
        let arc_m_rec = self.receiver.clone();
        Box::pin(async move {
            let mut rec = arc_m_rec.lock().await;
            let msg = (*rec).recv().await.unwrap();
            let msg_octets = msg.into_octets();
            if msg_octets.len() > buf.len() {
                panic!("test returned reply that is bigger than buffer");
            }
            Ok(msg_octets)
        })
    }
}

impl AsyncDgramSend for DgramConnection {
    type Fut =
        Pin<Box<dyn Future<Output = Result<usize, std::io::Error>> + Send>>;
    fn send(&self, buf: &[u8]) -> Self::Fut {
        let msg = Message::from_octets(buf).unwrap();
        let opt_reply = do_server(&msg, &self.deckard, &self.step_value);
        let sender = self.sender.clone();
        let len = buf.len();
        Box::pin(async move {
            if opt_reply.is_some() {
                sender.send(opt_reply.unwrap()).await.unwrap();
            }
            Ok(len)
        })
    }
}
