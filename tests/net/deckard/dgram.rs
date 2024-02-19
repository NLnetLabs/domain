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
use std::sync::Mutex as SyncMutex;
use std::task::{Context, Poll, Waker};
use tokio::io::ReadBuf;

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
                + Send
                + Sync,
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

    reply: SyncMutex<Option<Message<Vec<u8>>>>,
    waker: SyncMutex<Option<Waker>>,
}

impl DgramConnection {
    fn new(deckard: Deckard, step_value: Arc<CurrStepValue>) -> Self {
        Self {
            deckard,
            step_value,
            reply: SyncMutex::new(None),
            waker: SyncMutex::new(None),
        }
    }
}
impl AsyncDgramRecv for DgramConnection {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut reply = self.reply.lock().unwrap();
        if (*reply).is_some() {
            let slice = (*reply).as_ref().unwrap().as_slice();
            buf.put_slice(slice);
            *reply = None;
            return Poll::Ready(Ok(()));
        }
        *reply = None;
        let mut waker = self.waker.lock().unwrap();
        *waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncDgramSend for DgramConnection {
    fn poll_send(
        &self,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let msg = Message::from_octets(buf).unwrap();
        let opt_reply = do_server(&msg, &self.deckard, &self.step_value);
        let len = buf.len();
        if opt_reply.is_some() {
            // Do we need to support more than one reply?
            let mut reply = self.reply.lock().unwrap();
            *reply = opt_reply;
            drop(reply);
            let mut waker = self.waker.lock().unwrap();
            let opt_waker = (*waker).take();
            drop(waker);
            if let Some(waker) = opt_waker {
                waker.wake();
            }
        }
        Poll::Ready(Ok(len))
    }
}
