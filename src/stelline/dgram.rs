//! Provide server-side of datagram protocols
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use tokio::io::ReadBuf;

use crate::base::message_builder::AdditionalBuilder;
use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramSend,
};

use super::client::CurrStepValue;
use super::parse_stelline::Stelline;
use super::server::do_server;

#[derive(Clone, Debug)]
pub struct Dgram {
    stelline: Stelline,
    step_value: Arc<CurrStepValue>,
}

impl Dgram {
    #[allow(dead_code)]
    pub fn new(stelline: Stelline, step_value: Arc<CurrStepValue>) -> Self {
        Self {
            stelline,
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
        let stelline = self.stelline.clone();
        let step_value = self.step_value.clone();
        Box::pin(
            async move { Ok(DgramConnection::new(stelline, step_value)) },
        )
    }
}

pub struct DgramConnection {
    stelline: Stelline,
    step_value: Arc<CurrStepValue>,

    reply: SyncMutex<Option<AdditionalBuilder<Vec<u8>>>>,
    waker: SyncMutex<Option<Waker>>,
}

impl DgramConnection {
    fn new(stelline: Stelline, step_value: Arc<CurrStepValue>) -> Self {
        Self {
            stelline,
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
        let opt_reply = do_server(&msg, &self.stelline, &self.step_value);
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
