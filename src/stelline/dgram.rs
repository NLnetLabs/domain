//! Provide server-side of datagram protocols
use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use tokio::io::ReadBuf;
use tokio::time::Instant;

use crate::base::message_builder::AdditionalBuilder;
use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramSend,
};
use crate::net::server::message::{
    Request, TransportSpecificContext, UdpTransportContext,
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
        let mock_client_addr =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let mock_transport_ctx =
            TransportSpecificContext::Udp(UdpTransportContext::new(None));
        let req = Request::new(
            mock_client_addr,
            Instant::now(),
            msg,
            mock_transport_ctx.clone(),
            (),
        );
        let len = buf.len();
        if let Some((opt_reply, _indices)) = do_server(&req, &self.stelline, &self.step_value) {
            // Do we need to support more than one reply?
            let mut reply = self.reply.lock().unwrap();
            *reply = Some(opt_reply);
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
