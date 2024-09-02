use std::pin::Pin;
use std::sync::Arc;
use std::task::Waker;
use std::task::{Context, Poll};
use std::vec::Vec;

use super::client::CurrStepValue;
use super::parse_stelline::Stelline;
use super::server::do_server;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::base::message_builder::AdditionalBuilder;
use crate::base::Message;
use tracing::trace;

#[derive(Debug)]
pub struct Connection {
    stelline: Stelline,
    step_value: Arc<CurrStepValue>,
    waker: Option<Waker>,
    reply: Option<Result<AdditionalBuilder<Vec<u8>>, std::io::Error>>,
    send_body: bool,

    tmpbuf: Vec<u8>,
}

impl Connection {
    pub fn new(
        stelline: Stelline,
        step_value: Arc<CurrStepValue>,
    ) -> Connection {
        Self {
            stelline,
            step_value,
            waker: None,
            reply: None,
            send_body: false,
            tmpbuf: Vec::new(),
        }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.reply.is_some() {
            if self.reply.as_ref().unwrap().is_err() {
                self.reply.take().unwrap()?;
            }
            trace!("Returning stored reply to the caller");
            let slice = self.reply.as_ref().unwrap().as_ref().unwrap().as_slice();
            let slice = slice;
            let len = slice.len();
            if self.send_body {
                buf.put_slice(slice);
                self.reply = None;
                return Poll::Ready(Ok(()));
            } else {
                buf.put_slice(&(len as u16).to_be_bytes());
                self.send_body = true;
                return Poll::Ready(Ok(()));
            }
        }
        self.reply = None;
        self.send_body = false;
        self.waker = Some(context.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.tmpbuf.push(buf[0]);
        let buflen = self.tmpbuf.len();
        if buflen < 2 {
            return Poll::Ready(Ok(1));
        }
        let mut len_str: [u8; 2] = [0; 2];
        len_str.copy_from_slice(&self.tmpbuf[0..2]);
        let len = u16::from_be_bytes(len_str) as usize;
        if buflen != 2 + len {
            return Poll::Ready(Ok(1));
        }
        let msg = Message::from_octets(self.tmpbuf[2..].to_vec()).unwrap();
        self.tmpbuf = Vec::new();
        let opt_reply = do_server(&msg, &self.stelline, &self.step_value);
        if opt_reply.is_some() {
            trace!("Storing response for caller to read");
            // Do we need to support more than one reply?
            self.reply = opt_reply;
            let opt_waker = self.waker.take();
            if let Some(waker) = opt_waker {
                waker.wake();
            }
        }
        Poll::Ready(Ok(1))
    }
    fn poll_flush(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        // Do we need to do anything here?
        Poll::Ready(Ok(()))
    }
}
