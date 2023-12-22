use crate::net::deckard::client::CurrStepValue;
use crate::net::deckard::parse_deckard::Deckard;
use crate::net::deckard::server::do_server;
use domain::base::Message;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

#[derive(Debug)]
pub struct Connection {
    deckard: Deckard,
    step_value: Arc<CurrStepValue>,
    waker: Option<Waker>,
    reply: Option<Message<Vec<u8>>>,
    send_body: bool,
}

impl Connection {
    pub fn new(
        deckard: Deckard,
        step_value: Arc<CurrStepValue>,
    ) -> Connection {
        Self {
            deckard,
            step_value,
            waker: None,
            reply: None,
            send_body: false,
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
            let slice = self.reply.as_ref().unwrap().as_slice();
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
        let buflen = buf.len();
        let mut len_str: [u8; 2] = [0; 2];
        len_str.copy_from_slice(&buf[0..2]);
        let len = u16::from_be_bytes(len_str) as usize;
        if buflen != 2 + len {
            panic!("expecting one complete message per write");
        }
        let msg = Message::from_octets(buf[2..].to_vec()).unwrap();
        let opt_reply = do_server(&msg, &self.deckard, &self.step_value);
        if opt_reply.is_some() {
            // Do we need to support more than one reply?
            self.reply = opt_reply;
            let opt_waker = self.waker.take();
            if let Some(waker) = opt_waker {
                waker.wake();
            }
        }
        Poll::Ready(Ok(buflen))
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
