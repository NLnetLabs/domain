//! The name service trait.

use std::io;
use futures::{Async, Future, Done, done};
use ::bits::{ComposeMode, MessageBuf, MessageBuilder};
use ::iana::Rcode;


//------------ NameService ---------------------------------------------------

pub trait NameService: Clone {
    type Future: Future<Item=Vec<u8>, Error=io::Error>;

    fn call(&self, req: MessageBuf, mode: ComposeMode) -> Self::Future;
    fn poll_ready(&self) -> Async<()>;
}


//------------ MockService ---------------------------------------------------

#[derive(Clone)]
pub struct MockService;

impl NameService for MockService {
    type Future = Done<Vec<u8>, io::Error>;

    fn call(&self, req: MessageBuf, mode: ComposeMode) -> Self::Future {
        let mut resp = MessageBuilder::new(mode, true).unwrap();
        resp.header_mut().set_id(req.header().id());
        resp.header_mut().set_qr(true);
        resp.header_mut().set_opcode(req.header().opcode());
        resp.header_mut().set_rcode(Rcode::Refused);
        done(Ok(resp.finish()))
    }

    fn poll_ready(&self) -> Async<()> {
        Async::Ready(())
    }
}
