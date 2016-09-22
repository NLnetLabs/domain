//! Transport for DNS

use std::io;
use futures::Future;
use futures::stream::Stream;
use tokio_core::reactor;
use ::bits::MessageBuf;
use super::request::ServiceRequest;


//------------ Write ---------------------------------------------------------

pub trait Write: Sized {
    type Future: Future<Item=(Self, ServiceRequest), Error=io::Error>;

    fn write(self, request: ServiceRequest) -> Self::Future;
}


//------------ Read ----------------------------------------------------------

pub trait Read: Stream<Item=MessageBuf, Error=io::Error> { }


//------------ Transport -----------------------------------------------------

pub trait Transport {
    type Write: Write;
    type Read: Read;
    type Future: Future<Item=(Self::Read, Self::Write), Error=io::Error>;

    fn create(&self, reactor: &reactor::Handle) -> io::Result<Self::Future>;
}


