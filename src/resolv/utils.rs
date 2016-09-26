/// Various useful things.

use std::io;
use std::mem;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::reactor::Timeout;


//------------ Passthrough ---------------------------------------------------

pub struct Passthrough<F: Future, T> {
    future: F,
    data: Option<T>
}

impl<F: Future, T> Passthrough<F, T> {
    pub fn new(future: F, data: T) -> Self {
        Passthrough{future: future, data: Some(data)}
    }

    pub fn take(&mut self) -> Option<T> {
        self.data.take()
    }

    pub fn future_mut(&mut self) -> &mut F {
        &mut self.future
    }
}

impl<F: Future, T> Future for Passthrough<F, T> {
    type Item = (F::Item, T);
    type Error = F::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let item = try_ready!(self.future.poll());
        let data = mem::replace(&mut self.data, None);
        if let Some(data) = data {
            Ok((item, data).into())
        }
        else {
            panic!("polled a resolved Passthrough")
        }
    }
}


//------------ TimeoutFuture -------------------------------------------------

pub struct TimeoutFuture<F: Future<Error=io::Error>> {
    future: F,
    timeout: Option<Timeout>
}

impl<F: Future<Error=io::Error>> TimeoutFuture<F> {
    pub fn new(future: F, timeout: Option<Timeout>) -> Self {
        TimeoutFuture{future: future, timeout: timeout}
    }
}

impl<F: Future<Error=io::Error>> Future for TimeoutFuture<F> {
    type Item = Option<F::Item>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<F::Item>, io::Error> {
        if let Async::Ready(item) = try!(self.future.poll()) {
            Ok(Async::Ready(Some(item)))
        }
        else if let Some(ref mut timeout) = self.timeout {
            try_ready!(timeout.poll());
            Ok(Async::Ready(None))
        }
        else {
            Ok(Async::NotReady)
        }
    }
}


//------------ IoStreamFuture ------------------------------------------------

pub struct IoStreamFuture<S: Stream<Error=io::Error>>(Option<S>);

impl<S: Stream<Error=io::Error>> IoStreamFuture<S> {
    pub fn new(s: S) -> Self {
        IoStreamFuture(Some(s))
    }

    pub fn take(&mut self) -> Option<S> {
        self.0.take()
    }
}

impl<S: Stream<Error=io::Error>> Future for IoStreamFuture<S> {
    type Item = (Option<S::Item>, S);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let item = {
            let stream = self.0.as_mut()
                             .expect("polled a resolved IoStreamFuture");
            match stream.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(item)) => Ok(item),
                Err(err) => Err(err),
            }
        };
        let stream = self.0.take().unwrap();
        item.map(|item| (item, stream).into())
    }
}

impl<S: Stream<Error=io::Error>> From<S> for IoStreamFuture<S> {
    fn from(s: S) -> Self {
        Self::new(s)
    }
}

