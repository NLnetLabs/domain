//! Utility types for networking.

use tokio::prelude::{Async, Future};


//------------ DecoratedFuture -----------------------------------------------

/// A future that stores data until resolved.
///
/// This future takes a future and some additional data. If the inner future
/// resolves successfully, the decorated future will return both the inner
/// future’s result as well as the data.
#[derive(Debug)]
pub struct DecoratedFuture<F, T>(F, Option<T>);

impl<F, T> DecoratedFuture<F, T> {
    pub fn new(fut: F, data: T) -> Self {
        DecoratedFuture(fut, Some(data))
    }
}

impl<F: Future, T> Future for DecoratedFuture<F, T> {
    type Item = (F::Item, T);
    type Error = F::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        Ok(Async::Ready((
            try_ready!(self.0.poll()),
            self.1.take().expect("polling a resolved future")
        )))
    }
}

