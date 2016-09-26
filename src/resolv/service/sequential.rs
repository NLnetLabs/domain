//! Service in single request mode.

use std::io;
use std::mem;
use std::time::{Duration, Instant};
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use rand;
use tokio_core::reactor::{self, Timeout};
use ::resolv::error::Error;
use ::resolv::request::{RequestReceiver, ServiceRequest};
use ::resolv::transport::{Transport, Write};
use ::resolv::utils::{IoStreamFuture, Passthrough, TimeoutFuture};
use super::ExpiringService;


//------------ Service -------------------------------------------------------

/// A service in single request mode.
pub struct Service<T: Transport> {
    reactor: reactor::Handle,
    request_timeout: Duration,
    state: State<T>
}

enum State<T: Transport> {
    Receiving(Passthrough<IoStreamFuture<RequestReceiver>,
                          (T::Read, T::Write)>),
    Writing(Passthrough<<T::Write as Write>::Future, 
                        (T::Read, RequestReceiver)>),
    Reading(Passthrough<TimeoutFuture<IoStreamFuture<T::Read>>, 
                        (ServiceRequest, Instant, RequestReceiver, T::Write)>),
    Done(Option<RequestReceiver>),
}


//--- ExpiringService

impl<T: Transport> ExpiringService<T> for Service<T> {
    fn create(rd: T::Read, wr: T::Write, receiver: RequestReceiver,
              mut request: ServiceRequest, reactor: reactor::Handle,
              request_timeout: Duration) -> Self {
        request.set_id(rand::random());
        let wr = wr.write(request);
        Service {
            reactor: reactor,
            request_timeout: request_timeout,
            state: State::Writing(Passthrough::new(wr, (rd, receiver)))
        }
    }

    fn take(&mut self) -> Option<RequestReceiver> {
        match mem::replace(&mut self.state, State::Done(None)) {
            State::Receiving(mut fut) => fut.future_mut().take(),
            State::Writing(mut fut) => fut.take().map(|(_, res)| res),
            State::Reading(mut fut) => fut.take().map(|res| res.2),
            State::Done(mut receiver) => receiver.take(),
        }
    }
}


//--- Stream

impl<T: Transport> Stream for Service<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        let state = match self.state {
            State::Receiving(ref mut fut) => {
                let ((item, receiver), (rd, wr)) = try_ready!(fut.poll());
                if let Some(mut request) = item {
                    request.set_id(rand::random());
                    let wr = wr.write(request);
                    State::Writing(Passthrough::new(wr, (rd, receiver)))
                }
                else {
                    State::Done(None)
                }
            }
            State::Writing(ref mut fut) => {
                let ((wr, request), (rd, receiver)) = match fut.poll() {
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Ok(Async::Ready(item)) => item,
                    Err((err, req)) => {
                        req.fail(Error::Timeout);
                        return Err(err)
                    }
                };
                let at = Instant::now() + self.request_timeout;
                let timeout = Timeout::new_at(at, &self.reactor).ok();
                let future = TimeoutFuture::new(rd.into(), timeout);
                State::Reading(Passthrough::new(future,
                                                (request, at, receiver, wr)))
            }
            State::Reading(ref mut fut) => {
                let (item, (request, at, receiver, wr))
                                        = try_ready!(fut.poll());
                if let Some((response, rd)) = item {
                    if let Some(response) = response {
                        if request.id() == response.header().id() {
                            request.response(response);
                            State::Receiving(Passthrough::new(receiver.into(),
                                                               (rd, wr)))
                        }
                        else {
                            let timeout = Timeout::new_at(at, &self.reactor);
                            let fut = TimeoutFuture::new(rd.into(),
                                                         timeout.ok());
                            State::Reading(Passthrough::new(fut,
                                                            (request, at,
                                                             receiver, wr)))
                        }
                    }
                    else {
                        State::Done(Some(receiver))
                    }
                }
                else {
                    request.fail(Error::Timeout);
                    State::Done(Some(receiver))
                }
            }
            State::Done(_) => panic!("polling a resolved service")
        };
        self.state = state;
        match self.state {
            State::Done(_) => Ok(Async::Ready(None)),
            State::Writing(_) => {
                try!(self.poll());
                Ok(Async::Ready(Some(())))
            }
            _ => self.poll()
        }
    }
}

