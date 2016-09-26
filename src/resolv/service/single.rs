//! Service in single request mode.

use std::io;
use std::time::{Duration, Instant};
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use rand;
use tokio_core::reactor::{self, Timeout};
use ::resolv::conf::ServerConf;
use ::resolv::error::Error;
use ::resolv::request::{RequestReceiver, ServiceRequest};
use ::resolv::transport::{Transport, Write};
use ::resolv::utils::{IoStreamFuture, Passthrough, TimeoutFuture};


//------------ Service -------------------------------------------------------

/// A service in single request mode.
pub struct Service<T: Transport> {
    receiver: RequestReceiver,
    transport: T,
    reactor: reactor::Handle,
    request_timeout: Duration,
    state: State<T>
}

enum State<T: Transport> {
    Idle,
    Connecting(Passthrough<T::Future, ServiceRequest>),
    Writing(Passthrough<<T::Write as Write>::Future, T::Read>),
    Reading(Passthrough<TimeoutFuture<IoStreamFuture<T::Read>>, 
                        (ServiceRequest, Instant)>),
}


impl<T: Transport> Service<T> {
    pub fn new(receiver: RequestReceiver, transport: T,
               reactor: reactor::Handle, conf: &ServerConf) -> Self {
        Service {
            receiver: receiver,
            transport: transport,
            reactor: reactor,
            request_timeout: conf.request_timeout,
            state: State::Idle
        }
    }
}


//--- Future

impl<T: Transport> Future for Service<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        let state = match self.state {
            State::Idle => {
                if let Some(request) = try_ready!(self.receiver.poll()) {
                    let fut = try!(self.transport.create(&self.reactor));
                    State::Connecting(Passthrough::new(fut, request))
                }
                else {
                    return Ok(().into())
                }
            }
            State::Connecting(ref mut fut) => {
                let ((rd, wr), mut request) = try_ready!(fut.poll());
                request.set_id(rand::random());
                let wr = wr.write(request);
                State::Writing(Passthrough::new(wr, rd))
            }
            State::Writing(ref mut fut) => {
                let ((_, request), rd) = match fut.poll() {
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Ok(Async::Ready(item)) => item,
                    Err((err, req)) => {
                        req.fail(Error::Timeout);
                        return Err(err)
                    }
                };
                let at = Instant::now() + self.request_timeout;
                let timeout = Timeout::new_at(at, &self.reactor).ok();
                State::Reading(Passthrough::new(TimeoutFuture::new(rd.into(),
                                                                   timeout),
                                                (request, at)))
            }
            State::Reading(ref mut fut) => {
                let (item, (request, at)) = try_ready!(fut.poll());
                if let Some((response, rd)) = item {
                    if let Some(response) = response {
                        if request.id() == response.header().id() {
                            request.response(response);
                            State::Idle
                        }
                        else {
                            let timeout = reactor::Timeout::new_at(at,
                                                                &self.reactor);
                            let fut = TimeoutFuture::new(rd.into(),
                                                         timeout.ok());
                            State::Reading(Passthrough::new(fut,
                                                            (request, at)))
                        }
                    }
                    else {
                        return Ok(().into())
                    }
                }
                else {
                    request.fail(Error::Timeout);
                    State::Idle
                }
            }
        };
        self.state = state;
        self.poll()
    }
}

