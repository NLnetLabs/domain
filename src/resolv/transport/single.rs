//! A transport that sends requests sequentially, sleeping between requests.
use std::io;
use std::time::Duration;
use rand::random;
use futures::{Async, AsyncSink, Future, Poll, Stream};
use tokio_core::reactor;
use super::super::channel::Channel;
use super::super::conf::ServerConf;
use super::super::request::{RequestReceiver, TransportRequest};


//------------ Transport -----------------------------------------------------

/// A transport that sends requests sequentially, sleeping between requests.
///
/// The transport will send one request, wait for its response, discarding any
/// other responses, resolve the request, send the channel to sleep 
/// thereby causing it to close the socket, and then wait for the next
/// request.
///
/// A request will time out if a response isn’t received within the time
/// given by the config’s request timeout. If no new request is received
/// for the time given by the config’s keep alive duration, the underlying
/// channel will be sent to sleep.
pub struct Transport<C: Channel> {
    /// The request receiver.
    receiver: RequestReceiver,

    /// The underlying channel.
    channel: C,

    /// The duration before a request expires.
    request_timeout: Duration,

    /// A reactor handle for creating timeouts futures.
    reactor: reactor::Handle,

    /// The current operational state.
    state: State,

    /// The request we are currently processing.
    ///
    /// Whether there is one depends on the state. Not having this be part
    /// of the respective variants of the `State` enum safes us having to
    /// temporarily `mem::replace()` the state all the time at the price of
    /// possible inconsistencies and, therefore, panics.
    request: Option<TransportRequest>
}

enum State {
    /// Waiting for a new request to arrive.
    Idle,

    /// A request is ready to be enqueued with the channel.
    ///
    /// In this state, `self.request´ must contain a request.
    Starting,

    /// The channel is currently sending the request.
    Sending,

    /// Waiting to receive a response from the channel.
    ///
    /// The included timer is started with the request timeout once the
    /// request has been sent.
    ///
    /// In this state, `self.request´ must contain a request.
    Receiving(reactor::Timeout),

    /// The receiver has closed down or the channel errored out.
    Closed,
}

impl<C: Channel> Transport<C> {
    /// Creates a new single-request transport.
    pub fn new(receiver: RequestReceiver, channel: C,
               reactor: reactor::Handle, conf: &ServerConf) -> Self {
        Transport {
            receiver: receiver,
            channel: channel,
            request_timeout: conf.request_timeout,
            reactor: reactor,
            state: State::Idle,
            request: None,
        }
    }
}

impl<C: Channel + 'static> Transport<C> {
    /// Spawns a new single-request transport into a reactor core.
    pub fn spawn(receiver: RequestReceiver, channel: C,
                 reactor: &reactor::Handle, conf: &ServerConf) {
        let transport = Self::new(receiver, channel, reactor.clone(), conf);
        reactor.spawn(transport);
    }
}


//--- Future

impl<C: Channel> Future for Transport<C> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<(), ()> {
        loop {
            match self.poll_step() {
                Ok(Async::Ready(State::Closed)) => {
                    assert!(self.request.is_none());
                    self.state = State::Closed;
                    return Ok(Async::Ready(()))
                }
                Ok(Async::Ready(state)) => self.state = state,
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Err(err) => {
                    if let Some(request) = self.request.take() {
                        request.fail(err.into())
                    }
                    self.state = State::Closed;
                    return Ok(Async::Ready(()));
                }
            }
        }
    }
}

impl<C: Channel> Transport<C> {
    /// A single poll step and return the new state.
    ///
    /// This method can be called repeatedly, replacing the state with the
    /// returned state until it returns `Ok(Async::NotReady)` at which time
    /// the loop should end.
    fn poll_step(&mut self) -> Poll<State, io::Error> {
        // Check for timeout first because this mutably references `self`
        // prohibiting calling `&mut self` methods.
        if let State::Receiving(ref mut timeout) = self.state {
            if let Async::Ready(()) = timeout.poll()? {
                let request = self.request.take().unwrap();
                request.timeout();
                return Ok(Async::Ready(State::Idle));
            }
        }
        match self.state {
            State::Idle => self.poll_idle(),
            State::Starting => self.poll_starting(),
            State::Sending => self.poll_sending(),
            State::Receiving(_) => self.poll_receiving(),
            State::Closed => panic!("polling a closed transport"),
        }
    }

    /// Polls in idle state.
    ///
    /// Checks if the receiver has a new message for us. Returns starting
    /// state if it does, not ready if it doesn’t and the closing state if
    /// the receiver has been closed.
    fn poll_idle(&mut self) -> Poll<State, io::Error> {
        match self.receiver.poll().unwrap() {
            Async::NotReady => return Ok(Async::NotReady),
            Async::Ready(None) => Ok(Async::Ready(State::Closed)),
            Async::Ready(Some(request)) => {
                self.request = Some(request);
                Ok(Async::Ready(State::Starting))
            }
        }
    }

    /// Polls in starting state.
    ///
    /// Tries to give the request to the channel for sending. This should
    /// normally always succeed unless there is a logic error somewhere.
    /// Returns sending state if it did indeed succeed and starting state
    /// if not.
    fn poll_starting(&mut self) -> Poll<State, io::Error> {
        let mut request = self.request.take().unwrap();
        request.set_id(random());
        match self.channel.start_send(request)? {
            AsyncSink::Ready => Ok(Async::Ready(State::Sending)),
            AsyncSink::NotReady(request) => {
                self.request = Some(request);
                Ok(Async::Ready(State::Starting))
            }
        }
    }

    /// Polls in sending state.
    ///
    /// Polls the channel for sending, returning sending state until it gets
    /// the request back, proceeding to receiving state.
    fn poll_sending(&mut self) -> Poll<State, io::Error> {
        self.request = try_ready!(self.channel.poll_send());
        assert!(self.request.is_some());
        let timeout = reactor::Timeout::new(self.request_timeout,
                                            &self.reactor)?;
        Ok(Async::Ready(State::Receiving(timeout)))
    }

    /// Polls in receiving state.
    ///
    /// Polls the channel for receiving, checking every response whether it
    /// is for the request and, if so, resolving the request and proceeding
    /// to idle state.
    fn poll_receiving(&mut self) -> Poll<State, io::Error> {
        let response = try_ready!(self.channel.poll_recv());
        if self.request.as_ref().unwrap().id().unwrap()
                    != response.header().id() {
            return Ok(Async::NotReady);
        }
        let request = self.request.take().unwrap();
        request.response(response);
        self.channel.sleep()?;
        Ok(Async::Ready(State::Idle))
    }
}

