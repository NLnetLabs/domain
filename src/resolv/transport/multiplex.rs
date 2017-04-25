//! A transport that multiplexes requests.

use std::io;
use std::time::Duration;
use futures::{Async, AsyncSink, Future, Poll, Stream};
use tokio_core::reactor;
use super::super::channel::Channel;
use super::super::conf::ServerConf;
use super::super::request::{RequestReceiver, TransportRequest};
use super::pending::PendingRequests;


//------------ Transport -----------------------------------------------------

/// A transport that multiplexes requests over a single socket.
///
/// The transport will send out all requests received immediately and then
/// keep them in a map. Whenever it receives a response, it tries to find
/// the matching request and resolve it.
///
/// Requests for which there are no responses received within the time
/// given by the config’s request timeout are being failed with a timeout
/// error.
///
/// The transport will use the configuration’s keep alive duration as an
/// indicator for how long to keep a channel active when there are no new
/// requests.
pub struct Transport<C: Channel> {
    /// The receiver for new requests.
    ///
    /// This gets switched to `None` when the receiver gets disconnected or
    /// taken away by the expiring wrapper. If that has happened, we wait
    /// until all pending request have expired and then end the stream.
    receiver: Option<RequestReceiver>,

    /// The underlying channel.
    channel: C,

    /// The duration before we send the channel to sleep.
    keep_alive: Duration,

    /// A map with all the requests currently in flight.
    pending: PendingRequests,

    /// A timeout that is started whenever we run out of requests.
    ///
    /// When it fires, we send the channel to sleep.
    sleep_timeout: Option<reactor::Timeout>,

    /// A request that is waiting to be sent.
    send_request: Option<TransportRequest>,
}


impl<C: Channel> Transport<C> {
    /// Creates a new multiplexing transport.
    pub fn new(receiver: RequestReceiver, channel: C,
               reactor: reactor::Handle, conf: &ServerConf) -> Self {
        Transport {
            receiver: Some(receiver),
            channel: channel,
            keep_alive: conf.keep_alive,
            pending: PendingRequests::new(reactor, conf.request_timeout),
            sleep_timeout: None,
            send_request: None,
        }
    }
}

impl<C: Channel + 'static> Transport<C> {
    /// Spawns a new multiplxing transport into a reactor.
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
        match self.poll_step() {
            Ok(()) => Ok(Async::NotReady),
            Err(_) => {
                self.pending.fail_all();
                self.receiver = None;
                Ok(Async::Ready(()))
            }
        }
    }
}

impl<C: Channel> Transport<C> {
    /// Does everything necessary for a single poll.
    ///
    /// If this returns `Ok(())`, then polling is done and
    /// `Ok(Async::NotReady)` should be returned by the `poll()` method.
    /// 
    /// Any errors happening are passed straight through and need to be
    /// sorted out by the `poll()` method.
    fn poll_step(&mut self) -> io::Result<()> {
        self.poll_sleep()?;
        self.poll_recv()?;
        self.poll_send()?;
        self.pending.expire();
        self.set_sleep_timeout()?;
        Ok(())
    }

    /// Reads and processes responses until reading blocks.
    fn poll_recv(&mut self) -> io::Result<()> {
        while let Async::Ready(response) = self.channel.poll_recv()? {
            let id = response.header().id();
            if let Some(request) = self.pending.pop(id) {
                request.response(response);
            }
        }
        Ok(())
    }

    /// Sends out requests until either writing blocks or there are no more.
    fn poll_send(&mut self) -> io::Result<()> {
        loop {
            match self.channel.poll_send()? {
                Async::NotReady => return Ok(()),
                Async::Ready(None) => { }
                Async::Ready(Some(request)) => {
                    self.pending.push(request)
                }
            }
            self.get_send_request()?;
            if self.send_request.is_none() {
                return Ok(())
            }
            self.start_send()?;
        }
    }

    /// Attempts to provide a send request.
    ///
    /// If available, a request is placed in `self.send_request`. If there
    /// is no requests at this time, `self.send_request` is left at `None`-
    fn get_send_request(&mut self) -> io::Result<()> {
        if self.send_request.is_some() {
            return Ok(())
        }
        match self.receiver {
            None => return Ok(()),
            Some(ref mut receiver) => {
                match receiver.poll() {
                    Ok(Async::NotReady) => return Ok(()),
                    Ok(Async::Ready(Some(request))) => {
                        self.send_request = self.pending
                                                .prepare_request(request);
                        self.sleep_timeout = None;
                        return Ok(())
                    }
                    Ok(Async::Ready(None)) | Err(_) => {
                        // Fall through to drop the receiver.
                    }
                }
            }
        }
        self.receiver = None;
        Ok(())
    }

    /// Attempts to start sending a request.
    fn start_send(&mut self) -> io::Result<()> {
        let request = match self.send_request.take() {
            None => return Ok(()),
            Some(request) => request
        };
        if let AsyncSink::NotReady(request)
                    = self.channel.start_send(request)? {
            self.send_request = Some(request)
        }
        Ok(())
    }

    /// Checks if the sleep timeout expired and sends the channel to sleep.
    fn poll_sleep(&mut self) -> io::Result<()> {
        match self.sleep_timeout {
            None => return Ok(()),
            Some(ref mut timeout) => {
                if let Async::NotReady = timeout.poll()? {
                    return Ok(())
                }
            }
        }
        self.channel.sleep()?;
        self.sleep_timeout = None;
        Ok(())
    }

    /// Sets the sleep timer if necessary.
    fn set_sleep_timeout(&mut self) -> io::Result<()> {
        if self.sleep_timeout.is_none() && self.pending.is_empty() {
            self.sleep_timeout
                = Some(reactor::Timeout::new(self.keep_alive,
                                             self.pending.reactor())?);
        }
        Ok(())
    }
}

