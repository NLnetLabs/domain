//! Service in request multiplexing mode.

use std::collections::{HashMap, VecDeque};
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
use super::ExpiringService;


//------------ Service -------------------------------------------------------

/// A service in multiplex mode.
pub struct Service<T: Transport> {
    receiver: Option<RequestReceiver>,
    write: Writer<T>,
    read: T::Read,
    pending: PendingRequests
}


//--- ExpiringService

impl<T: Transport> ExpiringService<T> for Service<T> {
    fn create(rd: T::Read, wr: T::Write, receiver: RequestReceiver,
              request: ServiceRequest, reactor: reactor::Handle,
              request_timeout: Duration) -> Self {
        let mut pending = PendingRequests::new(reactor.clone(),
                                               request_timeout);
        let mut write = Writer::new(wr);
        write.write(request, &mut pending);
        Service {
            receiver: Some(receiver),
            write: write,
            read: rd,
            pending: pending
        }
    }

    fn take(&mut self) -> Option<RequestReceiver> {
        self.receiver.take()
    }
}


//--- Stream and Helper Methods for Stream

impl<T: Transport> Stream for Service<T> {
    type Item = ();
    type Error = io::Error;

    /// Polls the stream.
    ///
    /// This needs to return some ready whenever the outer timeout needs to
    /// be reset, ie., whenever we got a new request from the receiver. It
    /// needs to return ready none when the socket closed, ie., either the
    /// `self.read` or `self.write` are done.
    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        self.pending.expire();
        if let Async::Ready(item) = try!(self.poll_read()) {
            return Ok(Async::Ready(item))
        }
        self.poll_send()
    }
}


impl<T: Transport> Service<T> {
    /// Does the reading.
    ///
    /// Reads until there is nothing more to read and processes any messages
    /// received that way. Returns ready or an error if the outer function
    /// should return ready or an error and not ready if the outer function
    /// should continue with its business.
    fn poll_read(&mut self) -> Poll<Option<()>, io::Error> {
        while let Some(response) = try_ready!(self.read.poll()) {
            let id = response.header().id();
            if let Some(request) = self.pending.pop(id) {
                request.response(response)
            }
        }
        Ok(Async::Ready(None))
    }

    /// Does everything related to sending out requests.
    ///
    /// Returns whatever the outer poll ought to return.
    ///
    /// Tries to finish writing if necessary, then fetches a new request and
    /// starts again. If we did fetch a new request, we need to return some
    /// ready. If the receiver went away, we need to pretend we are still
    /// writing until all pending requests are either resolved or have
    /// expired.
    fn poll_send(&mut self) -> Poll<Option<()>, io::Error> {
        let mut res = Async::NotReady;
        loop {
            match try!(self.poll_write()) {
                Async::NotReady => return Ok(res),
                Async::Ready(Some(())) => { }
                Async::Ready(None) => return Ok(Async::Ready(None))
            }
            match try_ready!(self.poll_receiver()) {
                Some(()) => res = Async::Ready(Some(())),
                None => return Ok(Async::Ready(None))
            }
        }
    }

    /// Does the writing.
    ///
    /// Returns some ready if it is done writing or doesn’t have anything to
    /// write, none ready if the writer is gone and all requests are done,
    /// not ready if it needs to write some more but can’t and error
    /// if there is an error.
    fn poll_write(&mut self) -> Poll<Option<()>, io::Error> {
        let (wr, request) = match self.write {
            Writer::Idle(..) => return Ok(Async::Ready(Some(()))),
            Writer::Writing(ref mut fut) => {
                match fut.poll() {
                    Ok(Async::Ready(item)) => item,
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Err((err, request)) => {
                        self.pending.unreserve(request.id());
                        request.fail(Error::Timeout);
                        return Err(err)
                    }
                }
            }
            Writer::Closed => {
                if self.pending.is_empty() { return Ok(Async::Ready(None)) }
                else { return Ok(Async::NotReady) }
            }
        };
        self.write = Writer::Idle(wr);
        self.pending.push(request);
        Ok(Async::Ready(Some(())))
    }

    /// Polls the receiver if necessary.
    ///
    /// Tries to get a new request from the receiver if we don’t
    /// currently have anything to write. Or, if we don’t have a receiver
    /// anymore and no more pending requests either, we are done.
    ///
    /// Returns some ready if there is something to write, returns
    /// none ready if the receiver is disconnected and everything has
    /// expired, not ready if we are waiting for a new request (which sorta
    /// is also the case if the receiver has disconnected and there is still
    /// pending requests left), and error for an error.
    fn poll_receiver(&mut self) -> Poll<Option<()>, io::Error> {
        let request = if let Some(ref mut receiver) = self.receiver {
            try_ready!(receiver.poll())
        }
        else { None };
        let request = if let Some(request) = request { request }
        else {
            self.receiver = None;
            if self.pending.is_empty() { return Ok(Async::Ready(None)) }
            else { return Ok(Async::NotReady) }
        };
        self.write.write(request, &mut self.pending);
        Ok(Async::Ready(Some(())))
    }
}


//------------ Writer -------------------------------------------------------

enum Writer<T: Transport> {
    Idle(T::Write),
    Writing(<T::Write as Write>::Future),
    Closed
}

impl<T: Transport> Writer<T> {
    fn new(wr: T::Write) -> Self {
        Writer::Idle(wr)
    }

    fn write(&mut self, mut request: ServiceRequest,
           pending: &mut PendingRequests) {
        let wr = match mem::replace(self, Writer::Closed) {
            Writer::Idle(wr) => wr,
            _ => unreachable!()
        };
        *self = match pending.reserve() {
            Ok(id) => {
                request.set_id(id);
                Writer::Writing(wr.write(request))
            }
            Err(_) => {
                request.fail(io::Error::new(io::ErrorKind::Other,
                                            "too many requests").into());
                Writer::Idle(wr)
            }
        }
    }
}


//------------ PendingRequests -----------------------------------------------

/// A collection of pending requests.
pub struct PendingRequests {
    /// A map from DNS message IDs to requests.
    ///
    /// If an ID is reserved, it maps to `None`, if a request has been
    /// pushed for it, it maps to `Some(_)`.
    requests: HashMap<u16, Option<ServiceRequest>>,

    /// An ordered list of message IDs and when they expire.
    ///
    /// Since we have a fixed duration and monotone time, we can use a
    /// simple deque here and push new requests to its end.
    expires: VecDeque<(u16, Instant)>,

    /// The optional future for the next time a request expires.
    timeout: Option<Timeout>,

    /// A handle to a reactor for creating timeout futures.
    reactor: reactor::Handle,

    /// The duration until a request expires.
    duration: Duration,
}

impl PendingRequests {
    /// Creates a new collection.
    pub fn new(reactor: reactor::Handle, expire: Duration) -> Self {
        PendingRequests {
            requests: HashMap::new(),
            expires: VecDeque::new(),
            timeout: None,
            reactor: reactor,
            duration: expire
        }
    }

    /// Returns whether there are no more pending requests.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Reserves a spot in the map and returns its ID.
    pub fn reserve(&mut self) -> Result<u16, ReserveError> {
        use std::collections::hash_map::Entry;

        // Pick a reasonably low number here so that we won’t hang too long
        // below.
        if self.requests.len() > 0xA000 {
            return Err(ReserveError);
        }
        // XXX I suppose there is a better way to do this. Anyone?
        loop {
            let id = rand::random();
            if let Entry::Vacant(entry) = self.requests.entry(id) {
                entry.insert(None);
                return Ok(id)
            }
        }
    }

    /// Drop a previously reserved id.
    pub fn unreserve(&mut self, id: u16) {
        match self.requests.remove(&id) {
            Some(Some(_)) => panic!("unreserving pushed ID"),
            Some(None) => { }
            None => panic!("unreserving unreserved ID")
        }
    }

    /// Adds the requests with the given ID to the collection.
    ///
    /// The `id` must have been reserved before and nothing been pushed
    /// for this ID since. Panics otherwise.
    pub fn push(&mut self, request: ServiceRequest) {
        let id = request.id();
        {
            let entry = self.requests.get_mut(&id)
                                     .expect("pushed unreserved ID");
            if entry.is_some() {
                panic!("pushed over existing ID");
            }
            *entry = Some(request);
        }
        self.expires.push_back((id, Instant::now() + self.duration));
        if self.timeout.is_none() {
            self.update_timeout();
        }
    }
    
    /// Removes and returns the request with the given ID.
    pub fn pop(&mut self, id: u16) -> Option<ServiceRequest> {
        if let Some(request) = self.requests.remove(&id) {
            if self.expires.front().unwrap().0 == id {
                self.expires.pop_front();
                self.update_timeout();
            }
            request
        }
        else { None }
    }

    /// Updates the timeout.
    ///
    /// Since we don’t delete the IDs in `pop()` (which could be expensive
    /// if they are somewhere in the middle), we need to pop items from the
    /// front until we find one that is actually still valid.
    fn update_timeout(&mut self) {
        while let Some(&(id, at)) = self.expires.front() {
            if self.requests.contains_key(&id) {
                // XXX What’s the best thing to do when getting a timeout
                //     fails?
                self.timeout = Timeout::new_at(at, &self.reactor).ok();
                return;
            }
            else {
                self.expires.pop_front();
            }
        }
        self.timeout = None
    }

    /// Removes and fails all expired requests.
    ///
    /// This method polls `self`’s timeout so it can only be called from
    /// within a task.
    pub fn expire(&mut self) {
        match self.timeout {
            Some(ref mut timeout) => {
                match timeout.poll() {
                    Ok(Async::NotReady) => return,
                    Ok(Async::Ready(())) => {
                        loop {
                            match self.expires.front() {
                                Some(&(_, at)) if at > Instant::now() => { }
                                _ => break
                            }
                            let id = self.expires.pop_front().unwrap().0;
                            if let Some(Some(item)) = self.requests
                                                          .remove(&id) {
                                item.fail(Error::Timeout)
                            }
                        }
                    }
                    Err(_) => {
                        // Fall through to update_timeout to perhaps fix
                        // the broken timeout.
                    }
                }
            }
            None => return
        }
        self.update_timeout();
        // Once more to register the timeout.
        self.expire()
    }
}


//--- Drop

impl Drop for PendingRequests {
    fn drop(&mut self) {
        for (_, item) in self.requests.drain() {
            if let Some(item) = item {
                item.fail(Error::Timeout)
            }
        }
    }
}


//------------ ReserveError --------------------------------------------------

/// An error happened while reserving an ID.
///
/// The only thing that can happen is that we run out of space.
pub struct ReserveError;

