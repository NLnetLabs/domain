//! Tools for building stream-oriented DNS transports.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::mpsc;
use vecio::Rawv;
use bits::message::MessageBuf;
use rand::random;
use resolv::conf::ResolvConf;
use rotor::Time;
use super::conn::{ConnCommand, ConnTransportSeed};
use super::query::Query;
use super::sync::RotorSender;
use super::timeout::TimeoutQueue;


//------------ StreamTransportInfo ------------------------------------------

/// Information necessary for running a stream-based DNS transport.
pub struct StreamTransportInfo {
    /// Query map.
    ///
    /// This actually contains all the IDs that are currently in use. If the
    /// value is `None`, the respective query is still stuck in the send
    /// queue.
    queries: HashMap<u16, Option<Query>>,

    /// Send queue.
    send_queue: StreamQueryWriter,

    /// The timeouts for the pending queries represented by their ID.
    ///
    /// Incidentally, these are also the queries waiting for a response.
    timeouts: TimeoutQueue<u16>,

    /// The receiving end of the command queue.
    commands: mpsc::Receiver<ConnCommand>,

    /// The sending end of the dispatcher’s query queue.
    failed: RotorSender<Query>,

    /// The socket address for connecting.
    addr: SocketAddr,

    /// The configuration.
    conf: ResolvConf,
} 


impl StreamTransportInfo {
    pub fn new(seed: ConnTransportSeed) -> Self {
        StreamTransportInfo {
            queries: HashMap::new(),
            send_queue: StreamQueryWriter::new(),
            timeouts: TimeoutQueue::new(),
            commands: seed.commands,
            failed: seed.queries,
            addr: seed.addr,
            conf: seed.conf,
        }
    }

    pub fn addr(&self) -> &SocketAddr { &self.addr }
    pub fn conf(&self) -> &ResolvConf { &self.conf }

    pub fn can_read(&self) -> bool { !self.timeouts.is_empty() }
    pub fn can_write(&self) -> bool { self.send_queue.can_write() }

    /// Processes the command queue.
    ///
    /// Returns whether a close command was received.
    pub fn process_commands(&mut self) -> bool {
        loop {
            match self.commands.try_recv() {
                Ok(ConnCommand::Query(query)) => self.incoming_query(query),
                Ok(ConnCommand::Close) => return true,
                Err(mpsc::TryRecvError::Empty) => return false,
                Err(mpsc::TryRecvError::Disconnected) => return true,
            }
        }
    }

    fn incoming_query(&mut self, mut query: Query) {
        let mut id = random();
        while self.queries.contains_key(&id) {
            id = random();
        }
        query.request_mut().header_mut().set_id(id);
        self.queries.insert(id, None);
        self.send_queue.push(query);
    }

    /// Process the command queue by rejecting all queries.
    ///
    /// Returns whether a close command was received.
    pub fn reject_commands(&mut self) -> bool {
        let mut close = false;
        loop {
            match self.commands.try_recv() {
                Ok(ConnCommand::Query(query)) => query.send(),
                Ok(ConnCommand::Close) => close = true,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => close = true,
            }
        }
        close
    }

    pub fn write<W: Rawv>(&mut self, w: &mut W, now: Time) -> io::Result<()> {
        try!(self.send_queue.write(w));
        while let Some(query) = self.send_queue.done.pop_front() {
            self.timeouts.push(now + self.conf.timeout, query.id());
            self.queries.insert(query.id(), Some(query));
        }
        Ok(())
    }

    pub fn process_response(&mut self, response: MessageBuf) {
        let mut query = match self.queries.remove(&response.header().id()) {
            Some(Some(query)) => query,
            _ => return, // XXX Log
        };
        if !response.is_answer(&query.request()) {
            self.queries.insert(query.request().header().id(), Some(query));
            return;
        }
        query.set_response(Ok(response));
        query.send()
    }

    pub fn process_timeouts(&mut self, now: Time) {
        while let Some(id) = self.timeouts.pop_expired(now) {
            self.failed.send(self.queries.remove(&id).unwrap().unwrap()).ok();
        }
    }

    pub fn next_timeout(&mut self) -> Option<Time> {
        {
            let (timeouts, queries) = (&mut self.timeouts, &self.queries);
            timeouts.clean_head(|x| !queries.contains_key(&x));
        }
        self.timeouts.next_timeout()
    }

    pub fn flush_timeouts(&mut self) {
        while let Some(id) = self.timeouts.pop() {
            self.failed.send(self.queries.remove(&id).unwrap().unwrap()).ok();
        }
    }
}


//------------ StreamQueryWriter --------------------------------------------

pub struct StreamQueryWriter {
    /// The queries we still need to write.
    pending: VecDeque<WriterItem>,

    /// How far into writing the head item of the queue are we?
    written: usize,

    /// The queries we are done with.
    done: VecDeque<Query>,
}

impl StreamQueryWriter {
    /// Creates a new writer.
    pub fn new() -> StreamQueryWriter {
        StreamQueryWriter {
            pending: VecDeque::new(),
            written: 0,
            done: VecDeque::new(),
        }
    }

    /// Pushes a new query to the end of the queue.
    pub fn push(&mut self, query: Query) {
        // XXX Deal with overlong messages.
        let size = query.request_data().len() as u16;
        self.pending.push_back(WriterItem::Size( unsafe {
            mem::transmute(size.to_be())
        }));
        self.pending.push_back(WriterItem::Query(query));
    }

    /// Do we have something to sing about?
    pub fn can_write(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Writes.
    pub fn write<W: Rawv>(&mut self, w: &mut W) -> io::Result<()> {
        let mut written = {
            let mut buf = Vec::<&[u8]>::new();
            let mut iter = self.pending.iter();
            match iter.next() {
                None => return Ok(()),
                Some(item) => {
                    assert!(item.len() > self.written);
                    buf.push(&item.data()[self.written..]);
                }
            }
            for item in iter {
                buf.push(item.data());
            }
            try!(w.writev(&buf))
        };
        while written > 0 {
            let item_len = self.pending.front().unwrap().len();
            if item_len > written {
                self.written = written;
                break;
            }
            else {
                written -= item_len;
                match self.pending.pop_front().unwrap() {
                    WriterItem::Query(query) => self.done.push_back(query),
                    _ => ()
                }
            }
        }
        Ok(())
    }
}


//------------ WriterItem ---------------------------------------------------

enum WriterItem {
    Size([u8; 2]),
    Query(Query),
}

impl WriterItem {
    fn data(&self) -> &[u8] {
        match *self {
            WriterItem::Size(ref data) => &data[..],
            WriterItem::Query(ref query) => query.request_data(),
        }
    }

    fn len(&self) -> usize {
        self.data().len()
    }
}


//------------ StreamReader -------------------------------------------------

pub struct StreamReader {
    item: ReaderItem,
    read: usize,
}

impl StreamReader {
    pub fn new() -> Self {
        StreamReader { item: ReaderItem::size(), read: 0 }
    }

    pub fn read<R: io::Read>(&mut self, r: &mut R)
                             -> io::Result<Option<MessageBuf>> {
        loop {
            let size = {
                let buf = &mut self.item.buf()[self.read..];
                match r.read(buf) {
                    Ok(0) => {
                        return Err(io::Error::new(
                                            io::ErrorKind::ConnectionAborted,
                                            "closed"))
                    }
                    Ok(size) => size,
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock
                        => return Ok(None),
                    Err(err) => return Err(err)
                }
            };
            self.read += size;
            if self.read == self.item.len() {
                let next_item = self.item.next_item();
                let item = mem::replace(&mut self.item, next_item);
                match item.finish() {
                    Some(message) => return Ok(Some(message)),
                    None => ()
                }
            }
            else {
                return Ok(None)
            }
        }
    }
}

enum ReaderItem {
    Size([u8; 2]),
    Message(Vec<u8>),
}

impl ReaderItem {
    fn size() -> Self {
        ReaderItem::Size([0; 2])
    }

    fn message(size: u16) -> Self {
        ReaderItem::Message(vec![0; size as usize])
    }

    fn buf(&mut self) -> &mut [u8] {
        match *self {
            ReaderItem::Size(ref mut data) => data,
            ReaderItem::Message(ref mut data) => data,
        }
    }

    fn len(&self) -> usize {
        match *self {
            ReaderItem::Size(_) => 2,
            ReaderItem::Message(ref data) => data.len(),
        }
    }

    fn next_item(&self) -> Self {
        match *self {
            ReaderItem::Size(ref data) => {
                let size = u16::from_be(unsafe { mem::transmute(*data) });
                ReaderItem::message(size)
            }
            ReaderItem::Message(_) => ReaderItem::size()
        }
    }

    fn finish(self) -> Option<MessageBuf> {
        match self {
            ReaderItem::Size(_) => None,
            // XXX Simply drops short messages. Should we log?
            ReaderItem::Message(data) => MessageBuf::from_vec(data).ok()
        }
    }
}


