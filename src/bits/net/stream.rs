//! Helper types for stream transports.

use std::{io, mem};
use std::collections::VecDeque;
use futures::Async;
use ::bits::MessageBuf;


//------------ StreamSend ----------------------------------------------------

pub struct StreamSend {
    queue: VecDeque<Vec<u8>>,
    pos: usize
}

impl StreamSend {
    pub fn new() -> Self {
        StreamSend {
            queue: VecDeque::new(),
            pos: 0
        }
    }

    pub fn send<W: io::Write>(&mut self, w: &mut W, msg: Vec<u8>)
                              -> io::Result<Async<()>> {
        self.queue.push_back(msg);
        self.flush(w)
    }

    pub fn flush<W: io::Write>(&mut self, w: &mut W)
                               -> io::Result<Async<()>> {
        loop {
            if let Some(item) = self.queue.front() {
                let written = try_nb!(w.write(&item[self.pos..]));
                if written == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero,
                                              "zero write"))
                }
                self.pos += written;
                if self.pos < item.len() {
                    // XXX We could return right away, but I think we need
                    //     run into a would block error which is most easily
                    //     achieved by trying to write again. Also, we may
                    //     for whatever reason be writable already.
                    continue;
                }
            }
            else {
                return Ok(Async::Ready(()))
            }
            self.queue.pop_front();
            self.pos = 0;
        }
    }
}


//------------ StreamRecv ----------------------------------------------------

pub struct StreamRecv {
    item: ReadItem,
    pos: usize
}


impl StreamRecv {
    pub fn new() -> Self {
        StreamRecv {
            item: ReadItem::size(),
            pos: 0
        }
    }

    pub fn recv<R: io::Read>(&mut self, reader: &mut R)
                             -> io::Result<Async<Option<MessageBuf>>> {
        loop {
            let size = {
                let buf = &mut self.item.buf()[self.pos..];
                try_nb!(reader.read(buf))
            };
            if size == 0 {
                return Ok(Async::Ready(None))
            }
            self.pos += size;
            if self.pos == self.item.len() {
                let next_item = self.item.next_item();
                self.pos = 0;
                let item = mem::replace(&mut self.item, next_item);
                if let Some(message) = item.finish() {
                    return Ok(Async::Ready(Some(message)))
                }
            }
        }
    }
}


//------------ ReadItem ------------------------------------------------------

/// A item to read on a stream transport.
enum ReadItem {
    /// The size shim preceeding the actual message.
    Size([u8; 2]),

    /// The actual message.
    ///
    /// The vector will start out with the size read first.
    Message(Vec<u8>),
}


impl ReadItem {
    /// Creates a new `ReadItem::Size` item.
    fn size() -> Self {
        ReadItem::Size([0; 2])
    }

    /// Creates a new `ReadItem::Messge` item of the given size.
    fn message(size: u16) -> Self {
        ReadItem::Message(vec![0; size as usize])
    }

    /// Returns the bytes buffer for current read item.
    fn buf(&mut self) -> &mut [u8] {
        match *self {
            ReadItem::Size(ref mut data) => data,
            ReadItem::Message(ref mut data) => data,
        }
    }

    /// Returns the size of the current read item.
    fn len(&self) -> usize {
        match *self {
            ReadItem::Size(_) => 2,
            ReadItem::Message(ref data) => data.len(),
        }
    }

    /// Returns the item that should replace the current item.
    fn next_item(&self) -> Self {
        match *self {
            ReadItem::Size(ref data) => {
                let size = u16::from_be(unsafe { mem::transmute(*data) });
                ReadItem::message(size)
            }
            ReadItem::Message(_) => ReadItem::size()
        }
    }

    /// Extracts the message from the current item if it is a message item.
    fn finish(self) -> Option<MessageBuf> {
        match self {
            ReadItem::Size(_) => None,
            // XXX Simply drops short messages. Should we log?
            ReadItem::Message(data) => MessageBuf::from_vec(data).ok()
        }
    }
}

