//! Message handling for queries.
//!
//! While queries appear to be like any other DNS message, they are in fact
//! special: They have exactly one entry in their question section, empty
//! answer and authority sections, and optionally an OPT and a TSIG record in
//! the additional section. In addition, queries may need to be reused – if
//! an upstream server won’t respond, another server needs to be asked. While
//! the OPT and TSIG records may need to be changed, the question doesn’t and
//! can be used again.
//!
//! This module provides types that help with creating, using, and re-using
//! queries. [`QueryBuilder`] allows to construct a query and add and remove
//! an OPT record as needed. A complete message can be frozen into a
//! [`QueryMessage`] that can be given to the transport for sending. It can
//! later be unfrozen back into a `QueryBuilder` for manipulations.
//!
//! [`QueryBuilder`]: struct.QueryBuilder.html
//! [`QueryMessage`]: struct.QueryMessage.html

use std::{mem, ops};
use bytes::{BigEndian, BufMut, ByteOrder, Bytes, BytesMut};
use super::compose::Compose;
use super::header::{Header, HeaderCounts, HeaderSection};
use super::message::Message;
use super::name::ToDname;
use super::opt::{OptData, OptHeader};
use super::question::Question;


//------------ QueryBuilder --------------------------------------------------

/// Builds a query DNS message.
///
/// You can create a new query from a given question using the [`new`]
/// function. The [`add_opt`] method provides the means to add an OPT record
/// to the additional section. The entire additional section can later be
/// removed through the [`revert_additional`] function.
///
/// Once you are happy with your query, you can turn it into a
/// [`QueryMessage`] through the [`freeze`] method.
///
/// [`freeze`]: #method.freeze
/// [`new`]: #method.new
/// [`add_opt`]: #method.add_opt
/// [`revert_additional`]: #method.revert_additional
/// [`QueryMessage`]: struct.QueryMessage.html
#[derive(Clone, Debug)]
pub struct QueryBuilder {
    /// The buffer containing the message.
    ///
    /// Note that we always build a query for streaming transports which
    /// means that the first two octets are the length shim.
    target: BytesMut,

    /// The index in `target` where the additional section starts.
    additional: usize,
}

impl QueryBuilder {
    /// Creates a new query builder.
    ///
    /// The query will contain one question built from `question`. It will
    /// have a random ID. The RD bit will _not_ be set. If you desire
    /// recursion, you can enable it via the [`set_rd`] method.
    ///
    /// [`set_rd`]: #method.set_rd
    pub fn new<N: ToDname, Q: Into<Question<N>>>(question: Q) -> Self {
        let mut header = HeaderSection::default();
        header.header_mut().set_random_id();
        header.counts_mut().set_qdcount(1);
        let question = question.into();
        let len = header.compose_len() + question.compose_len();
        let mut target = BytesMut::with_capacity(len + 2);
        target.put_u16_be(len as u16);
        header.compose(&mut target);
        question.compose(&mut target);
        QueryBuilder {
            additional: target.len(),
            target
        }
    }

    /// Returns a reference to the header of the query.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(&self.target.as_ref()[2..])
    }

    /// Returns a mutable reference to the header of the query.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(&mut self.target.as_mut()[2..])
    }

    /// Returns a reference to the section counts of the query.
    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(&mut self.target.as_mut()[2..])
    }

    /// Sets the ‘recursion desired’ (RD) bit to the given value. 
    ///
    /// This is a shortcut to `self.header_mut().set_rd(value)`.
    ///
    /// By default, this bit is _not_ set.
    pub fn set_rd(&mut self, value: bool) {
        self.header_mut().set_rd(value)
    }

    /// Updates the length shim of the message.
    ///
    /// Call this method any time you add or remove octets from the message.
    fn update_shim(&mut self) {
        let len = self.target.len() - 2;
        assert!(len <= ::std::u16::MAX as usize);
        BigEndian::write_u16(self.target.as_mut(), len as u16);
    }

    /// Adds an OPT record to the additional section.
    ///
    /// The content of the record can be manipulated in the closure provided
    /// as an argument. This closure receives a mutable reference to an
    /// [`OptBuilder`] which will allow access to the OPT record’s header as
    /// well as allow adding options.
    ///
    /// [`OptBuilder`]: struct.OptBuilder.html
    pub fn add_opt<F>(&mut self, op: F)
    where F: FnOnce(&mut OptBuilder) {
        op(&mut OptBuilder::new(self))
    }

    /// Removes all records from the additional section.
    ///
    /// Afterwards, only the single question will remain in the message.
    pub fn revert_additional(&mut self) {
        self.target.truncate(self.additional);
        self.counts_mut().set_adcount(0);
        self.update_shim();
    }

    /// Freezes the query builder into a query message.
    pub fn freeze(self) -> QueryMessage {
        let bytes = self.target.freeze();
        QueryMessage {
            message: Message::from_bytes(bytes.slice_from(2)).unwrap(),
            bytes,
            additional: self.additional
        }
    }
}


//------------ OptBuilder ----------------------------------------------------

/// A builder for the OPT record of a query.
///
/// A mutable reference to this type will be passed to the closure given to
/// [`QueryBuilder::add_opt`]. It allows manipulation of the record’s header
/// via the [`header_mut`] method and adding of options via [`push`].
/// 
/// # Limitations
///
/// Note that currently this type is not compatible with the various option
/// types‘ `push` functions. This will be addressed soon by redesigning that
/// mechanism.
///
/// [`QueryBuilder::add_opt`]: struct.QueryBuilder.html#method.add_opt
/// [`header_mut`]: #method.header_mut
/// [`push`]: #method.push
#[derive(Debug)]
pub struct OptBuilder<'a> {
    /// The query builder we work with.
    query: &'a mut QueryBuilder,

    /// The index in `query`’s target where the OPT record started.
    pos: usize,
}

impl<'a> OptBuilder<'a> {
    /// Creates a new OPT builder borrowing the given query builder.
    ///
    /// The function appends the OPT record’s header to the query, increases
    /// its ARCOUNT, and recalculates the stream shim.
    fn new(query: &'a mut QueryBuilder) -> Self {
        let pos = query.target.len();
        let header = OptHeader::default();
        query.target.reserve(header.compose_len());
        header.compose(&mut query.target);
        0u16.compose(&mut query.target);
        query.counts_mut().inc_arcount();
        query.update_shim();
        OptBuilder { query, pos }
    }

    /// Returns a reference to the header of the OPT record.
    pub fn header(&self) -> &OptHeader {
        OptHeader::for_record_slice(&self.query.target.as_ref()[self.pos..])
    }

    /// Returns a mutable reference to the header of the OPT record.
    pub fn header_mut(&mut self) -> &mut OptHeader {
        OptHeader::for_record_slice_mut(&mut self.query.target.as_mut()
                                                                [self.pos..])
    }

    /// Appends an option to the OPT record.
    pub fn push<O: OptData>(&mut self, option: &O) {
        option.code().compose(&mut self.query.target);
        let len = option.compose_len();
        assert!(len <= ::std::u16::MAX.into());
        (len as u16).compose(&mut self.query.target);
        option.compose(&mut self.query.target);
        self.update_length();
    }

    /// Updates the length of OPT record and the length shim of the query.
    fn update_length(&mut self) {
        let len = self.query.target.len()
                - (self.pos + mem::size_of::<OptHeader>() + 2);
        assert!(len <= ::std::u16::MAX.into());
        let count_pos = self.pos + mem::size_of::<OptHeader>();
        BigEndian::write_u16(
            &mut self.query.target.as_mut()[count_pos..],
            len as u16
        );
        self.query.update_shim();
    }
}


//------------ QueryMessage --------------------------------------------------

/// A DNS query message.
///
/// A value of this type contains a complete DNS query message ready for
/// sending. The type derefs to [`Message`] to provide all the functionality
/// of a regular message.
///
/// In order to send the query, the two methods [`as_stream_slice`] and
/// [`as_dgram_slice`] provide access to raw octets with or without the two
/// octet length indicator necessary for stream transports such as TCP,
/// respectively.
///
/// Finally, in order to manipulat the message for re-use, the method
/// [`unfreeze`] returns it into a [`QueryBuilder`].
///
/// [`Message`]: ../message/struct.Message.html
/// [`as_stream_slice`]: #method.as_stream_slice
/// [`as_dgram_slice`]: #method.as_dgram_slice
/// [`unfreeze`]: #method.unfreeze
/// [`QueryBuilder`]: struct.QueryBuilder.html
#[derive(Clone, Debug)]
pub struct QueryMessage {
    /// The complete bytes of the message including the length shim.
    bytes: Bytes,

    /// The message itself.
    ///
    /// This references the same memory as `bytes`.
    //
    //  XXX We should re-work `Message` s that it can deal with the length
    //      shim natively.
    message: Message,

    /// The index in `bytes` where the message’s additional section starts.
    additional: usize
}

impl QueryMessage {
    /// Convert the message into a query builder.
    ///
    /// If this message has the only reference to the underlying bytes, no
    /// re-allocation is necessary. Otherwise, the bytes will be copied into
    /// a new allocation.
    ///
    /// The returned builder will have a new, random message ID to make sure
    /// you don’t accidentally reuse the old one.
    pub fn unfreeze(self) -> QueryBuilder {
        drop(self.message);
        let mut res = QueryBuilder {
            target: self.bytes.into(),
            additional: self.additional
        };
        res.header_mut().set_random_id();
        res
    }

    /// Returns a slice of the message octets including the length shim.
    ///
    /// This is suitable for stream transports such as TCP.
    pub fn as_stream_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Returns a slice of the message octets without the length shim.
    ///
    /// This is suitable for datagram transports such as UDP.
    pub fn as_dgram_slice(&self) -> &[u8] {
        &self.bytes.as_ref()[2..]
    }
}


//--- Deref and AsRef

impl ops::Deref for QueryMessage {
    type Target = Message;

    fn deref(&self) -> &Message {
        &self.message
    }
}

impl AsRef<Message> for QueryMessage {
    fn as_ref(&self) -> &Message {
        &self.message
    }
}

