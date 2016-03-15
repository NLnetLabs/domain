//! DNS messages
//!

use std::collections::HashMap;
use std::convert;
use std::error;
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::result;
use super::header::{Header, HeaderCounts, FullHeader};
use super::iana::{Class, RRType};
use super::name::{self, DomainName, DomainNameBuf, DomainNameSlice,
                  CompactDomainName};
use super::bytes::{self, BytesBuf};
use super::question::{self, Question};
use super::record::Record;
use super::rdata::traits::{RecordData, CompactRecordData};


//============ Message Slice ================================================

//------------ Message ------------------------------------------------------

#[derive(Debug)]
pub struct Message {
    slice: [u8]
}


/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes slice.
    pub fn from_bytes(s: &[u8]) -> Result<&Message> {
        if s.len() < mem::size_of::<FullHeader>() {
            return Err(Error::OctetError(bytes::Error::PrematureEnd))
        }
        Ok(unsafe { mem::transmute(s) })
    }

    /// Creates a message from any byte slice.
    unsafe fn from_bytes_unsafe(s: &[u8]) -> &Message {
        mem::transmute(s)
    }

    /// Converts `self` into an owned message.
    pub fn to_owned(&self) -> MessageBuf {
        MessageBuf::from(self)
    }
}


/// # Header Access
///
impl Message {
    pub fn header(&self) -> &Header {
        unsafe { Header::from_message(&self.slice) }
    }

    pub fn counts(&self) -> &HeaderCounts {
        unsafe { HeaderCounts::from_message(&self.slice) }
    }

    pub fn question(&self) -> QuestionSection {
        QuestionSection::new(self,
                             &self.slice[mem::size_of::<FullHeader>()..])
    }
}


//------------ QuestionSection ----------------------------------------------

#[derive(Debug)]
pub struct QuestionSection<'a> {
    message: &'a Message,
    slice: &'a [u8],
    count: u16,
}

impl<'a> QuestionSection<'a> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        QuestionSection {
            message: message,
            slice: slice,
            count: message.counts().qdcount(),
        }
    }

    pub fn iter(&mut self) -> &mut Self {
        self
    }

    pub fn answer<D: CompactRecordData<'a>>(self)
                                            -> Option<AnswerSection<'a, D>> {
        if self.count == 0 {
            Some(AnswerSection::new(self.message, self.slice))
        }
        else { None }
    }
}

impl<'a> Iterator for QuestionSection<'a> {
    type Item = Result<Question<CompactDomainName<'a>>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        match Question::split_from(self.slice, &self.message.slice) {
            Ok((res, slice)) => {
                self.count -= 1;
                self.slice = slice;
                Some(Ok(res))
            }
            Err(e) => Some(Err(Error::from(e)))
        }
    }
}


//------------ RecordSection ------------------------------------------------

#[derive(Debug)]
pub struct RecordSection<'a, D: CompactRecordData<'a>> {
    message: &'a Message,
    slice: &'a [u8],
    count: u16,
    phantom: PhantomData<D>,
}

impl<'a, D: CompactRecordData<'a>> RecordSection<'a, D> {
    fn new(message: &'a Message, slice: &'a[u8], count: u16) -> Self {
        RecordSection { message: message, slice: slice, count: count,
                        phantom: PhantomData }
    }

    pub fn iter(&mut self) -> &mut Self {
        self
    }
}

impl<'a, D: CompactRecordData<'a>> Iterator for RecordSection<'a, D> {
    type Item = Result<Record<CompactDomainName<'a>, D>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.count == 0 { return None }
            match Record::split_from(self.slice, &self.message.slice) {
                Ok((inner, slice)) => {
                    self.count -= 1;
                    self.slice = slice;
                    match inner {
                        Some(record) => return Some(Ok(record)),
                        None => { }
                    }
                }
                Err(e) => return Some(Err(Error::from(e)))
            }
        }
    }
}


//------------ AnswerSection ------------------------------------------------

#[derive(Debug)]
pub struct AnswerSection<'a, D: CompactRecordData<'a>> {
    inner: RecordSection<'a, D>,
}

impl<'a, D: CompactRecordData<'a>> AnswerSection<'a, D> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AnswerSection {
            inner: RecordSection::new(message, slice,
                                      message.counts().ancount())
        }
    }

    pub fn authority(self) -> Option<AuthoritySection<'a, D>> {
        if self.inner.count == 0 {
            Some(AuthoritySection::new(self.inner.message, self.inner.slice))
        }
        else { None }
    }
}

impl<'a, D: CompactRecordData<'a>> Deref for AnswerSection<'a, D> {
    type Target = RecordSection<'a, D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, D: CompactRecordData<'a>> DerefMut for AnswerSection<'a, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}


//------------ AuthoritySection ---------------------------------------------

#[derive(Debug)]
pub struct AuthoritySection<'a, D: CompactRecordData<'a>> {
    inner: RecordSection<'a, D>
}

impl<'a, D: CompactRecordData<'a>> AuthoritySection<'a, D> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AuthoritySection {
            inner: RecordSection::new(message, slice,
                                      message.counts().nscount())
        }
    }

    pub fn additional(self) -> Option<AdditionalSection<'a, D>> {
        if self.inner.count == 0 {
            Some(AdditionalSection::new(self.inner.message,
                                        self.inner.slice))
        }
        else { None }
    }
}

impl<'a, D: CompactRecordData<'a>> Deref for AuthoritySection<'a, D> {
    type Target = RecordSection<'a, D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, D: CompactRecordData<'a>> DerefMut for AuthoritySection<'a, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}


//------------ AdditionalSection --------------------------------------------

#[derive(Debug)]
pub struct AdditionalSection<'a, D: CompactRecordData<'a>> {
    inner: RecordSection<'a, D>
}

impl<'a, D: CompactRecordData<'a>> AdditionalSection<'a, D> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AdditionalSection {
            inner: RecordSection::new(message, slice,
                                      message.counts().arcount())
        }
    }
}

impl<'a, D: CompactRecordData<'a>> Deref for AdditionalSection<'a, D> {
    type Target = RecordSection<'a, D>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, D: CompactRecordData<'a>> DerefMut for AdditionalSection<'a, D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}


//============ Owned Message ================================================

#[derive(Debug)]
pub struct MessageBuf {
    buf: Vec<u8>,
    offset: usize,
}


impl MessageBuf {
    /// Creates an owned message from a bytes slice.
    ///
    /// This is only safe if this really is a proper message.
    unsafe fn from_bytes(s: &[u8], offset: usize) -> MessageBuf {
        MessageBuf { buf: Vec::from(s), offset: offset }
    }

    pub fn from_vec(buf: Vec<u8>, offset: usize) -> Result<MessageBuf> {
        if buf.len() < mem::size_of::<FullHeader>() + offset {
            return Err(Error::OctetError(bytes::Error::PrematureEnd))
        }
        Ok(MessageBuf { buf: buf, offset: offset })
    }

    /// Coerces to a message slice.
    pub fn as_slice(&self) -> &Message {
        self
    }

    pub fn prefix(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    pub fn prefix_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.offset]
    }

    pub fn message_bytes(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    pub fn message_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf[self.offset..]
    }
}

impl<'a> From<&'a Message> for MessageBuf {
    fn from(msg: &'a Message) -> MessageBuf {
        unsafe { MessageBuf::from_bytes(&msg.slice, 0) }
    }
}

impl From<MessageVec> for MessageBuf {
    fn from(vec: MessageVec) -> MessageBuf {
        MessageBuf { buf: vec.vec, offset: vec.offset }
    }
}

impl Deref for MessageBuf {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        unsafe { Message::from_bytes_unsafe(&self.message_bytes()) }
    }
}

impl AsRef<Message> for MessageBuf {
    fn as_ref(&self) -> &Message { self }
}


//============ Message Builder ==============================================

//------------ MessageBuilder -----------------------------------------------

#[derive(Debug)]
pub struct MessageBuilder {
    buf: MessageVec
}

impl MessageBuilder {
    /// Creates a new messsage builder.
    ///
    pub fn new(maxlen: usize, offset: usize, compress: bool)
               -> MessageBuilder {
        MessageBuilder { buf: MessageVec::new(maxlen, offset, compress) }
    }

    /// Proceeds to building the question section.
    pub fn question(self) -> QuestionBuilder {
        QuestionBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> Vec<u8> {
        self.buf.vec
    }
}

impl Deref for MessageBuilder {
    type Target = HeaderBuilder;

    fn deref(&self) -> &HeaderBuilder {
        HeaderBuilder::from_buf(&self.buf)
    }
}

impl DerefMut for MessageBuilder {
    fn deref_mut(&mut self) -> &mut HeaderBuilder {
        HeaderBuilder::from_buf_mut(&mut self.buf)
    }
}


//------------ QuestionBuilder ----------------------------------------------

#[derive(Debug)]
pub struct QuestionBuilder {
    buf: MessageVec
}

impl QuestionBuilder {
    fn new(buf: MessageVec) -> Self {
        QuestionBuilder { buf: buf }
    }

    /// Appends a new question to the question section.
    pub fn push<N: DomainName>(&mut self, question: &Question<N>)
                               -> Result<()> {
        self.buf.push(|buf| question.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_qdcount(1))
    }

    pub fn push_question<N: DomainName>(&mut self, name: N, qtype: RRType,
                                        qclass: Class) -> Result<()> {
        self.push(&Question::new(name, qtype, qclass))
    }

    /// Move on to the answer section
    pub fn answer(self) -> AnswerBuilder {
        AnswerBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> MessageBuf {
        self.buf.into()
    }
}


impl Deref for QuestionBuilder {
    type Target = HeaderBuilder;

    fn deref(&self) -> &HeaderBuilder {
        HeaderBuilder::from_buf(&self.buf)
    }
}

impl DerefMut for QuestionBuilder {
    fn deref_mut(&mut self) -> &mut HeaderBuilder {
        HeaderBuilder::from_buf_mut(&mut self.buf)
    }
}


//------------ AnswerBuilder ------------------------------------------------

pub struct AnswerBuilder {
    buf: MessageVec,
}

impl AnswerBuilder {
    fn new(buf: MessageVec) -> Self {
        AnswerBuilder { buf: buf }
    }

    pub fn push<N, D>(&mut self, record: &Record<N, D>) -> Result<()>
                where N: DomainName, D: RecordData {
        self.buf.push(|buf| record.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_ancount(1))
    }

    pub fn push_record<N, D>(&mut self, name: N, rclass: Class, ttl: u32,
                             data: D) -> Result<()>
                       where N: DomainName, D: RecordData {
        self.push(&Record::new(name, rclass, ttl, data))
    }

    /*
    pub fn push<N: AsRef<DomainNameSlice>>(&mut self, name: N, rclass: Class,
                                      ttl: u32, dataop: Box<PushDataOp>)
                                      -> Result<()> {
        self.buf.push_record(name.as_ref(), rclass, ttl, dataop,
                             |counts| counts.inc_ancount(1))
    }
    */

    pub fn authority(self) -> AuthorityBuilder {
        AuthorityBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying message.
    pub fn finish(self) -> MessageBuf {
        self.buf.into()
    }
}


impl Deref for AnswerBuilder {
    type Target = HeaderBuilder;

    fn deref(&self) -> &HeaderBuilder {
        HeaderBuilder::from_buf(&self.buf)
    }
}

impl DerefMut for AnswerBuilder {
    fn deref_mut(&mut self) -> &mut HeaderBuilder {
        HeaderBuilder::from_buf_mut(&mut self.buf)
    }
}


//------------ AuthorityBuilder ---------------------------------------------

pub struct AuthorityBuilder {
    buf: MessageVec
}

impl AuthorityBuilder {
    fn new(buf: MessageVec) -> Self {
        AuthorityBuilder { buf: buf }
    }

    /*
    pub fn push<N, F>(&mut self, name: N, rclass: Class, ttl: u32,
                      dataop: F) -> Result<()>
                where N: AsRef<DomainName>,
                      F: FnOnce(&mut Vec<u8>) -> RRType {
        self.buf.push_record(name.as_ref(), rclass, ttl, dataop,
                             |counts| counts.inc_ancount(1))
    }
    */

    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> MessageBuf {
        self.buf.into()
    }
}


impl Deref for AuthorityBuilder {
    type Target = HeaderBuilder;

    fn deref(&self) -> &HeaderBuilder {
        HeaderBuilder::from_buf(&self.buf)
    }
}

impl DerefMut for AuthorityBuilder {
    fn deref_mut(&mut self) -> &mut HeaderBuilder {
        HeaderBuilder::from_buf_mut(&mut self.buf)
    }
}


//------------ AdditionalBuilder --------------------------------------------

pub struct AdditionalBuilder {
    buf: MessageVec
}

impl AdditionalBuilder {
    fn new(buf: MessageVec) -> Self {
        AdditionalBuilder { buf: buf }
    }

    /*
    pub fn push<N, F>(&mut self, name: N, rclass: Class, ttl: u32,
                      dataop: F) -> Result<()>
                where N: AsRef<DomainName>,
                      F: FnOnce(&mut Vec<u8>) -> RRType {
        self.buf.push_record(name.as_ref(), rclass, ttl, dataop,
                             |counts| counts.inc_ancount(1))
    }
    */

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> MessageBuf {
        self.buf.into()
    }
}


impl Deref for AdditionalBuilder {
    type Target = HeaderBuilder;

    fn deref(&self) -> &HeaderBuilder {
        HeaderBuilder::from_buf(&self.buf)
    }
}

impl DerefMut for AdditionalBuilder {
    fn deref_mut(&mut self) -> &mut HeaderBuilder {
        HeaderBuilder::from_buf_mut(&mut self.buf)
    }
}


//------------ HeaderBuilder ------------------------------------------------

#[derive(Debug)]
pub struct HeaderBuilder {
    buf: MessageVec
}

impl HeaderBuilder {
    fn from_buf(buf: &MessageVec) -> &HeaderBuilder {
        unsafe { mem::transmute(buf) }
    }

    fn from_buf_mut(buf: &mut MessageVec) -> &mut HeaderBuilder {
        unsafe { mem::transmute(buf) }
    }
}

impl HeaderBuilder {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        self.buf.header()
    }

    /// Returns a mutable reference to the message header.
    pub fn header_mut(&mut self) -> &mut Header {
        self.buf.header_mut()
    }

    /// Returns a reference to the message header counts.
    pub fn counts(&self) -> &HeaderCounts {
        self.buf.counts()
    }

    /// Returns a reference to the prefix.
    pub fn prefix(&self) -> &[u8] {
        self.buf.prefix()
    }

    /// Returns a mutable reference to the prefix.
    pub fn prefix_mut(&mut self) -> &mut [u8] {
        self.buf.prefix_mut()
    }

    /// Returns a reference to the message so far.
    pub fn message(&self) -> &Message {
        unsafe { Message::from_bytes_unsafe(self.buf.message_bytes()) }
    }

    /// Returns the lenth of the message so far.
    pub fn len(&self) -> usize {
        self.buf.message_bytes().len()
    }
}


//------------ MessageVec ---------------------------------------------------

/// A bytes vector for assembling DNS messages.
///
/// This private type does all the heavy lifting for creating a message.
///
#[derive(Debug)]
struct MessageVec {
    /// The underlying vector.
    vec: Vec<u8>,

    /// When writing to a stream socket, the message actually starts with
    /// a two byte length indicator. In order to be able to assemble such
    /// messages herein, we generalize this a little and allow an
    /// arbitrarily sized prefix. This field keeps the offset where the
    /// actual message starts.
    offset: usize,

    /// Maximum size of the message.
    ///
    /// While existing wire protocols limit messages to 65535 bytes, we
    /// can build messages up to `std::usize::MAX` bytes in length.
    maxlen: usize,

    /// Whether then message has exceeded its length and has been truncated.
    /// 
    /// We need to store this separatly since cutting back to the checkpoint
    /// will get us below the maximum length again.
    truncated: bool,

    /// Position of the optional check point.
    ///
    /// If this is set, the vector will be cut back to this length when
    /// it crosses its length boundary.
    checkpoint: Option<usize>,

    /// If we do compression, we will store domain names and their offset
    /// in this here map. If we don't do compression, there is no map.
    compress: Option<HashMap<DomainNameBuf, u16>>,
}


impl MessageVec {
    fn new(maxlen: usize, offset: usize, compress: bool) -> MessageVec {
        MessageVec {
            vec: vec![0; offset + mem::size_of::<FullHeader>()],
            offset: offset,
            maxlen: maxlen,
            truncated: false,
            checkpoint: None,
            compress: if compress { Some(HashMap::new()) }
                      else { None }
        }
    }

    fn prefix(&self) -> &[u8] {
        &self.vec[..self.offset]
    }

    fn prefix_mut(&mut self) -> &mut [u8] {
        &mut self.vec[..self.offset]
    }

    fn message_bytes(&self) -> &[u8] {
        &self.vec[self.offset..]
    }

    fn message_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.vec[self.offset..]
    }

    fn header(&self) -> &Header {
        unsafe { Header::from_message(self.message_bytes()) }
    }

    fn header_mut(&mut self) -> &mut Header {
        unsafe { Header::from_message_mut(self.message_bytes_mut()) }
    }

    fn counts(&self) -> &HeaderCounts {
        unsafe { HeaderCounts::from_message(self.message_bytes()) }
    }

    fn counts_mut(&mut self) -> &mut HeaderCounts {
        unsafe { HeaderCounts::from_message_mut(self.message_bytes_mut()) }
    }

    fn keep_pushing(&mut self, len: usize) -> bool {
        if self.truncated { false }
        else if self.vec.len() + len > self.maxlen {
            self.checkpoint.map(|len| self.vec.truncate(len));
            self.truncated = true;
            self.header_mut().set_tc(true);
            false
        }
        else { true }
    }

    fn checkpoint(&mut self) {
        self.checkpoint = Some(self.vec.len())
    }

    fn rollback(&mut self) {
        if let Some(len) = self.checkpoint {
            self.vec.truncate(len);
            self.checkpoint = None;
        }
    }

    fn push<B, I>(&mut self, buildop: B, incop: I) -> Result<()>
            where B: FnOnce(&mut MessageVec) -> Result<()>,
                  I: FnOnce(&mut HeaderCounts) -> bytes::Result<()> {
        self.checkpoint();
        try!(buildop(self));
        if self.truncated {
            self.rollback();
            Err(bytes::Error::SizeExceeded.into())
        }
        else {
            incop(self.counts_mut()).map_err(|err| {
                self.rollback();
                err.into()
            })
        }
    }

    /*
    fn push_record<I>(&mut self, name: &DomainNameSlice, rclass: Class,
                         ttl: u32, dataop: Box<PushDataOp>, incop: I) -> Result<()>
                   where 
                         I: FnOnce(&mut HeaderCounts) -> bytes::Result<()> {
        let buildop = |buf: &mut MessageVec| {
            try!(name.push_buf_compressed(buf));
            let type_pos = buf.pos();
            buf.push_u16(0);
            rclass.push_buf(buf);
            buf.push_u32(ttl);
            let len_pos = buf.pos();
            buf.push_u16(0);
            let rtype = dataop(&mut buf.vec);
            let delta = buf.pos();
            if delta > (::std::u16::MAX as usize) {
                return Err(Error::OctetError(bytes::Error::Overflow));
            }
            buf.update_u16(type_pos, rtype.to_int());
            buf.update_u16(len_pos, delta as u16);
            Ok(())
        };
        self.push(buildop, incop)
    }
    */
}


impl BytesBuf for MessageVec {
    type Pos = <Vec<u8> as BytesBuf>::Pos;

    fn push_bytes(&mut self, data: &[u8]) {
        if self.keep_pushing(data.len()) {
            self.vec.push_bytes(data)
        }
    }

    fn pos(&self) -> Self::Pos { self.vec.pos() }
    fn delta(&self, pos: Self::Pos) -> usize { self.vec.delta(pos) }
    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8]) {
        self.vec.update_bytes(pos, data)
    }

    fn can_compress(&self) -> bool {
        self.compress.is_some()
    }

    fn add_name_pos<N: AsRef<DomainNameSlice>>(&mut self, name: N) {
        if self.truncated { return }
        if let Some(ref mut map) = self.compress {
            if self.vec.len() >= 65535 { return }
            let name = name.as_ref().to_owned();
            map.insert(name, (self.vec.len() - self.offset) as u16);
        }
    }

    fn get_name_pos<N: AsRef<DomainNameSlice>>(&self, name: N) -> Option<u16> {
        match self.compress {
            Some(ref map) => map.get(name.as_ref()).map(|x| *x),
            None => None
        }
    }
}


//============ Error and Result =============================================

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NameError(name::ErrorKind),
    OctetError(bytes::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::NameError(ref kind) => kind.description(),
            Error::OctetError(ref error) => {
                use std::error::Error;

                error.description()
            }
        }
    }
}

impl convert::From<bytes::Error> for Error {
    fn from(error: bytes::Error) -> Error {
        Error::OctetError(error)
    }
}

impl convert::From<name::Error> for Error {
    fn from(error: name::Error) -> Error {
        match error {
            name::Error::NameError(kind) => Error::NameError(kind),
            name::Error::OctetError(error) => Error::OctetError(error),
        }
    }
}

impl convert::From<question::Error> for Error {
    fn from(error: question::Error) -> Error {
        match error {
            question::Error::NameError(kind) => Error::NameError(kind),
            question::Error::OctetError(kind) => Error::OctetError(kind),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}

pub type Result<T> = result::Result<T, Error>;


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;
    use super::super::iana::{Class, RRType};
    use super::super::name::DomainNameBuf;
    use super::super::rdata::rfc1035::{A, NS};
    use super::*;

    #[test]
    fn build_message() {
        let mut msg = MessageBuilder::new(1550, 0, true).question();
        msg.push_question(DomainNameBuf::from_str("example.com.").unwrap(),
                          RRType::A, Class::IN).unwrap();
        let mut msg = msg.answer();
        let data = A::new(Ipv4Addr::new(127, 0, 0, 1));
        msg.push_record(DomainNameBuf::from_str("example.com.").unwrap(),
                        Class::IN, 3600, data).unwrap();
        let data = NS::new(DomainNameBuf::from_str("ns.example.com.").unwrap());
        msg.push_record(DomainNameBuf::from_str("example.com.").unwrap(),
                        Class::IN, 3600, data).unwrap();
        let _ = msg.finish();
    }
}
                 
