//! DNS messages
//!

use std::collections::HashMap;
use std::convert;
use std::error;
use std::fmt;
use std::mem;
use std::ops::{Deref, DerefMut};
use std::result;
use super::header::{Header, HeaderCounts, FullHeader};
use super::name::{self, DomainName, DomainNameBuf};
use super::bytes::{self, BytesBuf};
use super::question::{self, BuildQuestion, WireQuestion};
use super::record::{WireRecord, BuildRecord};


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

    pub fn answer(self) -> Option<AnswerSection<'a>> {
        if self.count == 0 {
            Some(AnswerSection::new(self.message, self.slice))
        }
        else { None }
    }
}

impl<'a> Iterator for QuestionSection<'a> {
    type Item = Result<WireQuestion<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        match WireQuestion::split_from(self.slice, &self.message.slice) {
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
pub struct RecordSection<'a> {
    message: &'a Message,
    slice: &'a [u8],
    count: u16
}

impl<'a> RecordSection<'a> {
    fn new(message: &'a Message, slice: &'a[u8], count: u16) -> Self {
        RecordSection { message: message, slice: slice, count: count }
    }
}

impl<'a> Iterator for RecordSection<'a> {
    type Item = Result<WireRecord<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 { return None }
        match WireRecord::split_from(self.slice, &self.message.slice) {
            Ok((res, slice)) => {
                self.count -= 1;
                self.slice = slice;
                Some(Ok(res))
            }
            Err(e) => Some(Err(Error::from(e)))
        }
    }
}


//------------ AnswerSection ------------------------------------------------

#[derive(Debug)]
pub struct AnswerSection<'a> {
    inner: RecordSection<'a>,
}

impl<'a> AnswerSection<'a> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AnswerSection {
            inner: RecordSection::new(message, slice,
                                      message.counts().ancount())
        }
    }

    pub fn authority(self) -> Option<AuthoritySection<'a>> {
        if self.inner.count == 0 {
            Some(AuthoritySection::new(self.inner.message, self.inner.slice))
        }
        else { None }
    }
}

impl<'a> Deref for AnswerSection<'a> {
    type Target = RecordSection<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}


//------------ AuthoritySection ---------------------------------------------

#[derive(Debug)]
pub struct AuthoritySection<'a> {
    inner: RecordSection<'a>
}

impl<'a> AuthoritySection<'a> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AuthoritySection {
            inner: RecordSection::new(message, slice,
                                      message.counts().nscount())
        }
    }

    pub fn additional(self) -> Option<AdditionalSection<'a>> {
        if self.inner.count == 0 {
            Some(AdditionalSection::new(self.inner.message,
                                        self.inner.slice))
        }
        else { None }
    }
}


//------------ AdditionalSection --------------------------------------------

#[derive(Debug)]
pub struct AdditionalSection<'a> {
    inner: RecordSection<'a>
}

impl<'a> AdditionalSection<'a> {
    fn new(message: &'a Message, slice: &'a[u8]) -> Self {
        AdditionalSection {
            inner: RecordSection::new(message, slice,
                                      message.counts().arcount())
        }
    }
}

impl<'a> Deref for AdditionalSection<'a> {
    type Target = RecordSection<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}


//============ Owned Message ================================================

#[derive(Debug)]
pub struct MessageBuf {
    inner: Vec<u8>
}


impl MessageBuf {
    /// Creates an owned message from a bytes slice.
    ///
    /// This is only safe if this really is a proper message.
    unsafe fn from_bytes(s: &[u8]) -> MessageBuf {
        MessageBuf { inner: Vec::from(s) }
    }

    /// Coerces to a message slice.
    pub fn as_name(&self) -> &Message {
        self
    }
}

impl<'a> From<&'a Message> for MessageBuf {
    fn from(msg: &'a Message) -> MessageBuf {
        unsafe { MessageBuf::from_bytes(&msg.slice) }
    }
}

impl Deref for MessageBuf {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        unsafe { Message::from_bytes_unsafe(&self.inner) }
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
    pub fn push<Q: BuildQuestion>(&mut self, question: &Q) -> Result<()> {
        self.buf.push(|buf| question.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_qdcount(1))
    }

    /// Move on to the answer section
    pub fn answer(self) -> AnswerBuilder {
        AnswerBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> Vec<u8> {
        self.buf.vec
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

    pub fn push<R: BuildRecord>(&mut self, record: &R) -> Result<()> {
        self.buf.push(|buf| record.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_ancount(1))
    }

    pub fn authority(self) -> AuthorityBuilder {
        AuthorityBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> Vec<u8> {
        self.buf.vec
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

    pub fn push<R: BuildRecord>(&mut self, record: &R) -> Result<()> {
        self.buf.push(|buf| record.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_nscount(1))
    }

    pub fn additional(self) -> AdditionalBuilder {
        AdditionalBuilder::new(self.buf)
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> Vec<u8> {
        self.buf.vec
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

    pub fn push<R: BuildRecord>(&mut self, record: &R) -> Result<()> {
        self.buf.push(|buf| record.push_buf(buf).map_err(|e| e.into()),
                      |counts| counts.inc_arcount(1))
    }

    /// Finish off the message and return the underlying vector.
    pub fn finish(self) -> Vec<u8> {
        self.buf.vec
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

}


impl BytesBuf for MessageVec {
    type Pos = <Vec<u8> as BytesBuf>::Pos;

    fn push_bytes(&mut self, data: &[u8]) {
        if self.keep_pushing(data.len()) {
            self.vec.push_bytes(data)
        }
    }

    fn pos(&self) -> Self::Pos { self.vec.pos() }
    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8]) {
        self.vec.update_bytes(pos, data)
    }

    fn can_compress(&self) -> bool {
        self.compress.is_some()
    }

    fn add_name_pos<N: AsRef<DomainName>>(&mut self, name: N) {
        if self.truncated { return }
        if let Some(ref mut map) = self.compress {
            if self.vec.len() >= 65535 { return }
            let name = name.as_ref().to_owned();
            map.insert(name, (self.vec.len() - self.offset) as u16);
        }
    }

    fn get_name_pos<N: AsRef<DomainName>>(&self, name: N) -> Option<u16> {
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



