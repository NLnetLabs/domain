
use std::mem;
use bytes::{BigEndian, BufMut, ByteOrder, BytesMut};
use optional::Optioned;
use super::oldcompose::{Compose, Compress, Compressor};
use super::header::{Header, HeaderCounts, HeaderSection};
use super::name::ToDname;
use super::oldparse::ShortBuf;
use super::question::Question;


//------------ MessageBuilder -----------------------------------------------

#[derive(Clone, Debug)]
pub struct MessageBuilder {
    /// The actual buffer to compose the message in.
    buf: Compressor,

    /// The index of the optional stream message shim.
    ///
    /// If this is present, the target will update the first two octets
    /// after this index with the length of the DNS message as is necessary
    /// for streaming protocols.
    shim: Optioned<usize>,
}


/// # Creation and Preparation
///
impl MessageBuilder {
    /// Creates a new message builder using an existing bytes buffer.
    ///
    /// The builder’s initial limit will be equal to whatever capacity is
    /// left in the buffer. As a consequence, the builder will never grow
    /// beyond that remaining capacity.
    pub fn from_buf(mut buf: BytesMut) -> Self {
        if buf.remaining_mut() < mem::size_of::<HeaderSection>() {
            let additional = mem::size_of::<HeaderSection>()
                           - buf.remaining_mut();
            buf.reserve(additional);
        }
        let mut buf = Compressor::from_buf(buf);
        HeaderSection::default().compose(&mut buf);
        MessageBuilder { buf, shim: Optioned::none() }
    }

    /// Creates a new stream message builder using an existing bytes buffer.
    ///
    /// In stream mode, the message is preceeded by two octets indicating the
    /// length of the message. This is used by streaming transports such as
    /// TCP.
    ///
    /// Consequently, a message can never be larger than 65536 octets. This
    /// will be the builders initial limit, irregardless of the capacity of
    /// the provided buffer.
    ///
    /// Currently, the capacity will grow with a page size of 512 but this
    /// may change if someone suggests a more reasonable value.
    pub fn stream_from_buf(mut buf: BytesMut) -> Self {
        // We don’t care about the capacity in this mode, so we can simply
        // reserve.
        buf.reserve(mem::size_of::<HeaderSection>() + 2);
        let shim = Optioned::some(buf.len());
        buf.put_u16_be(mem::size_of::<HeaderSection>() as u16);
        let mut buf = Compressor::from_buf(buf);
        HeaderSection::default().compose(&mut buf);
        buf.set_limit(::std::u16::MAX.into());
        buf.set_page_size(512);
        MessageBuilder { buf, shim }
    }

    /// Creates a message builder with the given capacity.
    ///
    /// The builder will have its own newly created bytes buffer with no
    /// prelude. Its inital limit will be equal to the capacity of that
    /// buffer. This may be larger than `capacity`. If you need finer
    /// control over the limit, use [`with_params`] instead.
    ///
    /// [`with_params`]: #method.with_params
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_buf(BytesMut::with_capacity(capacity))
    }

    /// Creates a new message builder with specific limits.
    ///
    /// A new buffer will be created for this builder. It will initially
    /// allocate space for at least `initial` bytes. The message will never
    /// exceed a size of `limit` bytes. Whenever the buffer’s capacity is
    /// exhausted, the builder will allocate at least another `page_size`
    /// bytes. If `page_size` is set to `0`, the builder will allocate at
    /// most once and then enough bytes to have room for the limit.
    pub fn with_params(
        initial: usize,
        limit: usize,
        page_size: usize,
    ) -> Self {
        let mut res = Self::with_capacity(initial);
        res.set_limit(limit);
        res.set_page_size(page_size);
        res
    }

    /// Creates a new builder for a datagram transport message.
    ///
    /// The builder will use a new bytes buffer. The buffer will have a
    /// capacity of 512 bytes and will also be limited to that. It will
    /// not have the stream message length indicator.
    ///
    /// This will result in a UDP message following the original limit. If
    /// you want to create larger messages, you should signal this through
    /// the use of EDNS.
    pub fn new_dgram() -> Self {
        Self::with_params(512, 512, 0)
    }

    /// Creates a new builder for a stream transport message.
    ///
    /// The builder will use a new buffer. It will be limited to 65535 bytes,
    /// starting with the capacity given.
    pub fn new_stream(capacity: usize) -> Self {
        Self::stream_from_buf(BytesMut::with_capacity(capacity))
    }

    /// Enables support for domain name compression.
    ///
    /// After this method is called, the domain names in questions, the owner
    /// domain names of resource records, and domain names appearing in the
    /// record data of record types defined in [RFC 1035] will be compressed.
    ///
    /// [RFC 1035]: ../../rdata/rfc1035.rs
    pub fn enable_compression(&mut self) {
        self.buf.enable_compression()
    }

    /// Sets the maximum size of the constructed DNS message.
    ///
    /// After this method was called, additional data will not be added to the
    /// message if that would result in the message exceeding a size of
    /// `limit` bytes. If the message is already larger than `limit` when the
    /// method is called, it will _not_ be truncated. That is, you can never
    /// actually set a limit smaller than the current message size.
    ///
    /// Note also that the limit only regards the message constructed by the
    /// builder itself. If a builder was created atop a buffer that already
    /// contained some data, this pre-existing data is not considered.
    ///
    /// Finally, for a message builder in stream mode, the limit is capped at
    /// 65536 bytes.
    pub fn set_limit(&mut self, mut limit: usize) {
        if self.shim.is_some() && limit > ::std::u16::MAX.into() {
            limit = ::std::u16::MAX.into();
        }
        self.buf.set_limit(limit)
    }

    /// Sets the amount of data by which to grow the underlying buffer.
    ///
    /// Whenever the buffer runs out of space but the message size limit has
    /// not yet been reached, the builder will grow the buffer by at least
    /// `page_size` bytes.
    ///
    /// A special case is a page size of zero, in which case the buffer will
    /// be grown only once to have enough space to reach the current limit.
    pub fn set_page_size(&mut self, page_size: usize) {
        self.buf.set_page_size(page_size)
    }
}


/// # Building
///
impl MessageBuilder {
    /// Returns a reference to the message’s header.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(self.buf.so_far())
    }

    /// Returns a mutable reference to the message’s header.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(self.buf.so_far_mut())
    }

    /// Returns a reference to the message’s header counts.
    fn counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.buf.so_far())
    }

    /// Returns a mutable reference to the message’s header counts.
    fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(self.buf.so_far_mut())
    }

    /// Appends a new question to the message.
    ///
    /// This method is generic over anything that can be converted into a
    /// [`Question`]. In particular, triples of a domain name, a record type,
    /// and a class as well as pairs of just a domain name and a record type
    /// fulfill this requirement with the class assumed to be `Class::In` in
    /// the latter case.
    ///
    /// The method will fail if by appending the question the message would
    /// exceed its size limit.
    ///
    /// [`Question`]: ../question/struct.Question.html
    pub fn push<N: ToDname, Q: Into<Question<N>>>(&mut self, question: Q)
                                                  -> Result<(), ShortBuf> {
        self.push_item(|target| question.into().compress(target),
                       |counts| counts.inc_qdcount())
    }

    /// Pushes something to the end of the message.
    ///
    /// There’s two closures here. The first one, `composeop` actually
    /// writes the data. The second, `incop` increments the counter in the
    /// messages header to reflect the new element.
    fn push_item<O, I, E>(&mut self, composeop: O, incop: I) -> Result<(), E>
    where
        O: FnOnce(&mut Compressor) -> Result<(), E>,
        I: FnOnce(&mut HeaderCounts)
    {
        composeop(&mut self.buf).map(|()| incop(self.counts_mut()))?;
        self.update_shim();
        Ok(())
    }

    /// Updates the length indicator if we are in stream mode.
    fn update_shim(&mut self) {
        if let Some(shim) = self.shim.into_option() {
            let len = self.buf.len() - self.buf.start();
            assert!(len < ::std::u16::MAX.into(), "long stream message");
            BigEndian::write_u16(
                &mut self.buf.as_slice_mut()[shim..],
                len as u16
            );
        }
    }

    /// Reverts all questions.
    ///
    /// This method removes all possibly existing questions from the message
    /// builder.
    pub fn revert(&mut self) {
        let pos = self.buf.start() + mem::size_of::<HeaderSection>();
        self.buf.truncate(pos);
        self.counts_mut().set_qdcount(0);
        self.update_shim()
    }
}

/// # Accessing Assembled Data
///
impl MessageBuilder {
    /// Returns a slice of the complete message.
    ///
    /// This includes any possible prelude and length shim.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_slice()
    }

    /// Returns a slice of the prelude.
    pub fn prelude(&self) -> &[u8] {
        match self.shim.into_option() {
            Some(shim) => &self.buf.as_slice()[..shim],
            None => &self.buf.as_slice()[..self.buf.start()]
        }
    }

    /// Returns a mutable slice of the prelude.
    pub fn prelude_mut(&mut self) -> &mut [u8] {
        let end = match self.shim.into_option() {
            Some(shim) => shim,
            None => self.buf.start()
        };
        &mut self.buf.as_slice_mut()[..end]
    }

    /// Returns a slice of the DNS message only.
    ///
    /// The slice will not contain a prelude or the length shim.
    pub fn as_message_slice(&self) -> &[u8] {
        &self.buf.as_slice()[self.buf.start()..]
    }

    /// Returns a slice of the length shim and message.
    ///
    /// This will return `None` if there is no shim.
    pub fn as_stream_slice(&self) -> Option<&[u8]> {
        self.shim.map(|shim| &self.buf.as_slice()[shim..])
    }

    /// Converts the builder into the underlying bytes buffer.
    pub fn unwrap(self) -> BytesMut {
        self.buf.unwrap()
    }

    /// Converts the builder into a imutable message.
    ///
    /// This conversion will retain both the prelude and length shim if
    /// present. They will be available again if the returned message is
    /// converted back into a builder.
    pub fn freeze(self) -> Message {
        Message::from_bytes_ext(
}

