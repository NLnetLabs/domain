//! Assembling wire-format DNS data.
//!
//! Assembling DNS data for transmission over the wire is being called
//! *composing* to distinguish it from other procedure that turn data into
//! some output such as formatting it into human-readable text.
//!
//! Data is being assembled directly into values implementing the [`BufMut`]
//! trait. Because such buffers do not reallocate, the overall size of the
//! assembled data needs to be known beforehand.
//!
//! This module provides the trait [`Compose`] for types that know how to
//! compose themselves into a buffer.
//!
//! [`BufMut`]: ../../../bytes/trait.BufMut.html
//! [`Compose`]: trait.Compose.html

use std::ops;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::{BigEndian, BufMut, Bytes, BytesMut};
use super::error::ShortBuf;
use super::name::{Dname, Label, ToDname};


//------------ Compose -------------------------------------------------------

/// A type that knows how to compose itself.
pub trait Compose {
    /// Returns the number of bytes this value will need without compression.
    fn compose_len(&self) -> usize;

    /// Appends the uncompressed representation of this value to `buf`.
    ///
    /// An implementation may assume that the buffer at least as many bytes
    /// remaining as the amount a call to `compose_len()` would return right
    /// now. If that’s not the case, the implementation should panic. That
    /// is, the implementation can use `buf`‘s `put_*()` methods unchecked.
    fn compose<B: BufMut>(&self, buf: &mut B);
}

impl<'a, C: Compose> Compose for &'a C {
    fn compose_len(&self) -> usize {
        (*self).compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        (*self).compose(buf)
    }
}


impl Compose for i8 {
    fn compose_len(&self) -> usize {
        1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i8(*self)
    }
}

impl Compose for u8 {
    fn compose_len(&self) -> usize {
        1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self)
    }
}

impl Compose for i16 {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i16::<BigEndian>(*self)
    }
}

impl Compose for u16 {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16::<BigEndian>(*self)
    }
}

impl Compose for i32 {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i32::<BigEndian>(*self)
    }
}

impl Compose for u32 {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32::<BigEndian>(*self)
    }
}

impl Compose for [u8] {
    fn compose_len(&self) -> usize {
        self.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self)
    }
}

impl Compose for Ipv4Addr {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets())
    }
}

impl Compose for Ipv6Addr {
    fn compose_len(&self) -> usize {
        16
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.octets())
    }
}
        

//------------ Compress ------------------------------------------------------

pub trait Compress {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf>;
}


//------------ Compressor ----------------------------------------------------

/// A type helping with compressing domain names.
///
/// This type is used for name compression through the
/// `Compose::compose_compressed` method.
///
/// Note: Name compression is currently implemented in a rather naive way
///       and could do with a smarter approach.
#[derive(Clone, Debug, )]
pub struct Compressor {
    /// The bytes buffer we work on.
    buf: BytesMut,

    /// Index of where in `buf` the message starts.
    start: usize,

    /// The maximum size of `buf` in bytes.
    limit: usize,

    /// The number of bytes to grow each time we run out of space.
    ///
    /// If this is 0, we grow exactly once to the size given by `limit`.
    page_size: usize,

    /// The optional compression map.
    ///
    /// This keeps the position relative to the start of the message for each
    /// name we’ve ever written.
    map: Option<HashMap<Dname, u16>>,
}

impl Compressor {
    /// Creates a compressor from the given bytes buffer.
    ///
    /// The compressor will have a default limit equal to the buffer’s current
    /// capacity and a page size of 0.
    pub fn from_buf(buf: BytesMut) -> Self {
        Compressor {
            start: buf.remaining_mut(),
            limit: buf.capacity(),
            page_size: 0,
            buf,
            map: None }
    }

    /// Creates a new compressor with the given capacity.
    ///
    /// The compressor will have a default limit equal to the given capacity
    /// and a page size of 0.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_buf(BytesMut::with_capacity(capacity))
    }

    pub fn enable_compression(&mut self) {
        if self.map.is_none() {
            self.map = Some(HashMap::new())
        }
    }

    /// Sets the size limit for the compressor.
    ///
    /// This limit only regards the part of the underlying buffer that is
    /// being built by the compressor. That is, if the compressor was created
    /// on top of a buffer that already contained data, the buffer will never
    /// exceed that amount of data plus `limit`.
    ///
    /// If you try to set the limit to a value smaller than what’s already
    /// there, it will silently be increased to the current size.
    ///
    /// A new compressor starts out with a size limit equal to the capacity
    /// of the buffer it is being created with.
    pub fn set_limit(&mut self, limit: usize) {
        let limit = limit + self.start;
        self.limit = ::std::cmp::max(limit, self.buf.len())
    }

    /// Sets the number of bytes by which the buffer should be grown.
    ///
    /// Each time the buffer runs out of capacity and is still below its
    /// size limit, it will be grown by `page_size` bytes. This may result in
    /// a buffer with more capacity than the limit.
    ///
    /// If `page_size` is set to 0, the buffer will be expanded only once to
    /// match the size limit.
    ///
    /// A new compressor starts out with a page size of 0.
    pub fn set_page_size(&mut self, page_size: usize) {
        self.page_size = page_size
    }

    pub fn unwrap(self) -> BytesMut {
        self.buf
    }

    pub fn freeze(self) -> Bytes {
        self.buf.freeze()
    }

    pub fn slice(&self) -> &[u8] {
        &self.buf.as_ref()[self.start..]
    }

    pub fn slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.start..]
    }

    /// Composes a the given name compressed into the buffer.
    pub fn compose_name<N: ToDname>(&mut self, name: &N)
                                    -> Result<(), ShortBuf> {
        let mut name = name.to_name();
        while !name.is_root() {
            if let Some(pos) = self.get_pos(&name) {
                return self.compose_compress_target(pos)
            }
            let pos = {
                let first = name.first();
                let pos = self.buf.len() - self.start;
                self.compose(first)?;
                pos
            };
            self.add_name(&name, pos);
            name.parent().unwrap();
        }
        self.compose(Label::root())
    }

    fn compose_compress_target(&mut self, pos: u16)
                               -> Result<(), ShortBuf> {
        if self.buf.remaining_mut() < 2 {
            return Err(ShortBuf)
        }
        (pos | 0xC000).compose(&mut self.buf);
        Ok(())
    }

    pub fn compose<C>(&mut self, what: &C) -> Result<(), ShortBuf>
                   where C: Compose + ?Sized {
        if self.remaining_mut() < what.compose_len() {
            return Err(ShortBuf)
        }
        what.compose(self);
        Ok(())
    }

    fn add_name(&mut self, name: &Dname, pos: usize) {
        if let Some(ref mut map) = self.map {
            if pos > 0x3FFF {
                // Position exceeds encodable position. Don’t add.
                return
            }
            map.insert(name.clone(), pos as u16);
        }
    }

    /// Returns the index of a name if it is known.
    fn get_pos(&self, name: &Dname) -> Option<u16> {
        match self.map {
            Some(ref map) => map.get(name).map(|v| *v),
            None => None
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }

    fn grow(&mut self) {
        if self.page_size == 0 {
            let additional = self.limit - self.buf.capacity();
            self.buf.reserve(additional)
        }
        else {
            self.buf.reserve(self.page_size)
        }
    }
}


//--- AsRef and AsMut

impl AsRef<BytesMut> for Compressor {
    fn as_ref(&self) -> &BytesMut {
        &self.buf
    }
}

impl AsMut<BytesMut> for Compressor {
    fn as_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }
}

impl AsRef<[u8]> for Compressor {
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

impl AsMut<[u8]> for Compressor {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }
}


//--- Deref and DerefMut

impl ops::Deref for Compressor {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl ops::DerefMut for Compressor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}


//--- BufMut

impl BufMut for Compressor {
    fn remaining_mut(&self) -> usize {
        self.limit - self.buf.len()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining_mut());
        while cnt > self.buf.remaining_mut() {
            self.grow();
        }
        self.buf.advance_mut(cnt)
    }

    unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        if self.buf.remaining_mut() == 0 && self.remaining_mut() > 0 {
            self.grow()
        }
        self.buf.bytes_mut()
    }
}

