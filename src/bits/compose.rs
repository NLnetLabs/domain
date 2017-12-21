//! Assembling wire-format DNS data.
//!
//! Assembling DNS data for transmission over the wire is being called
//! *composing* to distinguish it from other procedures that turn data into
//! some output such as formatting it into human-readable text.
//!
//! Data is being assembled directly into values implementing the [`BufMut`]
//! trait. Because such buffers do not reallocate, the overall size of the
//! assembled data needs to be known beforehand. This module provides the
//! trait [`Compose`] for types that know how to compose themselves into a
//! buffer.
//!
//! There is, however, the matter of domain name compression which allows a
//! domain name to indicate that it continues elsewhere in an assembled
//! message. A consequence is that for a given name, the length of its
//! assembled representation depends on what is present in the message
//! already and thus cannot be given in general.
//!
//! Because of this differing behaviour when using domain name compression,
//! we call the process of assembling a messgage *compressing* instead.
//! Consequently, the module also defines a trait [`Compress`] for type that
//! know how to compress itself. This happens atop a helper type
//! [`Compressor`] that wraps a [`BytesMut`] and all the information
//! necessary for compressing names.
//!
//!
//! [`BufMut`]: ../../../bytes/trait.BufMut.html
//! [`BytesMut`]: ../../../bytes/struct.BytesMut.html
//! [`Compose`]: trait.Compose.html
//! [`Compress`]: trait.Compress.html
//! [`Compressor`]: struct.Compressor.html

use std::ops;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::{BigEndian, BufMut, Bytes, BytesMut};
use super::name::{Dname, Label, ToDname};
use super::parse::ShortBuf;


//------------ Compose -------------------------------------------------------

/// A type that knows how to compose itself.
///
/// The term ‘composing’ refers to the process of creating a DNS wire-format
/// representation of a value’s data. This happens by appending appending
/// this data to the end of a type implementing the [`BufMut`] trait.
///
/// [`BufMut`]: ../../../bytes/trait.BufMut.html
pub trait Compose {
    /// Returns the number of bytes this value will need without compression.
    fn compose_len(&self) -> usize;

    /// Appends the uncompressed representation of this value to `buf`.
    ///
    /// An implementation may assume that the buffer has at least as many
    /// bytes remaining as the amount a call to `compose_len()` would return
    /// right now. If that’s not the case, the implementation should panic.
    /// That is, the implementation can use `buf`‘s `put_*()` methods
    /// unchecked.
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

/// A type that knows how to compress itself.
///
/// The term `compressing` refers to the process of producing the DNS
/// wire-format representation of a value’s data allowing it to optionally
/// employ domain name compression.
///
/// Because [`BufMut`] doesn’t allow looking back at the data added to the
/// message before, compression cannot be implemented using just [`Compose`].
/// Instead, a special type, [`Compressor`] is provided that implements all
/// the necessary logic for name compression.
///
/// `Compress` should only be implemented for domain name types or types that
/// contain or may contain domain names and want to support name compression.
/// For all other types, [`Compressor::compose`] uses their [`Compose`]
/// implementation for appending.
///
/// [`BufMut`]: ../../../bytes/trait.BufMut.html
/// [`Compose`]: trait.Compose.html
/// [`Compressor`]: struct.Compressor.html
/// [`Compressor::compose`]: struct.Compressor.html#method.compose
pub trait Compress {
    /// Appends the wire-format representation of the value to `buf`.
    ///
    /// If `buf` does not have enough space available for appending the
    /// representation, the method returns an error. If this happens, some
    /// data may have been appended to the buffer.
    ///
    /// For implementers of composite types, this means that they can simply
    /// compress or compose their consitutent types onto `buf` bailing out
    /// if that fails. There is no need to truncate `buf` back to its prior
    /// state on failure.
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf>;
}

impl<'a, C: Compress + 'a> Compress for &'a C {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        (*self).compress(buf)
    }
}


//------------ Compressor ----------------------------------------------------

/// A buffer for composing a compressed DNS message.
///
/// This type wraps a [`BytesMut`] value into which it composes a message,
/// growing it as necessary. It provides an implementation for [`BufMut`]
/// allowing it to be used like any other buffer. In addition, it provides
/// special handling for types that implement [`Compose`] via the
/// [`compose`] method, appending them if there’s enough space.
///
/// The whole point of this type is, of course, name compression. This is
/// being provided via the [`compress_name`] method which appends any domain
/// name. Since compression is actually rather expensive as we need to keep
/// track of names that have been written so far, it needs to be explicitely
/// enabled via the [`enable_compression`] method.
///
/// Two more methods for tweaking the behaviour of `Compressor` are available. 
/// The maximum size of a message can be set via the [`set_limit`]. A value
/// will grow its underlying buffer as needed up to at most this size. It
/// will re-allocate memory if necessary by the amount set through
/// [`set_page_size`]. By default, or if the page size is set to 0, it will
/// only allocate exactly once to have enough space to reach the current
/// limit.
///
/// Once you are done composing your message, you can either extract the
/// underlying [`BytesMut`] via [`unwrap`] or get it as a frozen [`Bytes`]
/// directly via [`freeze`].
///
/// Note: Name compression is currently implemented in a rather naive way
///       by simply storing each compressed name’s position in a hash map
///       (also considering all its parents). This can probably be optimized.
///       In addition, this approach doesn’t
///       consider non-compressed names (since they are appended via their
///       `Compose` implementation).
///
/// [`BufMut`]: ../../../bytes/trait.BufMut.html
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`BytesMut`]: ../../../bytes/struct.BytesMut.html
/// [`Compose`]: trait.Compose.html
/// [`compose`]: #method.compose
/// [`compress_name`]: #method.compress_name
/// [`enable_compression`]: #method.enable_compression
/// [`freeze`]: #method.freeze
/// [`set_limit`]: #method.set_limit
/// [`set_page_size`]: #method.set_page_size
/// [`unwrap`]: #method.unwrap
#[derive(Clone, Debug, )]
pub struct Compressor {
    /// The bytes buffer we work on.
    buf: BytesMut,

    /// Index of where in `buf` the message starts.
    start: usize,

    /// The maximum size of `buf` in bytes.
    /// 
    /// This is is whatever is set via `set_limit` plus `start`.
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
            start: buf.len(),
            limit: buf.capacity(),
            page_size: 0,
            buf,
            map: None }
    }

    /// Creates a new compressor with a default capacity and limit.
    ///
    /// The compressor will be created atop a new buffer which will use its
    /// default capacity. This is the largest capacity it can use without
    /// having to allocate. The compressor will start out with a limit equal
    /// to this capacity and a page size of 0.
    pub fn new() -> Self {
        Self::from_buf(BytesMut::new())
    }

    /// Creates a new compressor with the given capacity.
    ///
    /// The compressor will be created atop a new buffer with at least the
    /// given capacity. The compressor’s initial limit will be the actual
    /// capacity of the buffer which may be larger than `capacity`. The
    /// initial page size will be 0.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_buf(BytesMut::with_capacity(capacity))
    }

    /// Enable name compression.
    ///
    /// By default, a compressor will not actually compress domain names,
    /// but rather append them like any other data. Instead, compression
    /// needs to be enable once via this method.
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
    /// If you try to set the limit to a value smaller than what has already
    /// been added so far, the limit will silently be increased to that
    /// amount.
    ///
    /// A new compressor starts out with a size limit equal to the
    /// remaining capacity of the buffer it is being created with.
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
    /// A new compressor starts out with this specia page size of 0.
    pub fn set_page_size(&mut self, page_size: usize) {
        self.page_size = page_size
    }

    /// Trades in the compressor for its underlying bytes buffer.
    pub fn unwrap(self) -> BytesMut {
        self.buf
    }

    /// Trades in the compressor for the frozen underlying buffer.
    pub fn freeze(self) -> Bytes {
        self.buf.freeze()
    }

    /// Returns a reference to the bytes that have been assembled so far.
    ///
    /// This differs from [`as_slice`](#method.as_slice) if the compressor
    /// was created atop an existing buffer in that the slice does not
    /// contain the data that was in the buffer before.
    pub fn so_far(&self) -> &[u8] {
        &self.buf.as_ref()[self.start..]
    }

    /// Returns a mutable reference to the data assembled so far.
    ///
    /// This differs from [`as_slice_mut`](#method.as_slice_mut) if the
    /// compressor was created atop an existing buffer in that the slice
    /// does not contain the data that was in the buffer before.
    pub fn so_far_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[self.start..]
    }

    /// Composes a the given name compressed into the buffer.
    ///
    /// If compression hasn’t been enable yet via
    /// [`enable_compression`](#method.enable_compression), the name will be
    /// appended without compression. It will also not be remembered as a
    /// compression target for later names.
    pub fn compress_name<N: ToDname>(&mut self, name: &N)
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

    /// Appends a compression label pointing to position `pos`.
    fn compose_compress_target(&mut self, pos: u16)
                               -> Result<(), ShortBuf> {
        if self.buf.remaining_mut() < 2 {
            return Err(ShortBuf)
        }
        (pos | 0xC000).compose(&mut self.buf);
        Ok(())
    }

    /// Appends something composable to the end of the buffer.
    ///
    /// This method can be used to append something and short circuit via the
    /// question mark operator if it doesn’t fit. This is most helpful when
    /// implementing the [`Compress`](trait.Compress.html) trait for a
    /// composite type.
    pub fn compose<C>(&mut self, what: &C) -> Result<(), ShortBuf>
                   where C: Compose + ?Sized {
        if self.remaining_mut() < what.compose_len() {
            return Err(ShortBuf)
        }
        what.compose(self);
        Ok(())
    }

    /// Remembers that `name` started at position `pos`.
    ///
    /// Doesn’t do that, though, if compression hasn’t been enabled yet.
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

    /// Returns a reference to the complete data of the underlying buffer.
    ///
    /// This may be more than the assembled data if the compressor was
    /// created atop a buffer that already contained data.
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref()
    }

    /// Returns a mutable reference to the data of the underlying buffer.
    ///
    /// This may be more than the assembled data if the compressor was
    /// created atop a buffer that already contained data.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }

    /// Grows the buffer size once.
    ///
    /// This may panic if used to grow beyond the limit.
    fn grow(&mut self) {
        if self.page_size == 0 {
            let additional = self.limit.checked_sub(self.buf.capacity())
                                 .unwrap();
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


//============ Testing, One, Two =============================================

#[cfg(test)]
mod test {
    use super::*;
    use bytes::BytesMut;


    //-------- Compose impls -------------------------------------------------

    #[test]
    fn compose_endian() {
        let mut buf = BytesMut::with_capacity(20);
        0x1234u16.compose(&mut buf);
        (-0x1234i16).compose(&mut buf);
        0x12345678u32.compose(&mut buf);
        (-0x12345678i32).compose(&mut buf);
        assert_eq!(buf.as_ref(),
                   b"\x12\x34\xed\xcc\x12\x34\x56\x78\xed\xcb\xa9\x88");
    }


    //-------- Compressor ----------------------------------------------------

    #[test]
    fn limit() {
        let mut buf = Compressor::new();
        buf.set_limit(2);
        assert_eq!(buf.remaining_mut(), 2);
        assert!(buf.compose(&0u32).is_err());
        buf.compose(&0u16).unwrap();
        assert!(buf.compose(&0u16).is_err());

        buf.set_limit(512); // definitely needs to realloc
        assert_eq!(buf.remaining_mut(), 510);
        buf.compose(AsRef::<[u8]>::as_ref(&vec![0u8; 508])).unwrap();
        assert!(buf.compose(&0u32).is_err());
        buf.compose(&0u16).unwrap();
        assert!(buf.compose(&0u16).is_err());

        let mut buf = Compressor::from_buf(buf.unwrap());
        assert_eq!(buf.so_far().len(), 0);
        buf.set_limit(512);
        buf.set_page_size(16);
        assert_eq!(buf.remaining_mut(), 512);
        buf.compose(AsRef::<[u8]>::as_ref(&vec![0u8; 510])).unwrap();
        assert_eq!(buf.remaining_mut(), 2);
        assert_eq!(buf.so_far().len(), 510);
    }

    #[test]
    fn compressed_names() {
        // Same name again
        //
        let mut buf = Compressor::with_capacity(1024);
        buf.enable_compression();
        buf.compose(&7u8).unwrap();
        let name = Dname::from_slice(b"\x03foo\x03bar\x00").unwrap();
        buf.compress_name(&name).unwrap();
        buf.compress_name(&name).unwrap();
        assert_eq!(buf.so_far(), b"\x07\x03foo\x03bar\x00\xC0\x01");

        // Prefixed name.
        //
        let mut buf = Compressor::with_capacity(1024);
        buf.enable_compression();
        buf.compose(&7u8).unwrap();
        Dname::from_slice(b"\x03foo\x03bar\x00").unwrap()
              .compress(&mut buf).unwrap();
        Dname::from_slice(b"\x03baz\x03foo\x03bar\x00").unwrap()
              .compress(&mut buf).unwrap();
        assert_eq!(buf.so_far(), b"\x07\x03foo\x03bar\x00\x03baz\xC0\x01");

        // Suffixed name.
        //
        let mut buf = Compressor::with_capacity(1024);
        buf.enable_compression();
        buf.compose(&7u8).unwrap();
        Dname::from_slice(b"\x03foo\x03bar\x00").unwrap()
              .compress(&mut buf).unwrap();
        Dname::from_slice(b"\x03baz\x03bar\x00").unwrap()
              .compress(&mut buf).unwrap();
        assert_eq!(buf.so_far(), b"\x07\x03foo\x03bar\x00\x03baz\xC0\x05");

        // Don’t compress the root label.
        //
        let mut buf = Compressor::with_capacity(1024);
        buf.enable_compression();
        buf.compose(&7u8).unwrap();
        Dname::root().compress(&mut buf).unwrap();
        Dname::from_slice(b"\x03foo\x00").unwrap()
              .compress(&mut buf).unwrap();
        Dname::root().compress(&mut buf).unwrap();
        assert_eq!(buf.so_far(), b"\x07\x00\x03foo\x00\x00");
    }
}
