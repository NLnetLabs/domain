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
//! This module provides the trait [`Composable`] for types that know how to
//! compose themselves into a buffer.
//!
//! [`BufMut`]: ../../../bytes/trait.BufMut.html
//! [`Composable`]: trait.Composable.html

use std::ops;
use std::collections::HashMap;
use bytes::{BigEndian, BufMut, BytesMut};
use super::error::ShortBuf;
use super::name::{Dname, Label, ToDname};


//------------ Composable ----------------------------------------------------

/// A type that knows how to compose itself.
pub trait Composable {
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

impl<'a, C: Composable> Composable for &'a C {
    fn compose_len(&self) -> usize {
        (*self).compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        (*self).compose(buf)
    }
}


impl Composable for i8 {
    fn compose_len(&self) -> usize {
        1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i8(*self)
    }
}

impl Composable for u8 {
    fn compose_len(&self) -> usize {
        1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(*self)
    }
}

impl Composable for i16 {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i16::<BigEndian>(*self)
    }
}

impl Composable for u16 {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16::<BigEndian>(*self)
    }
}

impl Composable for i32 {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_i32::<BigEndian>(*self)
    }
}

impl Composable for u32 {
    fn compose_len(&self) -> usize {
        4
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32::<BigEndian>(*self)
    }
}


//------------ Compressable --------------------------------------------------

pub trait Compressable {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf>;
}


//------------ Compressor ----------------------------------------------------

/// A type helping with compressing domain names.
///
/// This type is used for name compression through the
/// `Composable::compose_compressed` method.
///
/// Note: The implementation is rather naive right now and could do with a
///       smarter approach.
#[derive(Clone, Debug, )]
pub struct Compressor {
    buf: BytesMut,
    start: usize,
    map: HashMap<Dname, u16>,
}

impl Compressor {
    /// Creates a new empty compressor.
    pub fn new(buf: BytesMut) -> Self {
        Compressor { start: buf.remaining_mut(), buf, map: HashMap::new() }
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
                let pos = self.start - self.buf.remaining_mut();
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
                   where C: Composable + ?Sized {
        if self.buf.remaining_mut() < what.compose_len() {
            return Err(ShortBuf)
        }
        what.compose(&mut self.buf);
        Ok(())
    }

    fn add_name(&mut self, name: &Dname, pos: usize) {
        if pos > 0x3FFF {
            // Position exceeds encodable position. Don’t add the name, then.
            return
        }
        self.map.insert(name.clone(), pos as u16);
    }

    /// Returns the index of a name if it is known.
    fn get_pos(&self, name: &Dname) -> Option<u16> {
        self.map.get(name).map(|v| *v)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
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
        self.buf.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt)
    }

    unsafe fn bytes_mut(&mut self) -> &mut [u8] {
        self.buf.bytes_mut()
    }
}

