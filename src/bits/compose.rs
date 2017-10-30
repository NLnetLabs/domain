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

use bytes::{BigEndian, BufMut};

/// A type that knows how to compose itself.
pub trait Composable {
    /// Returns the number of bytes this value will need.
    fn compose_len(&self) -> usize;

    /// Appends the representation of this value to `buf`.
    ///
    /// An implementation may assume that the buffer at least as many bytes
    /// remaining as the amount a call to `compose_len()` would return right
    /// now. If that’s not the case, the implementation should panic. That
    /// is, the implementation can use `buf`‘s `put_*()` methods unchecked.
    fn compose<B: BufMut>(&self, buf: &mut B);
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

