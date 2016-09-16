//! Building of wire-format DNS data.
//!
//! This module provides a trait for types implementing wire message
//! composition as well as such a type operating on a byte vector.

use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::ops::Deref;
use std::ptr;
use super::charstr::CharStr;
use super::error::{ComposeError, ComposeResult};
use super::name::{AsDName, DNameSlice, Label, DNameBuf};
use super::nest::Nest;
use super::octets::Octets;


//------------ ComposeBytes ---------------------------------------------------

/// A trait for composing a DNS wire format message.
///
/// Messages are created by pushing data to the end of the message.
/// However, in order to avoid having to preassemble length-value parts of
/// the message such as record data, there is an option to update previously
/// written data.
///
/// Additionally, the length can be limited and the resulting message
/// truncated when it exceeds this limit. In order to provide for controlled
/// truncation at well defined points (normally, between resource records),
/// truncation points can be set. Whenever writing goes past the predefined
/// length, the message is automatically cut back to the last such
/// truncation point and nothing is added anymore–all push operations will
/// result in `Err(ComposeError::SizeExceeded)`.
pub trait ComposeBytes: Sized + fmt::Debug {
    type Pos: Copy + fmt::Debug;

    //--- Appending of basic types

    /// Pushes a bytes slice to the end of the message.
    fn push_bytes(&mut self, data: &[u8]) -> ComposeResult<()>;

    /// Pushes placeholder bytes to the end of the message.
    fn push_empty(&mut self, len: usize) -> ComposeResult<()>;

    /// Pushes a single octet to the end of the message.
    fn push_u8(&mut self, data: u8) -> ComposeResult<()> {
        let bytes: [u8; 1] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    /// Pushes an unsigned 16-bit word to the end of the message.
    ///
    /// The word is converted to network byte order if necessary.
    fn push_u16(&mut self, data: u16) -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 2] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    /// Pushes a unsigned 32-bit word to the end of the message.
    ///
    /// The word is converted to network byte order if necessary.
    fn push_u32(&mut self, data: u32) -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 4] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    //--- Appending of domain names.

    /// Pushes a domain name to the end of the message.
    fn push_dname<D: AsDName>(&mut self, name: &D) -> ComposeResult<()>;

    /// Pushes a domain name to the end of the message using name compression.
    ///
    /// Since compression is only allowed in a few well-known places per
    /// RFC 1123 and RFC 3597, this isn’t the default behaviour.
    fn push_dname_compressed<D: AsDName>(&mut self, name: &D)
                                         -> ComposeResult<()>;

    /// Pushes a character string to the end of the message.
    fn push_charstr(&mut self, cstring: &CharStr) -> ComposeResult<()> {
        cstring.compose(self)
    }

    /// Pushes a nest to the end of the message.
    fn push_nest(&mut self, nest: &Nest) -> ComposeResult<()> {
        nest.compose(self)
    }

    /// Pushes arbitrary bytes data to the end of the message.
    fn push_octets(&mut self, octets: &Octets) -> ComposeResult<()> {
        octets.compose(self)
    }

    //--- Checkpoint and rollback.

    /// Mark the current position as a point for truncation.
    ///
    /// If the length of the resulting message exceeds its predefined
    /// maximum size for the first time and a truncation point was set, it
    /// will be cut back to that point.
    fn truncation_point(&mut self);

    /// Returns whether the target has been truncated.
    fn truncated(&self) -> bool;


    //--- Updating of earlier data.

    /// Returns the current write position of the builder.
    fn pos(&self) -> Self::Pos;

    /// Returns the length of data added since the given position.
    fn delta(&self, pos: Self::Pos) -> usize;

    /// Updates the builder starting at the given position with a bytes slice.
    ///
    /// This method panics if the bytes slice is longer than the data
    /// assembled since the given write position.
    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8])
                    -> ComposeResult<()>;

    /// Updates the octet at the given write position.
    ///
    /// This method panics if there is no data at the given write position.
    fn update_u8(&mut self, pos: Self::Pos, data: u8)
                 -> ComposeResult<()> {
        let bytes: [u8; 1] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes)
    }

    /// Updates an unsigned 16-bit word starting at the given write position.
    ///
    /// This method panics if there aren’t two octets following the write
    /// position.
    fn update_u16(&mut self, pos: Self::Pos, data: u16)
                  -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 2] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes)
    }

    /// Updates an unsigned 32-bit word starting at the given write position.
    ///
    /// This method panics if there aren’t four octets following the write
    /// position.
    fn update_u32(&mut self, pos: Self::Pos, data: u32)
                  -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 4] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes)
    }
}


//------------ ComposeBuf -----------------------------------------------------

/// A compose target based on a simple vector.
///
/// You can get to the underlying bytes vector by calling `finish()`
/// which will transform into a vector. Alternatively, the type derefs to
/// a bytes vector.
#[derive(Clone, Debug)]
pub struct ComposeBuf {
    /// The vector holding the bytes.
    vec: Vec<u8>,

    /// Composition mode.
    mode: ComposeMode,

    /// The index in `vec` where the message started.
    ///
    /// All message compression indexes will be relative to this value.
    start: usize,

    /// The truncation point if set.
    checkpoint: Option<usize>,

    /// Has the vector been truncated yet?
    truncated: bool,

    /// A hashmap storing the indexes of domain names for compression.
    ///
    /// If this is `None`, we don’t do compression at all.
    compress: Option<HashMap<DNameBuf, u16>>,
}


/// # Creation and Finalization
///
impl ComposeBuf {
    /// Creates a new compose buffer.
    ///
    /// The composition mode is given through `mode`. If `compress` is
    /// `true`, name compression will be available for domain names.
    /// Otherwise, all names will always be uncompressed.
    pub fn new(mode: ComposeMode, compress: bool) -> Self {
        ComposeBuf::with_vec(Vec::new(), mode, compress)
    }

    /// Create a new compose buffer based on an existing vector.
    ///
    /// The existing content of `vec` will be used as a prefix to the
    /// message and the actual DNS message will start after it.
    ///
    /// The composition mode is given through `mode`. If the mode is
    /// `ComposeMode::Stream`, two bytes will be pushed to the end of the
    /// vector before composition starts. These will be updated once
    /// `finish()` is being called to the size of the composition.
    ///
    /// If `compress` is `true`, name compression will be used if requested.
    /// Otherwise, all domain names are always uncompressed.
    pub fn with_vec(mut vec: Vec<u8>, mode: ComposeMode, compress: bool)
                    -> ComposeBuf {
        if let ComposeMode::Stream = mode {
            use bits::bytes::BytesBuf;
            vec.push_u16(0);
        }
        let start = vec.len();
        ComposeBuf {
            vec: vec,
            mode: mode,
            start: start,
            checkpoint: None,
            truncated: false,
            compress: if compress { Some(HashMap::new()) }
                      else { None }
        }
    }

    /// Returns a bytes vector with the final data.
    pub fn finish(mut self) -> Vec<u8> {
        if let ComposeMode::Stream = self.mode {
            let start = self.start - 2;
            let delta = self.delta(self.start) as u16;
            self.update_u16(start, delta).unwrap();
        }
        self.vec
    }
}


/// # Internal Helpers
///
impl ComposeBuf {
    /// Checks whether `len` bytes can be pushed to the message.
    ///
    /// This method can be used with `try!` for convenience.
    fn keep_pushing(&mut self, len: usize) -> ComposeResult<()> {
        if self.truncated { return Err(ComposeError::SizeExceeded) }
        let maxlen = match self.mode {
            ComposeMode::Unlimited => return Ok(()),
            ComposeMode::Limited(len) => len,
            ComposeMode::Stream => 0xFFFF,
        };
        if maxlen < self.vec.len() + self.start + len {
            self.checkpoint.map(|len| self.vec.truncate(len));
            self.truncated = true;
            return Err(ComposeError::SizeExceeded)
        }
        Ok(())
    }

    /// Pushes a domain name ignoring compression entirely.
    ///
    /// The name will be pushed uncompressed and no entries will be made
    /// to the compression hashmap.
    fn push_dname_simple<D: AsDName>(&mut self, name: &D)
                                     -> ComposeResult<()> {
        for label in name.as_dname().iter() {
            let label = try!(label);
            try!(label.compose(self));
            if label.is_root() {
                return Ok(())
            }
        }
        Err(ComposeError::RelativeName)
    }

    /// Returns the compression index for the current position.
    fn compress_pos(&self) -> usize {
        self.vec.len() - self.start
    }

    /// Adds `name` to the compression hashmap with `pos` as its index.
    fn add_compress_target(&mut self, name: DNameBuf, pos: usize) {
        if let Some(ref mut compress) = self.compress {
            if pos <= ::std::u16::MAX as usize {
                let _ = compress.insert(name, pos as u16);
            }
        }
    }

    /// Returns the compression index for the given name if any.
    fn get_compress_target(&self, name: &DNameSlice) -> Option<u16> {
        if let Some(ref compress) = self.compress {
            compress.get(name).map(|v| *v)
        }
        else { None }
    }
}


//--- ComposeBytes

impl ComposeBytes for ComposeBuf {
    type Pos = usize;

    fn push_bytes(&mut self, data: &[u8]) -> ComposeResult<()> {
        try!(self.keep_pushing(data.len()));
        self.vec.extend(data);
        Ok(())
    }

    fn push_empty(&mut self, len: usize) -> ComposeResult<()> {
        try!(self.keep_pushing(len));
        let len = self.vec.len() + len;
        self.vec.resize(len, 0);
        Ok(())
    }

    fn push_dname<D: AsDName>(&mut self, name: &D) -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = try!(name.as_dname().into_cow());
            if name.is_relative() {
                return Err(ComposeError::RelativeName);
            }
            let mut name_ref = name.deref();
            while let Some((label, tail)) = name_ref.split_first() {
                let pos = self.compress_pos();
                try!(label.compose(self));
                self.add_compress_target(name_ref.to_owned(), pos);
                name_ref = tail;
            }
            Ok(())
        }
        else {
            self.push_dname_simple(name)
        }
    }

    fn push_dname_compressed<D: AsDName>(&mut self, name: &D)
                                         -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = try!(name.as_dname().into_cow());
            if name.is_relative() {
                return Err(ComposeError::RelativeName);
            }
            let mut iter = name.iter();
            loop {
                let name = iter.as_name();
                if let Some(pos) = self.get_compress_target(name) {
                    try!(Label::compose_compressed(self, pos));
                    break;
                }
                let label = match iter.next() {
                    Some(x) => x, None => break
                };
                let pos = self.compress_pos();
                try!(label.compose(self));
                self.add_compress_target(name.to_owned(), pos);
            }
            Ok(())
        }
        else {
            self.push_dname_simple(name)
        }
    }

    fn truncation_point(&mut self) {
        self.checkpoint = Some(self.vec.len())
    }

    fn truncated(&self) -> bool {
        self.truncated
    }

    fn pos(&self) -> Self::Pos {
        self.vec.len()
    }

    fn delta(&self, pos: Self::Pos) -> usize {
        self.vec.len().checked_sub(pos).unwrap()
    }

    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8])
                    -> ComposeResult<()> {
        if pos + data.len() > self.vec.len() {
            panic!("composer update overrun")
        }
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(),
                                 self.vec[pos..pos + data.len()].as_mut_ptr(),
                                 data.len())
        }
        Ok(())
    }
}


//--- Deref

impl Deref for ComposeBuf {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        &self.vec
    }
}


//------------ ComposeMode ---------------------------------------------------

/// An enum determining the construction mode of a composition.
#[derive(Clone, Debug)]
pub enum ComposeMode {
    /// The composition can grow to any size.
    Unlimited,

    /// The composition can never exceed a size of the given value.
    ///
    /// When creating a `ComposeBuf` from an existing vector, the maximum
    /// only pertains to the composition itself. That is, the resulting
    /// vector will be larger by whatever has been in there already.
    Limited(usize),

    /// The composition is for a stream transport.
    ///
    /// In this mode, the composition will be preceeded by a two-byte value
    /// which, upon finishing, will be set to the length of the composition.
    /// This implies a maximum composition size of 65535 bytes.
    Stream
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use bits::error::ComposeError;
    use bits::name::DNameBuf;
    use super::*;

    #[test]
    fn simple_push() {
        let mut c = ComposeBuf::new(None, false);
        c.push_bytes(b"foo").unwrap();
        c.push_u8(0x07).unwrap();
        c.push_u16(0x1234).unwrap();
        c.push_u32(0xdeadbeef).unwrap();
        assert_eq!(c.finish(),
                   b"foo\x07\x12\x34\xde\xad\xbe\xef");
    }

    #[test]
    fn push_name() {
        let mut c = ComposeBuf::new(None, false);
        c.push_dname(&DNameBuf::from_str("foo.bar.").unwrap()).unwrap();
        assert_eq!(c.finish(),
                   b"\x03foo\x03bar\x00");
    }

    #[test]
    fn push_compressed_name() {
        // Same name again.
        let mut c = ComposeBuf::new(None, true);
        c.push_u8(0x07).unwrap();
        c.push_dname(&DNameBuf::from_str("foo.bar.").unwrap()).unwrap();
        c.push_dname_compressed(&DNameBuf::from_str("foo.bar.").unwrap())
         .unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\xC0\x01");

        // Prefixed name.
        let mut c = ComposeBuf::new(None, true);
        c.push_u8(0x07).unwrap();
        c.push_dname(&DNameBuf::from_str("foo.bar.").unwrap()).unwrap();
        c.push_dname_compressed(&DNameBuf::from_str("baz.foo.bar.").unwrap())
         .unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\x03baz\xC0\x01");

        // Suffixed name.
        let mut c = ComposeBuf::new(None, true);
        c.push_u8(0x07).unwrap();
        c.push_dname(&DNameBuf::from_str("foo.bar.").unwrap()).unwrap();
        c.push_dname_compressed(&DNameBuf::from_str("bar.").unwrap())
         .unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\xC0\x05");
    }

    #[test]
    fn update() {
        let mut c = ComposeBuf::new(None, false);
        c.push_bytes(b"foo").unwrap();
        let p8 = c.pos();
        c.push_u8(0x00).unwrap();
        let p16 = c.pos();
        c.push_u16(0x83c7).unwrap();
        let p32 = c.pos();
        c.push_u32(0x12312819).unwrap();

        c.update_u8(p8, 0x07).unwrap();
        c.update_u16(p16, 0x1234).unwrap();
        c.update_u32(p32, 0xdeadbeef).unwrap();
        assert_eq!(c.finish(),
                   b"foo\x07\x12\x34\xde\xad\xbe\xef");
    }

    #[test]
    fn truncation() {
        let mut c = ComposeBuf::new(Some(4), false);
        assert!(!c.truncated());
        c.push_u16(0).unwrap();
        assert!(!c.truncated());
        c.truncation_point();
        c.push_u8(0).unwrap();
        assert!(!c.truncated());
        assert_eq!(c.push_u16(0), Err(ComposeError::SizeExceeded));
        assert_eq!(c.push_u16(0), Err(ComposeError::SizeExceeded));
        assert!(c.truncated());
        assert_eq!(c.finish(),
                   b"\0\0");
    }
}

