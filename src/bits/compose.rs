//! Building of wire-format DNS data.

use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::ptr;
use super::error::{ComposeError, ComposeResult};
use super::name::{DName, DNameSlice, Label, OwnedDName};


//------------ ComposeBytes ---------------------------------------------------

/// A trait for composing a DNS wire format message.
///
/// Messages are created by pushing data to the end of the message.
/// However, in order to avoid having to preassemble length-value parts of
/// the message such as record data, there is an option to update previously
/// written data.
pub trait ComposeBytes: Sized + fmt::Debug {
    type Pos: Copy + fmt::Debug;

    //--- Appending of basic types

    /// Pushes a bytes slice to the end of the builder.
    fn push_bytes(&mut self, data: &[u8]) -> ComposeResult<()>;

    /// Pushes placeholder bytes to the end of the target.
    fn push_empty(&mut self, len: usize) -> ComposeResult<()>;

    /// Pushes a single octet to the end of the builder.
    fn push_u8(&mut self, data: u8) -> ComposeResult<()> {
        let bytes: [u8; 1] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    /// Pushes an unsigned 16-bit word to the end of the builder.
    ///
    /// The word is converted to network byte order before writing if
    /// necessary.
    fn push_u16(&mut self, data: u16) -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 2] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    /// Pushes a unsigned 32-bit word to the end of the builder.
    ///
    /// The word is converted to network byte order before writing if
    /// necessary.
    fn push_u32(&mut self, data: u32) -> ComposeResult<()> {
        let data = data.to_be();
        let bytes: [u8; 4] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes)
    }

    //--- Appending of domain names.

    /// Pushes a domain name to the end of the builder.
    fn push_dname<D: DName>(&mut self, name: &D) -> ComposeResult<()>;

    /// Pushes a domain name to the end of the builder using compression.
    fn push_dname_compressed<D: DName>(&mut self, name: &D)
                                       -> ComposeResult<()>;


    //--- Checkpoint and rollback.

    /// Mark the current position as a point for truncation.
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


//------------ ComposeVec -----------------------------------------------------

/// A compose target based on a simple vector.
#[derive(Clone, Debug)]
pub struct ComposeVec {
    vec: Vec<u8>,
    start: usize,
    maxlen: Option<usize>,
    checkpoint: Option<usize>,
    truncated: bool,
    compress: Option<HashMap<OwnedDName, u16>>,
}


impl ComposeVec {
    pub fn new(maxlen: Option<usize>, compress: bool) -> ComposeVec {
        ComposeVec::with_vec(Vec::new(), maxlen, compress)
    }

    pub fn with_vec(vec: Vec<u8>, maxlen: Option<usize>, compress: bool)
                    -> ComposeVec {
        let start = vec.len();
        ComposeVec {
            vec: Vec::new(),
            start: start,
            maxlen: maxlen,
            checkpoint: None,
            truncated: false,
            compress: if compress { Some(HashMap::new()) }
                      else { None }
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.vec
    }
}


impl ComposeVec {
    fn keep_pushing(&mut self, len: usize) -> ComposeResult<()> {
        if self.truncated { return Err(ComposeError::SizeExceeded) }
        else if let Some(maxlen) = self.maxlen {
            if maxlen < self.vec.len() + len {
                self.checkpoint.map(|len| self.vec.truncate(len));
                self.truncated = true;
                return Err(ComposeError::SizeExceeded)
            }
        }
        Ok(())
    }

    fn push_dname_simple<D: DName>(&mut self, name: &D) -> ComposeResult<()> {
        for label in try!(name.to_cow()).iter() {
            try!(label.compose(self))
        }
        Ok(())
    }

    fn compress_pos(&self) -> usize {
        self.vec.len() - self.start
    }

    fn add_compress_target(&mut self, name: OwnedDName, pos: usize) {
        if let Some(ref mut compress) = self.compress {
            if pos <= ::std::u16::MAX as usize {
                let _ = compress.insert(name, pos as u16);
            }
        }
    }

    fn get_compress_target(&self, name: &DNameSlice) -> Option<u16> {
        if let Some(ref compress) = self.compress {
            compress.get(name).map(|v| *v)
        }
        else { None }
    }
}


impl ComposeBytes for ComposeVec {
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

    fn push_dname<D: DName>(&mut self, name: &D) -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = try!(name.to_owned());
            let pos = self.compress_pos();
            try!(self.push_dname_simple(&name));
            self.add_compress_target(name, pos);
            Ok(())
        }
        else {
            self.push_dname_simple(name)
        }
    }

    fn push_dname_compressed<D: DName>(&mut self, name: &D)
                                       -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = try!(name.to_cow());
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


