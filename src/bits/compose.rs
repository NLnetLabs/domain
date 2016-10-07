//! Building wire-format DNS data.

use std::collections::HashMap;
use std::error;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::ptr;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use super::name::{DName, DNameBuf, DNameSlice};
use super::parser::ParseError;


//------------ Composer ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Composer {
    /// The vector holding the bytes.
    vec: Vec<u8>,

    /// Composition mode.
    mode: ComposeMode,

    /// The index in `vec` where the message started.
    ///
    /// All message compression indexes placed in the message will be
    /// relative to this value.
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
impl Composer {
    /// Creates a new composer.
    pub fn new(mode: ComposeMode, compress: bool) -> Self {
        Self::with_vec(Vec::new(), mode, compress)
    }

    /// Creates a new compose buffer based on an exisiting vector.
    pub fn with_vec(mut vec: Vec<u8>, mode: ComposeMode, compress: bool)
                    -> Self {
        if let ComposeMode::Stream = mode {
            vec.write_u16::<BigEndian>(0).unwrap();
        }
        let start = vec.len();
        Composer {
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
        self.update_shim();
        self.vec
    }

    fn update_shim(&mut self) {
        if let ComposeMode::Stream = self.mode {
            let start = self.start - 2;
            let delta = self.delta(self.start) as u16;
            self.update_u16(start, delta);
        }
    }

    /// Returns a snapshot of the composer.
    pub fn snapshot(self) -> ComposeSnapshot {
        ComposeSnapshot::new(self)
    }

    /// Returns a reference to the underlying vector as it looks now.
    ///
    /// This method updates the length shim in stream mode, hence the
    /// need for a `&mut self`.
    pub fn preview(&mut self) -> &[u8] {
        self.update_shim();
        &self.vec
    }

    /// Returns the message bytes as far as they are assembled yet.
    pub fn so_far(&self) -> &[u8] {
        &self.vec[self.start..]
    }

    pub fn so_far_mut(&mut self) -> &mut [u8] {
        &mut self.vec[self.start..]
    }
}


/// # Working with Positions
///
impl Composer {
    /// Returns the current position.
    pub fn pos(&self) -> usize {
        self.vec.len()
    }

    /// Returns the position where the message starts.
    pub fn start(&self) -> usize {
        self.start
    }

    /// Returns the length of data added since the given position.
    ///
    /// # Panics
    ///
    /// Panics if `pos` is larger than the current position.
    pub fn delta(&self, pos: usize) -> usize {
        self.vec.len().checked_sub(pos).unwrap()
    }

    /// Mark the current position as a point for truncation.
    ///
    /// If the length of the resulting message exceeds its predefined
    /// maximum size for the first time and a truncation point was set, it
    /// will be cut back to that point.
    pub fn mark_checkpoint(&mut self) {
        self.checkpoint = Some(self.pos())
    }

    /// Returns whether the target has been truncated.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}


/// # Composing
///
impl Composer {
    /// Pushes a bytes slice to the end of the message.
    pub fn compose_bytes(&mut self, data: &[u8]) -> ComposeResult<()> {
        try!(self.can_push(data.len()));
        self.vec.extend_from_slice(data);
        Ok(())
    }

    /// Pushes placeholder bytes to the end of the message.
    pub fn compose_empty(&mut self, len: usize) -> ComposeResult<()> {
        try!(self.can_push(len));
        let len = self.vec.len() + len;
        self.vec.resize(len, 0);
        Ok(())
    }

    /// Pushes a single octet to the end of the message.
    pub fn compose_u8(&mut self, data: u8) -> ComposeResult<()> {
        try!(self.can_push(1));
        self.vec.write_u8(data).unwrap();
        Ok(())
    }

    /// Pushes an unsigned 16-bit word to the end of the message.
    pub fn compose_u16(&mut self, data: u16) -> ComposeResult<()> {
        try!(self.can_push(2));
        self.vec.write_u16::<BigEndian>(data).unwrap();
        Ok(())
    }

    /// Pushes a unsigned 32-bit word to the end of the message.
    pub fn compose_u32(&mut self, data: u32) -> ComposeResult<()> {
        try!(self.can_push(4));
        self.vec.write_u32::<BigEndian>(data).unwrap();
        Ok(())
    }

    /// Pushes a domain name to the end of the message.
    pub fn compose_dname<N: DName>(&mut self, name: &N)
                                   -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = name.to_cow();
            if name.is_relative() {
                // This also catches an empty label ...
                return Err(ComposeError::RelativeName);
            }
            let mut name_ref = name.deref();
            loop {
                let pos = self.pos();
                let (label, tail) = name_ref.split_first().unwrap();
                try!(self.compose_bytes(label.as_bytes()));
                if label.is_root() {
                    return Ok(())
                }
                self.add_compress_target(name_ref.to_owned(), pos);
                name_ref = tail;
            }
        }
        else {
            self.compose_dname_simple(name)
        }
    }

    /// Pushes a domain name to the end of the message using name compression.
    ///
    /// Since compression is only allowed in a few well-known places per
    /// RFC 1123 and RFC 3597, this isn’t the default behaviour.
    pub fn compose_dname_compressed<N: DName>(&mut self, name: &N)
                                              -> ComposeResult<()> {
        if self.compress.is_some() {
            let name = name.to_cow();
            if name.is_relative() {
                // This also catches an empty label ...
                return Err(ComposeError::RelativeName);
            }
            let mut iter = name.iter();
            loop {
                let name = iter.to_cow();
                if let Some(pos) = self.get_compress_target(&name) {
                    return self.compose_compress_target(pos)
                }
                let label = iter.next().unwrap();
                let pos = self.pos();
                try!(self.compose_bytes(label.as_bytes()));
                if label.is_root() {
                    return Ok(())
                }
                self.add_compress_target(name.deref().to_owned(), pos);
            }
        }
        else {
            self.compose_dname_simple(name)
        }
    }
}


/// # Helpers for Composing
///
impl Composer {
    /// Checks whether `len` bytes can be pushed to the message.
    ///
    /// This method can be used with `try!` for convenience.
    fn can_push(&mut self, len: usize) -> ComposeResult<()> {
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
    fn compose_dname_simple<N: DName>(&mut self, name: &N)
                                      -> ComposeResult<()> {
        let pos = self.vec.len();
        for label in name.iter() {
            try!(self.compose_bytes(label.as_bytes()));
            if label.is_root() {
                return Ok(())
            }
        }
        self.vec.truncate(pos);
        Err(ComposeError::RelativeName)
    }

    /// Adds `name` to the compression hashmap with `pos` as its index.
    fn add_compress_target(&mut self, name: DNameBuf, pos: usize) {
        if let Some(ref mut compress) = self.compress {
            let pos = pos.checked_sub(self.start).unwrap();
            if pos <= 0x3FFF {
                let _ = compress.insert(name, pos as u16);
            }
        }
    }

    /// Returns the compression index for the given name if any.
    fn get_compress_target<N: AsRef<DNameSlice>>(&self, name: N)
                                                 -> Option<u16> {
        if let Some(ref compress) = self.compress {
            compress.get(name.as_ref()).cloned()
        }
        else { None }
    }

    /// Composes a pointer label.
    ///
    /// # Panics
    ///
    /// Panics if the position is greater than 0x3FFFF, the largest position
    /// we can encode.
    fn compose_compress_target(&mut self, pos: u16) -> ComposeResult<()> {
        assert!(pos <= 0x3FFF);
        let pos = pos | 0xC000;
        self.compose_u16(pos)
    }
}


/// # Updating Earlier Data
///
impl Composer {
    /// Updates the bytes starting at the given position.
    ///
    /// # Panics
    ///
    /// Panics if the bytes slice is longer than the data assembled since
    /// the given position.
    pub fn update_bytes(&mut self, pos: usize, data: &[u8]) {
        if pos + data.len() > self.vec.len() {
            panic!("composer update overrun");
        }
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(),
                                 self.vec[pos..pos + data.len()].as_mut_ptr(),
                                 data.len())
        }
    }

    /// Updates the octet at the given position.
    ///
    /// # Panics
    ///
    /// Panics if there has not been at least one byte of data assembled
    /// since the given position.
    pub fn update_u8(&mut self, pos: usize, data: u8) {
        self.vec[pos] = data
    }

    /// Updates an unsigned 16-bit word starting at the given position.
    ///
    /// # Panics
    ///
    /// Panics if there has not been at least two bytes of data assembled
    /// since the given position.
    pub fn update_u16(&mut self, pos: usize, data: u16) {
        BigEndian::write_u16(&mut self.vec[pos..], data);
    }

    /// Updates an unsigned 32-bit word starting at the given position.
    ///
    /// # Panics
    ///
    /// Panics if there has not been at least four bytes of data assembled
    /// since the given position.
    pub fn update_u32(&mut self, pos: usize, data: u32) {
        BigEndian::write_u32(&mut self.vec[pos..], data);
    }
}

//--- AsRef, AsMut

impl AsRef<Composer> for Composer {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsMut<Composer> for Composer {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}


//------------ ComposeSnapshot ----------------------------------------------

#[derive(Clone, Debug)]
pub struct ComposeSnapshot {
    composer: Composer,
    pos: usize,
    checkpoint: Option<usize>,
    truncated: bool,
    compress: Option<HashMap<DNameBuf, u16>>
}


impl ComposeSnapshot {
    pub fn new(mut composer: Composer) -> Self {
        composer.update_shim();
        ComposeSnapshot {
            pos: composer.vec.len(),
            checkpoint: composer.checkpoint,
            truncated: composer.truncated,
            compress: composer.compress.clone(),
            composer: composer
        }
    }

    pub fn rewind(&mut self) {
        self.composer.vec.truncate(self.pos);
        self.composer.checkpoint = self.checkpoint;
        self.composer.truncated = self.truncated;
        self.composer.compress = self.compress.clone();
    }

    pub fn rollback(self) -> Composer {
        let mut res = self.composer;
        res.vec.truncate(self.pos);
        res.checkpoint = self.checkpoint;
        res.truncated = self.truncated;
        res.compress = self.compress;
        res
    }

    pub fn commit(self) -> Composer {
        self.composer
    }

    pub fn bytes(&self) -> &[u8] {
        &self.composer.vec[..self.pos]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.composer.vec[..self.pos]
    }
}


//--- Deref, DerefMut, AsRef, AsMut

impl Deref for ComposeSnapshot {
    type Target = Composer;

    fn deref(&self) -> &Self::Target {
        &self.composer
    }
}

impl DerefMut for ComposeSnapshot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.composer
    }
}

impl AsRef<Composer> for ComposeSnapshot {
    fn as_ref(&self) -> &Composer {
        &self.composer
    }
}

impl AsMut<Composer> for ComposeSnapshot {
    fn as_mut(&mut self) -> &mut Composer {
        &mut self.composer
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


//------------ Composeable ---------------------------------------------------

pub trait Composable {
    fn compose<C: AsMut<Composer>>(&self, target: C) -> ComposeResult<()>;
}

impl Composable for [u8] {
    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        target.as_mut().compose_bytes(self)
    }
}

impl Composable for u8 {
    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        target.as_mut().compose_u8(*self)
    }
}

impl Composable for u16 {
    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        target.as_mut().compose_u16(*self)
    }
}

impl Composable for u32 {
    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        target.as_mut().compose_u32(*self)
    }
}


//------------ ComposeError and ComposeResult -------------------------------

/// An error happening when composing wire-format DNS data.
#[derive(Clone, Debug, PartialEq)]
pub enum ComposeError {
    /// The maximum size of the message has been exceeded.
    SizeExceeded,

    /// An internal counter has overflown.
    ///
    /// Examples of these are record counters for the various sections in the
    /// message header.
    Overflow,

    /// A domain name is too long.
    ///
    /// Domain names within messages are limited to 255 bytes overall.
    LongName,

    /// A domain name was relative.
    ///
    /// Since domain names are implicitely terminated by the root label
    /// within messages, only absolute names are acceptable for composing.
    RelativeName,

    /// A `ParseError` has happened while preparing data for composing.
    ///
    /// Since we are trying to be as lazy as possible, parse errors can
    /// happen very late. For instance, when writing a lazy domain name,
    /// that name is only checked when it is being written and may contain
    /// invalid references.
    ParseError(ParseError),
}

impl error::Error for ComposeError {
    fn description(&self) -> &str {
        use self::ComposeError::*;

        match *self {
            SizeExceeded => "message size has been exceeded",
            Overflow => "a counter has overflown",
            LongName => "a domain name was too long",
            RelativeName => "a relative domain name was encountered",
            ParseError(ref error) => error.description(),
        }
    }
}

impl From<ParseError> for ComposeError {
    fn from(error: ParseError) -> ComposeError {
        ComposeError::ParseError(error)
    }
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


/// The result type for a `ComposeError`.
pub type ComposeResult<T> = Result<T, ComposeError>;

