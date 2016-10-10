//! Assembling wire-format DNS data.
//!
//! This module provides helper types for assembling the wire format of a
//! DNS message, a process termed *composing* to distinguish it from other
//! procedures that turn DNS data into some output such as formatting into
//! human-readable data.
//!
//! There are two main types here. [`Composer`] owns a bytes vector and
//! provides a number of methods allowing to append data to it meanwhile
//! making sure that certain conditions such as the maximum message size are
//! being fulfilled. These conditions are defined through the [`ComposeMode`].
//!
//! The [`Composer`] has a companion type [`ComposeSnapshot`] that wraps the
//! original composer but allows it to roll back to an earlier state. The
//! intention here is to reuse a partly assembled message a second attempt
//! with slightly different data.
//!
//! As a convenience, there is a trait [`Composable`] that can be implemented
//! for types that know how to add themselves to a message-to-be.
//!
//! # Todo
//!
//! Snapshots currently clone the compression map. As this is costly, we
//! should have a way to either only clone on write or allow turn off 
//! compressing before cloning. This isn’t all that important, though, since
//! we can create requests (which contain exactly one domain name in their
//! only question) with compression turned off entirely.
//!
//! [`Composer`]: struct.Composer.html
//! [`ComposeMode`]: enum.ComposeMode.html
//! [`ComposeSnapshot`]: struct.ComposeSnapshot.html
//! [`Composable`]: trait.Composable.html

use std::{error, fmt, ptr};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use super::name::{DName, DNameBuf, DNameSlice};
use super::parse::ParseError;


//------------ Composer ------------------------------------------------------

/// A type for assembling a wire-format DNS message.
///
/// A composer can be created either anew with [`new()`] or through
/// [`from_vec()`] atop an existing vector that may already contain some data.
/// In either case, a [`ComposeMode`] is necessary to tell the composer what
/// kind of message it is supposed to create.
///
/// In particular, there is something called the *stream mode*, requested
/// through `ComposeMode::Stream`, where a sixteen bit, big-endian length
/// shim is prepended to the actual message as required for sending DNS
/// messages over stream transports such as TCP. It’s value, however, is
/// not constantly updated but only when [`preview()`] or [`finish()`] are
/// called.
///
/// A number of methods are available for adding data to the composer.
/// Alternatively, types may implement [`Composable`] to acquire a
/// `compose()` method themselves.
///
/// Since it makes composing a lot easier, methods are available to update
/// data added earlier. These are normally used to add length markers after
/// the fact without always having to know the eventual size of data added.
///
/// DNS messages that are sent over the wire are limited in size. If a
/// message becomes to large, it has to be cut back to a well-known boundary
/// and a truncation flag set in the header. To facilitate this process,
/// a checkpoint can be set during composing. If the composition grows over
/// the limit, it will be cut back to that checkpoint. Any further composing
/// will fail.
///
/// Note that size limits apply to the assembled message. If a composer is
/// created atop an exisiting vector, the size of any earlier data is not
/// considered.
///
/// [`new()`]: #method.new
/// [`from_vec()`]: #method.from_vec
/// [`preview()`]: #method.preview
/// [`finish()`]: #method.finish
/// [`ComposeMode`]: ../enum.ComposeMode.html
/// [`Composable`]: ../trait.Composable.html
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
    ///
    /// A possible prefix and the maximum size of the composed message are
    /// determined through `mode`. If `compress` is `true`, name compression
    /// will be available for domain names. Otherwise, all names will always
    /// be uncompressed.
    pub fn new(mode: ComposeMode, compress: bool) -> Self {
        Self::from_vec(Vec::new(), mode, compress)
    }

    /// Creates a new compose buffer based on an exisiting vector.
    ///
    /// The existing content of `vec` will be preserved and the actual DNS
    /// message will start after it.
    ///
    /// A possible prefix and the maximum size of the composed message are
    /// determined through `mode`. If `compress` is `true`, name compression
    /// will be available for domain names. Otherwise, all names will always
    /// be uncompressed.
    pub fn from_vec(mut vec: Vec<u8>, mode: ComposeMode, compress: bool)
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

    /// Finalizes the composition and returns the final data.
    pub fn finish(mut self) -> Vec<u8> {
        self.update_shim();
        self.vec
    }

    /// Updates the size shim if the composer is in stream mode.
    fn update_shim(&mut self) {
        if let ComposeMode::Stream = self.mode {
            let start = self.start - 2;
            let delta = self.delta(self.start) as u16;
            self.update_u16(start, delta);
        }
    }

    /// Returns a snapshot of the composer at its current position.
    ///
    /// If the snapshot is rolled back, the resulting composer will be
    /// exactly the same as `self` right now.
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
    ///
    /// The returned bytes slice really only contains the message bytes
    /// and neither whatever was contained in the vector with which the
    /// composer was posssibly created nor the length prefix of stream
    /// mode.
    pub fn so_far(&self) -> &[u8] {
        &self.vec[self.start..]
    }

    /// Returns the message bytes as far as they are assembled yet.
    ///
    /// The returned bytes slice really only contains the message bytes
    /// and neither whatever was contained in the vector with which the
    /// composer was posssibly created nor the length prefix of stream
    /// mode.
    pub fn so_far_mut(&mut self) -> &mut [u8] {
        &mut self.vec[self.start..]
    }
}


/// # Working with Positions
///
impl Composer {
    /// Returns the current position.
    ///
    /// The returned value is identical to the current overall length of the
    /// underlying bytes vec.
    pub fn pos(&self) -> usize {
        self.vec.len()
    }

    /// Returns the position where the message starts.
    ///
    /// This is identical to having called `self.pos()` right after `self`
    /// was created.
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

    /// Marks the current position as a point for truncation.
    ///
    /// If the length of the resulting message exceeds its predefined
    /// maximum size for the first time after a call to this method, the
    /// data will be cut back to the length it had when the method was
    /// called. If this happens, any further writing will fail.
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
    ///
    /// In particular, if successful, the message will have been extended
    /// by `len` octets of value zero,
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
    ///
    /// Since DNS data is big-endian, `data` will be converted to that
    /// endianess if necessary.
    pub fn compose_u16(&mut self, data: u16) -> ComposeResult<()> {
        try!(self.can_push(2));
        self.vec.write_u16::<BigEndian>(data).unwrap();
        Ok(())
    }

    /// Pushes a unsigned 32-bit word to the end of the message.
    ///
    /// Since DNS data is big-endian, `data` will be converted to that
    /// endianess if necessary.
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
    /// [RFC 1123] and [RFC 3597], this isn’t the default behaviour.
    ///
    /// [RFC 1123]: https://tools.ietf.org/html/rfc1123
    /// [RFC 3597]: https://tools.ietf.org/html/rfc3597
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
        for label in name.labels() {
            try!(self.compose_bytes(label.as_bytes()));
            if label.is_root() {
                return Ok(())
            }
        }
        self.vec.truncate(pos);
        Err(ComposeError::RelativeName)
    }

    /// Adds `name` to the compression hashmap with `pos` as its index.
    ///
    /// The value of `pos` is a composer position as returned by `pos()`
    /// and will be translated into a valid message index before adding.
    fn add_compress_target(&mut self, name: DNameBuf, pos: usize) {
        if let Some(ref mut compress) = self.compress {
            let pos = pos.checked_sub(self.start).unwrap();
            if pos <= 0x3FFF {
                let _ = compress.insert(name, pos as u16);
            }
        }
    }

    /// Returns the index where the given name starts in the message.
    ///
    /// The returned value, if any, is relative to the start of the message
    /// and can be used as is.
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
    /// Panics if the position is greater than 0x3FFF, the largest position
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

/// A snapshot of a composer’s state.
///
/// This type is actually a composer all by itself, that is, it implements
/// `AsMut<Composer>`. However, if necessary, it can be rolled back to the
/// state the composer had when it was created forgetting about all changes
/// made since.
///
/// This process currently is not transitive. While a new snapshot can be
/// created from both a composer and a snapshot, when you roll back you get
/// a composer. Ie., you can only roll back once. This is enough for the
/// purpose, reuse of messages when transitioning through several servers
/// in a resolver.
#[derive(Clone, Debug)]
pub struct ComposeSnapshot {
    /// The composer we deref to.
    composer: Composer,

    /// The positon to roll back to.
    pos: usize,

    /// The value of the checkpoint to roll back to.
    checkpoint: Option<usize>,

    /// The value of `truncated` to roll back to.
    truncated: bool,

    /// The value of `compress` to roll back to.
    compress: Option<HashMap<DNameBuf, u16>>
}


impl ComposeSnapshot {
    /// Creates a new snapshot from the given composer.
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

    /// Rewinds the state to when the snapshot was taken.
    pub fn rewind(&mut self) {
        self.composer.vec.truncate(self.pos);
        self.composer.checkpoint = self.checkpoint;
        self.composer.truncated = self.truncated;
        self.composer.compress = self.compress.clone();
    }

    /// Rolls back to a composer with state as when the snapshot was taken.
    pub fn rollback(self) -> Composer {
        let mut res = self.composer;
        res.vec.truncate(self.pos);
        res.checkpoint = self.checkpoint;
        res.truncated = self.truncated;
        res.compress = self.compress;
        res
    }

    /// Trades in the snapshot to a composer with all changes commited.
    pub fn commit(self) -> Composer {
        self.composer
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
    /// which, upon finishing, will be set to the big-endian sixteen bit
    /// integer value of the length of the composition.
    /// This implies a maximum composition size of 65535 bytes.
    Stream
}


//------------ Composeable ---------------------------------------------------

/// A trait allowing types to compose themselves.
pub trait Composable {

    /// Append the wire-format representation of `self` to a composer.
    ///
    /// The method is generic over `AsMut<Composer>` because it may either
    /// receive a [`Composer`] or [`ComposeSnapshot`]. This means that when
    /// using `target`, you’ll have to call `target.as_mut()`.
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
    /// In some cases composition can happen using as-yet unparsed DNS data.
    /// If necessary parsing fails, its error is wrapped in this variant.
    ParseError(ParseError),
}


//--- Error

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


//--- From

impl From<ParseError> for ComposeError {
    fn from(error: ParseError) -> ComposeError {
        ComposeError::ParseError(error)
    }
}


//--- Display

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


/// The result type for a `ComposeError`.
pub type ComposeResult<T> = Result<T, ComposeError>;


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use bits::name::DNameSlice;
    use super::*;

    #[test]
    fn bytes_and_ints() {
        let mut c = Composer::new(ComposeMode::Unlimited, false);
        c.compose_bytes(b"foo").unwrap();
        c.compose_u8(0x07).unwrap();
        c.compose_u16(0x1234).unwrap();
        c.compose_u32(0xdeadbeef).unwrap();
        assert_eq!(c.finish(),
                   b"foo\x07\x12\x34\xde\xad\xbe\xef");
    }

    #[test]
    fn dname() {
        let mut c = Composer::new(ComposeMode::Unlimited, false);
        let name = DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap();
        c.compose_dname(&name).unwrap();
        assert_eq!(c.finish(), b"\x03foo\x03bar\x00");

        let mut c = Composer::new(ComposeMode::Unlimited, false);
        let name = DNameSlice::root();
        c.compose_dname(&name).unwrap();
        assert_eq!(c.finish(), b"\x00");

        let mut c = Composer::new(ComposeMode::Unlimited, false);
        let name = DNameSlice::from_bytes(b"\x03foo\x03bar").unwrap();
        assert_eq!(c.compose_dname(&name),
                   Err(ComposeError::RelativeName));
    }

    #[test]
    fn dname_compressed() {
        // Same name again.
        let mut c = Composer::new(ComposeMode::Unlimited, true);
        c.compose_u8(0x07).unwrap();
        let name = DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap();
        c.compose_dname_compressed(&name).unwrap();
        c.compose_dname_compressed(&name).unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\xC0\x01");

        // Prefixed name.
        let mut c = Composer::new(ComposeMode::Unlimited, true);
        c.compose_u8(0x07).unwrap();
        let name = DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap();
        c.compose_dname_compressed(&name).unwrap();
        let name = DNameSlice::from_bytes(b"\x03baz\x03foo\x03bar\x00")
                              .unwrap();
        c.compose_dname_compressed(&name).unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\x03baz\xC0\x01");

        // Suffixed name.
        let mut c = Composer::new(ComposeMode::Unlimited, true);
        c.compose_u8(0x07).unwrap();
        let name = DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap();
        c.compose_dname_compressed(&name).unwrap();
        let name = DNameSlice::from_bytes(b"\x03baz\x03bar\x00").unwrap();
        c.compose_dname_compressed(&name).unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x03foo\x03bar\x00\x03baz\xC0\x05");

        // Don’t compress the root label.
        let mut c = Composer::new(ComposeMode::Unlimited, true);
        c.compose_u8(0x07).unwrap();
        c.compose_dname_compressed(&DNameSlice::root()).unwrap();
        let name = DNameSlice::from_bytes(b"\x03foo\x00").unwrap();
        c.compose_dname_compressed(&name).unwrap();
        c.compose_dname_compressed(&DNameSlice::root()).unwrap();
        assert_eq!(c.finish(),
                   b"\x07\x00\x03foo\x00\x00");
    }

    #[test]
    fn update() {
        let mut c = Composer::new(ComposeMode::Unlimited, false);
        c.compose_bytes(b"foo").unwrap();
        let p8 = c.pos();
        c.compose_u8(0x00).unwrap();
        let p16 = c.pos();
        c.compose_u16(0x83c7).unwrap();
        let p32 = c.pos();
        c.compose_u32(0x12312819).unwrap();

        c.update_u8(p8, 0x07);
        c.update_u16(p16, 0x1234);
        c.update_u32(p32, 0xdeadbeef);
        assert_eq!(c.finish(),
                   b"foo\x07\x12\x34\xde\xad\xbe\xef");
    }

    #[test]
    fn truncated() {
        let mut c = Composer::new(ComposeMode::Limited(4), false);
        c.compose_u16(0x1234).unwrap();
        assert!(!c.is_truncated());
        c.mark_checkpoint();
        assert_eq!(c.compose_u32(0xdeadbeef),
                   Err(ComposeError::SizeExceeded));
        assert!(c.is_truncated());
        assert_eq!(c.finish(),
                   b"\x12\x34");
    }

    #[test]
    fn stream_mode() {
        let mut c = Composer::new(ComposeMode::Stream, false);
        assert_eq!(c.preview(), b"\x00\x00");
        assert_eq!(c.so_far(), b"");
        c.compose_u32(0xdeadbeef).unwrap();
        assert_eq!(c.preview(), b"\x00\x04\xde\xad\xbe\xef");
        assert_eq!(c.so_far(), b"\xde\xad\xbe\xef");
        assert_eq!(c.finish(), b"\x00\x04\xde\xad\xbe\xef");
    }

    #[test]
    fn snapshot() {
        let mut c = Composer::new(ComposeMode::Stream, false);
        c.compose_u16(0x1234).unwrap();
        let mut s = c.snapshot();
        assert_eq!(s.so_far(), b"\x12\x34");
        s.compose_u16(0x5678).unwrap();
        assert_eq!(s.so_far(), b"\x12\x34\x56\x78");
        s.rewind();
        assert_eq!(s.so_far(), b"\x12\x34");
        s.compose_u16(0x5678).unwrap();
        assert_eq!(s.so_far(), b"\x12\x34\x56\x78");
        let c = s.rollback();
        assert_eq!(c.so_far(), b"\x12\x34");
        let mut s = c.snapshot();
        s.compose_u16(0x5678).unwrap();
        let c = s.commit();
        assert_eq!(c.finish(), b"\x00\x04\x12\x34\x56\x78");
    }
}

