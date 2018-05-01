//! Building a domain name.
//!
//! This is a private module for tidiness. `DnameBuilder` and `PushError`
//! are re-exported by the parent module.

use bytes::{BufMut, BytesMut};
use super::dname::Dname;
use super::relative::RelativeDname;
use super::traits::{ToDname, ToRelativeDname};


//------------ DnameBuilder --------------------------------------------------

/// Builds a domain name step by step by appending data.
/// 
/// The domain name builder is the most fundamental way to construct a new
/// domain name. It wraps a [`BytesMut`] value and allows adding single bytes,
/// byte slices, or entire labels.
///
/// Unlike a [`BytesMut`], the name builder will take care of growing the
/// buffer if there isn’t enough space. It will, however, do so only once. If
/// it runs out of space, it will grow the buffer to 255 bytes, since that is
/// the maximum length of a domain name.
///
/// [`BytesMut`]: ../../../bytes/struct.BytesMut.html
#[derive(Clone)]
pub struct DnameBuilder {
    /// The buffer to build the name in.
    bytes: BytesMut,

    /// The position in `bytes` where the current label started.
    ///
    /// If this is `None` we do not have a label currently.
    head: Option<usize>,
}

impl DnameBuilder {
    /// Creates a new domain name builder from an existing bytes buffer.
    ///
    /// Whatever is in the buffer already is considered to be a relative
    /// domain name. Since that may not be the case, this function is
    /// unsafe.
    pub(super) unsafe fn from_bytes(bytes: BytesMut) -> Self {
        DnameBuilder { bytes, head: None }
    }

    /// Creates a domain name builder with default capacity.
    ///
    /// The capacity will be just large enough that the underlying `BytesMut`
    /// value does not need to allocate. On a 64 bit system, that will be 31
    /// bytes, with 15 bytes on a 32 bit system. Either should be enough to
    /// hold most common domain names.
    pub fn new() -> Self {
        unsafe {
            DnameBuilder::from_bytes(BytesMut::new())
        }
    }

    /// Creates a domain name builder with a given capacity.
    ///
    /// The `capacity` may be larger than 255, even if the resulting domain
    /// name will never be.
    pub fn with_capacity(capacity: usize) -> Self {
        unsafe {
            DnameBuilder::from_bytes(BytesMut::with_capacity(capacity))
        }
    }

    /// Returns the current length of the domain name.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the capacity of the underlying bytes buffer.
    ///
    /// A domain name can be up to 255 bytes in size independently of what
    /// this method returns.
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Returns whether there currently is a label under construction.
    ///
    /// This returns `false` if the name is still empty or if the last thing
    /// that happend was a call to [`end_label`].
    ///
    /// [`end_label`]: #method.end_label
    pub fn in_label(&self) -> bool {
        self.head.is_some()
    }

    /// Pushes a byte to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing the byte
    /// would exceed the size limits for labels or domain names.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        let len = self.bytes.len();
        if len >= 254 {
            return Err(PushError::LongName);
        }
        if let Some(head) = self.head {
            if len - head > 63 {
                return Err(PushError::LongLabel)
            }
            self.ensure_capacity(1);
        }
        else {
            self.head = Some(len);
            self.ensure_capacity(2);
            self.bytes.put_u8(0)
        }
        self.bytes.put_u8(ch);
        Ok(())
    }

    /// Appends a byte slice to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing
    /// would exceed the size limits for labels or domain names.
    ///
    /// If bytes is empty, does absolutely nothing.
    pub fn append<T: AsRef<[u8]>>(&mut self, bytes: T)
                                  -> Result<(), PushError> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() {
            return Ok(())
        }
        if let Some(head) = self.head {
            if bytes.len() > 63 - (self.bytes.len() - head) {
                return Err(PushError::LongLabel)
            }
        }
        else {
            if bytes.len() > 63 {
                return Err(PushError::LongLabel)
            }
            if self.bytes.len() + bytes.len() > 254 {
                return Err(PushError::LongName)
            }
            self.head = Some(self.bytes.len());
            self.ensure_capacity(1);
            self.bytes.put_u8(0)
        }
        self.ensure_capacity(bytes.len());
        self.bytes.put_slice(bytes);
        Ok(())
    }

    /// Ensures that there is enough capacity for `additional` bytes.
    ///
    /// The argument `additional` is only used to check whether adding that
    /// many bytes will exceed the current capacity. If it does, the buffer
    /// will be grown to a total capacity of 255 bytes. It will *not* be
    /// grown to `additional` bytes.
    fn ensure_capacity(&mut self, additional: usize) {
        if self.bytes.remaining_mut() < additional {
            let additional = 255 - self.bytes.len();
            self.bytes.reserve(additional)
        }
    }

    /// Ends the current label.
    ///
    /// If there isn’t a current label, does nothing.
    pub fn end_label(&mut self) {
        if let Some(head) = self.head {
            let len = self.bytes.len() - head - 1;
            self.bytes[head] = len as u8;
            self.head = None;
        }
    }

    /// Appends a byte slice as a complete label.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `label`.
    ///
    /// Returns an error if `label` exceeds the label size limit of 63 bytes
    /// or appending the label would exceed the domain name size limit of
    /// 255 bytes.
    pub fn append_label<T: AsRef<[u8]>>(&mut self, label: T)
                                        -> Result<(), PushError> {
        let head = self.head;
        self.end_label();
        if let Err(err) = self.append(label) {
            self.head = head;
            return Err(err)
        }
        self.end_label();
        Ok(())
    }

    /// Appends a relative domain name.
    ///
    /// If there currently is a lable under construction, it will be ended
    /// before appending `name`.
    ///
    /// Returns an error if appending would result in a name longer than 254
    /// bytes.
    //
    //  XXX NEEDS TESTS
    pub fn append_name<N: ToRelativeDname>(&mut self, name: &N)
                                           -> Result<(), PushNameError> {
        let head = self.head.take();
        self.end_label();
        if self.bytes.len() + name.compose_len() > 254 {
            self.head = head;
            return Err(PushNameError)
        }
        self.ensure_capacity(name.compose_len());
        name.compose(&mut self.bytes);
        Ok(())
    }

    /// Finishes building the name and returns the resulting domain name.
    /// 
    /// If there currently is a label being built, ends the label first
    /// before returning the name. I.e., you don’t have to call [`end_label`]
    /// explicitely.
    ///
    /// [`end_label`]: #method.end_label
    pub fn finish(mut self) -> RelativeDname {
        self.end_label();
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes.freeze()) }
    }

    /// Appends the root label to the name and returns it as a `Dname`.
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the empty root label and transforms the name into a
    /// `Dname`. As adding the root label may push the name over the size
    /// limit, this may return an error.
    //
    // XXX I don’t think adding the root label will actually ever push the
    //     builder over the limit. Double check and if true, change the return
    //     type.
    pub fn into_dname(mut self) -> Result<Dname, PushNameError> {
        self.end_label();
        if self.bytes.len() >= 255 {
            Err(PushNameError)
        }
        else {
            self.ensure_capacity(1);
            self.bytes.put_u8(0);
            Ok(unsafe { Dname::from_bytes_unchecked(self.bytes.freeze()) })
        }
    }

    /// Appends an origin and returns the resulting `Dname`.
    /// If there currently is a label under construction, ends the label.
    /// Then adds the `origin` and transforms the name into a
    /// `Dname`. 
    //
    //  XXX NEEDS TESTS
    pub fn append_origin<N: ToDname>(mut self, origin: &N)
                                     -> Result<Dname, PushNameError> {
        self.end_label();
        if self.bytes.len() + origin.compose_len() > 255 {
            return Err(PushNameError)
        }
        self.ensure_capacity(origin.compose_len());
        origin.compose(&mut self.bytes);
        Ok(unsafe { Dname::from_bytes_unchecked(self.bytes.freeze()) })
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    #[fail(display="long label")]
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    #[fail(display="long domain name")]
    LongName,
}


//------------ PushNameError -------------------------------------------------

/// An error happened while trying to push a name to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="long domain name")]
pub struct PushNameError;


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn build() {
        let mut builder = DnameBuilder::with_capacity(255);
        builder.push(b'w').unwrap();
        builder.append(b"ww").unwrap();
        builder.end_label();
        builder.append(b"exa").unwrap();
        builder.push(b'm').unwrap();
        builder.push(b'p').unwrap();
        builder.append(b"le").unwrap();
        builder.end_label();
        builder.append(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_by_label() {
        let mut builder = DnameBuilder::with_capacity(255);
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_label(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_mixed() {
        let mut builder = DnameBuilder::with_capacity(255);
        builder.push(b'w').unwrap();
        builder.append(b"ww").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn buf_growth() {
        let mut builder = DnameBuilder::new();
        builder.append_label(b"1234567890").unwrap();
        builder.append_label(b"1234567890").unwrap();
        builder.append_label(b"1234567890").unwrap();
        builder.append_label(b"1234567890").unwrap();
        assert!(builder.capacity() >= 255 && builder.capacity() < 1024);
        assert_eq!(
            builder.finish().as_slice(),
            &b"\x0a1234567890\x0a1234567890\x0a1234567890\x0a1234567890"[..]
        );
    }

    #[test]
    fn name_limit() {
        let mut builder = DnameBuilder::new();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total 
            builder.append_label(b"123456789").unwrap();
        }

        assert_eq!(builder.append_label(b"12345"), Err(PushError::LongName));
        assert_eq!(builder.clone().append_label(b"1234"), Ok(()));

        assert_eq!(builder.append(b"12345"), Err(PushError::LongName));
        assert_eq!(builder.clone().append(b"1234"), Ok(()));

        assert_eq!(builder.append(b"12"), Ok(()));
        assert_eq!(builder.push(b'3'), Ok(()));
        assert_eq!(builder.push(b'4'), Err(PushError::LongName))
    }

    #[test]
    fn label_limit() {
        let mut builder = DnameBuilder::new();
        builder.append_label(&[0u8; 63][..]).unwrap();
        assert_eq!(builder.append_label(&[0u8; 64][..]),
                   Err(PushError::LongLabel));
        assert_eq!(builder.append_label(&[0u8; 164][..]),
                   Err(PushError::LongLabel));

        builder.append(&[0u8; 60][..]).unwrap();
        let _ = builder.clone().append_label(b"123").unwrap();
        assert_eq!(builder.append(b"1234"), Err(PushError::LongLabel));
        builder.append(b"12").unwrap();
        builder.push(b'3').unwrap();
        assert_eq!(builder.push(b'4'), Err(PushError::LongLabel));
    }

    #[test]
    fn finish() {
        let mut builder = DnameBuilder::new();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn into_dname() {
        let mut builder = DnameBuilder::new();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append(b"com").unwrap();
        assert_eq!(builder.into_dname().unwrap().as_slice(),
                   b"\x03www\x07example\x03com\x00");
    }

    #[test]
    fn into_dname_limit() {
        let mut builder = DnameBuilder::new();
        for _ in 0..51 {
            builder.append_label(b"1234").unwrap();
        }
        assert_eq!(builder.len(), 255);
        assert_eq!(builder.into_dname(), Err(PushNameError));
    }
}

