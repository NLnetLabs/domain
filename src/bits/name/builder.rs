//! Building a domain name.

use std::{error, fmt};
use bytes::{BufMut, BytesMut};
use super::dname::Dname;
use super::relname::RelativeDname;


//------------ DnameBuilder --------------------------------------------------

/// Builds a domain name step by step from bytes.
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
    /// domain name. Since that may not ne the case, this function is
    /// unsafe.
    unsafe fn from_bytes(bytes: BytesMut) -> Self {
        DnameBuilder { bytes, head: None }
    }

    /// Creates a domain name builder with default capacity.
    ///
    /// The capacity will be just large enough that the underlying `BytesMut`
    /// value does not need to allocate.
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

    /// Returns whether the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns whether there currently is a label under construction.
    ///
    /// This returns `false` if the name is still empty or if the last thing
    /// that happend was a call to `end_label()`.
    pub fn in_label(&self) -> bool {
        self.head.is_some()
    }

    /// Pushes an byte to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing the byte
    /// would exceed the size limits for labels or domain names.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        if self.bytes.len() >= 255 {
            return Err(PushError::LongName);
        }
        if let Some(head) = self.head {
            if head == 63 {
                return Err(PushError::LongLabel)
            }
            self.ensure_capacity(1);
        }
        else {
            self.head = Some(self.bytes.len());
            self.ensure_capacity(2);
            self.bytes.put_u8(0)
        }
        self.bytes.put_u8(ch);
        Ok(())
    }

    /// Pushes a byte slice to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing the byte
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
            if self.bytes.len() + bytes.len() > 255 {
                return Err(PushError::LongName)
            }
        }
        self.ensure_capacity(bytes.len());
        self.bytes.put_slice(bytes);
        Ok(())
    }

    fn ensure_capacity(&mut self, additional: usize) {
        if self.bytes.remaining_mut() < additional {
            let additional = 255 - self.bytes.len();
            self.bytes.reserve(additional)
        }
    }

    /// Ends the current label.
    ///
    /// If there isn’t a current label, does nothing. Use `into_fqdn` to
    /// append the root label and finish building.
    pub fn end_label(&mut self) {
        if let Some(head) = self.head {
            let len = self.bytes.len() - head - 1;
            self.bytes[head] = len as u8;
            self.head = None;
        }
    }

    /// Appends a byte slice as a complete label.
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

    /// Finishes building the name and returns the resulting domain name.
    /// 
    /// If there currently is a label being built, ends the label first
    /// before returning the name. I.e., you don’t have to call `end_label`
    /// first.
    pub fn finish(mut self) -> RelativeDname {
        self.end_label();
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes.freeze()) }
    }

    /// Appends the root label to the name and returns it as a `Dname`.
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the empty root label and transforms the name into an
    /// `Dname`. As adding the root label may push the name over the size
    /// limit, this may return an error.
    ///
    /// Note: Technically, this can only ever exceed the name size limit,
    /// never the label size limit, so returning a `PushError` isn’t quite
    /// correct. However, I didn’t want to define a separate error type just
    /// for this case.
    pub fn into_dname(mut self) -> Result<Dname, PushError> {
        self.end_label();
        if self.bytes.len() >= 255 {
            Err(PushError::LongName)
        }
        else {
            self.ensure_capacity(1);
            self.bytes.put_u8(0);
            Ok(unsafe { Dname::from_bytes_unchecked(self.bytes.freeze()) })
        }
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    LongName,
}
 
impl error::Error for PushError {
    fn description(&self) -> &str {
        match *self {
            PushError::LongLabel => "label size exceeded",
            PushError::LongName => "name size exceeded",
        }
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

