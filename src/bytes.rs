//! Low-level access to wire format DNS.
//!

use std::error;
use std::fmt;
use std::mem;
use std::ptr;
use std::result;
use super::name::DomainName;


//------------ BytesBuf -----------------------------------------------------

/// A trait for writing binary DNS data.
///
pub trait BytesBuf {
    type Pos;

    //--- Appending basic types
    fn push_bytes(&mut self, data: &[u8]);

    fn push_u8(&mut self, data: u8) {
        let bytes: [u8; 1] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes);
    }

    fn push_u16(&mut self, data: u16) {
        let data = data.to_be();
        let bytes: [u8; 2] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes);
    }

    fn push_u32(&mut self, data: u32) {
        let data = data.to_be();
        let bytes: [u8; 4] = unsafe { mem::transmute(data) };
        self.push_bytes(&bytes);
    }

    //--- Updating of earlier data.
    fn pos(&self) -> Self::Pos;
    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8]);

    fn update_u8(&mut self, pos: Self::Pos, data: u8) {
        let bytes: [u8; 1] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes);
    }

    fn update_u16(&mut self, pos: Self::Pos, data: u16) {
        let data = data.to_be();
        let bytes: [u8; 2] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes);
    }

    fn update_u32(&mut self, pos: Self::Pos, data: u32) {
        let data = data.to_be();
        let bytes: [u8; 4] = unsafe { mem::transmute(data) };
        self.update_bytes(pos, &bytes);
    }

    //--- Name compression support
    //
    // This is disabled by default

    /// Returns whether `self` can compress names.
    fn can_compress(&self) -> bool { false }

    /// Adds a reference to a domain name at the current position.
    fn add_name_pos<N: AsRef<DomainName>>(&mut self, name: N) {
        let _ = name;
    }

    /// Retrieves the position for `name`, if available.
    fn get_name_pos<N: AsRef<DomainName>>(&self, name: N) -> Option<u16> {
        let _ = name; None
    }
}

impl BytesBuf for Vec<u8> {
    type Pos = usize;

    fn push_bytes(&mut self, data: &[u8]) {
        self.extend(data)
    }

    fn pos(&self) -> Self::Pos {
        self.len()
    }

    fn update_bytes(&mut self, pos: Self::Pos, data: &[u8]) {
        assert!(pos + data.len() < self.len());
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(),
                                     self[pos..pos + data.len()].as_mut_ptr(),
                                     data.len())
        }
    }
}


//------------ BytesSlice ---------------------------------------------------

/// A trait extending a bytes slice for reading of DNS data.
///
pub trait BytesSlice {
    fn split_u8(&self) -> Result<(u8, &Self)>;
    fn split_u16(&self) -> Result<(u16, &Self)>;
    fn split_u32(&self) -> Result<(u32, &Self)>;
    fn split_bytes(&self, at: usize) -> Result<(&[u8], &Self)>;
    fn tail(&self, start: usize) -> Result<&Self>;
    fn check_len(&self, len: usize) -> Result<()>;
}

impl BytesSlice for [u8] {
    fn split_u8(&self) -> Result<(u8, &[u8])> {
        self.split_first().map(|(l,r)| (*l, r)).ok_or(Error::PrematureEnd)
    }

    fn split_u16(&self) -> Result<(u16, &[u8])> {
        try!(self.check_len(2));
        let (l, r) = self.split_at(2);
        let l: &[u8; 2] = unsafe { mem::transmute(l.as_ptr()) };
        let l = unsafe { mem::transmute(*l) };
        Ok((l, r))
    }

    fn split_u32(&self) -> Result<(u32, &[u8])> {
        try!(self.check_len(4));
        if self.len() < 4 { return Err(Error::PrematureEnd) }
        let (l, r) = self.split_at(4);
        let l: &[u8; 4] = unsafe { mem::transmute(l.as_ptr()) };
        let l = unsafe { mem::transmute(*l) };
        Ok((l, r))
    }

    fn split_bytes(&self, at: usize) -> Result<(&[u8], &[u8])> {
        try!(self.check_len(at));
        Ok(self.split_at(at))
    }

    fn tail(&self, start: usize) -> Result<&[u8]> {
        try!(self.check_len(start));
        if self.len() < start { return Err(Error::PrematureEnd) }
        Ok(&self[start..])
    }

    fn check_len(&self, len: usize) -> Result<()> {
        if len > self.len() { Err(Error::PrematureEnd) }
        else { Ok(()) }
    }
}


//------------ Error and Result ---------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    PrematureEnd,
    SizeExceeded,
    Overflow,
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::PrematureEnd => "premature end of domain name",
            Error::SizeExceeded => "the message size has been exceeded",
            Error::Overflow => "a counter has overflowed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}

pub type Result<T> = result::Result<T, Error>;



