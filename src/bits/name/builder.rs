//! Building an owned domain name,

use super::{DNameBuf, DNameSlice, FromStrError};
use super::plain::buf_from_vec_unsafe;

//------------ DNameBuilder --------------------------------------------------

/// Builds an owned domain step by step from bytes.
///
/// This type allows to build a `DNameBuf` slowly by feeding bytes. It is
/// used by the master format scanner.
#[derive(Clone, Debug)]
pub struct DNameBuilder<'a>(DNameBuildInto<'a, Vec<u8>>);

impl<'a> DNameBuilder<'a> {
    /// Create a new domain name builder.
    ///
    /// If `origin` is given, it will be appened to the resulting domain
    /// name if it is relative.
    pub fn new(origin: Option<&'a DNameSlice>) -> Self {
        DNameBuilder(DNameBuildInto::new(Vec::new(), origin))
    }

    /// Pushes an octet to the end of the builder.
    pub fn push(&mut self, b: u8) -> Result<(), FromStrError> {
        self.0.push(b)
    }

    /// Pushes a label end to the builder.
    pub fn end_label(&mut self) {
        self.0.end_label()
    }

    /// Extracts the finished domain name from the builder.
    pub fn done(self) -> Result<DNameBuf, FromStrError> {
        let res = try!(self.0.done());
        Ok(unsafe { buf_from_vec_unsafe(res) })
    }
}


//------------ DNameBuildInto ------------------------------------------------

/// A type for iteratively pushing a domain name into a bytes vec.
#[derive(Clone, Debug)]
pub struct DNameBuildInto<'a, V: AsMut<Vec<u8>>> {
    target: V,

    /// The position in `buf` where we start.
    start: usize,

    /// The position of the last label head.
    head: usize,

    /// The origin to append to the name if it is relative.
    origin: Option<&'a DNameSlice>,

    /// The name is absolute and we are done.
    absolute: bool,
}

impl<'a, V: AsMut<Vec<u8>>> DNameBuildInto<'a, V> {
    /// Creates a new domain name builder.
    ///
    /// The domain name will be appended to the end of `target`.
    ///
    /// If `origin` is given, it will be appened to the resulting domain
    /// name if it is relative.
    pub fn new(mut target: V, origin: Option<&'a DNameSlice>)
               -> Self {
        let len = target.as_mut().len();
        let mut res = DNameBuildInto { target: target, start: len, head: len,
                                  origin: origin, absolute: false };
        res.target.as_mut().push(0);
        res
    }

    /// Appends an octet to the end of the domain name.
    pub fn push(&mut self, b: u8) -> Result<(), FromStrError> {
        if self.absolute {
            Err(FromStrError::EmptyLabel)
        }
        else if self.target.as_mut().len() - self.head == 63 {
                Err(FromStrError::LongLabel)
            }
        else if self.target.as_mut().len() - self.start == 254 {
            Err(FromStrError::LongName)
        }
        else {
            self.target.as_mut().push(b);
            Ok(())
        }
    }

    /// Ends a label.
    pub fn end_label(&mut self) {
        if !self.absolute {
            if self.target.as_mut().len() == self.head + 1 {
                // Empty label is root label. We are done here.
                self.absolute = true
            }
            else {
                self.target.as_mut()[self.head]
                        = (self.target.as_mut().len() - self.head - 1) as u8;
                self.head = self.target.as_mut().len();
                self.target.as_mut().push(0);
            }
        }
    }

    /// Finishes building the name and extracts the target.
    pub fn done(mut self) -> Result<V, FromStrError> {
        if !self.absolute && self.target.as_mut().len() > self.head + 1 {
            self.target.as_mut()[self.head]
                    = (self.target.as_mut().len() - self.head - 1) as u8;
            if let Some(origin) = self.origin {
                self.target.as_mut().extend(origin.as_bytes());
                if self.target.as_mut().len() - self.start > 255 {
                    return Err(FromStrError::LongName)
                }
            }
            else {
                return Err(FromStrError::RelativeName)
            }
        }
        Ok(self.target)
    }
}

