//! Character sources.
//!
//! This is here so we can read from things that aren’t ASCII or UTF-8.

use std::{char, error, io};
use std::io::Read;
use std::fs::File;
use std::path::Path;
use super::scan::CharSource;


//------------ str -----------------------------------------------------------

impl<'a> CharSource for &'a str {
    fn next(&mut self) -> Result<Option<char>, io::Error> {
        let res = match self.chars().next() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        *self = &self[res.len_utf8()..];
        Ok(Some(res))
    }
}


//------------ AsciiFile -----------------------------------------------------

/// A file that contains only ASCII characters.
///
//  This isn’t built atop a BufReader because we can optimize for our
//  strategy of reading from the buffer byte by byte.
pub struct AsciiFile {
    file: File,
    buf: Option<(Box<[u8]>, usize, usize)>,
}

impl AsciiFile {
    pub fn new(file: File) -> Self {
        AsciiFile {
            file,
            buf: unsafe {
                let mut buffer = Vec::with_capacity(CAP);
                buffer.set_len(CAP);
                Some((buffer.into_boxed_slice(), 0, 0))
            }
        }
    }

    /// Opens a file at the given path as an ASCII-only file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        File::open(path).map(Self::new)
    }
}

impl CharSource for AsciiFile {
    fn next(&mut self) -> Result<Option<char>, io::Error> {
        let err = if let Some((ref mut buf, ref mut len, ref mut pos))
                                = self.buf {
            if *pos < *len {
                let res = buf[*pos];
                if res.is_ascii() {
                    *pos += 1;
                    return Ok(Some(res as char))
                }
                Err(io::Error::new(
                    io::ErrorKind::InvalidData, AsciiError(res)
                ))
            }
            else {
                match self.file.read(buf) {
                    Ok(0) => Ok(None),
                    Ok(read_len) => {
                        *len = read_len;
                        let res = buf[0];
                        if res.is_ascii() {
                            *pos = 1;
                            return Ok(Some(res as char))
                        }
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData, AsciiError(res)
                        ))
                    }
                    Err(err) => Err(err)
                }
            }
        }
        else {
            return Ok(None);
        };
        self.buf = None;
        err
    }
}


//------------ AsciiError ----------------------------------------------------

/// An error happened while reading an ASCII-only file.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="invalid ASCII character '{}'", _0)]
pub struct AsciiError(u8);

impl error::Error for AsciiError { }


//------------ Utf8File ------------------------------------------------------

/// A file that contains UTF-8 encoded text.
pub struct Utf8File(OctetFile);

impl Utf8File {
    pub fn new(file: File) -> Self {
        Utf8File(OctetFile::new(file))
    }

    /// Opens a file at the given path as an ASCII-only file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        File::open(path).map(Self::new)
    }
}

impl CharSource for Utf8File {
    fn next(&mut self) -> Result<Option<char>, io::Error> {
        let first = match self.0.next()? {
            Some(ch) => ch,
            None => return Ok(None)
        };
        if first.is_ascii() { //first < 0x80  {
            return Ok(Some(first as char))
        }
        let second = match self.0.next()? {
            Some(ch) => ch,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "unexpected EOF"
                ))
            }
        };
        if first < 0xC0 || second < 0x80 {
            return Err(Utf8Error.into())
        }
        if first < 0xE0 {
            return Ok(Some(unsafe {
                char::from_u32_unchecked(
                    (u32::from(first & 0x1F)) << 6 |
                    u32::from(second & 0x3F)
                )
            }))
        }
        let third = match self.0.next()? {
            Some(ch) => ch,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "unexpected EOF"
                ))
            }
        };
        if third < 0x80 {
            return Err(Utf8Error.into())
        }
        if first < 0xF0 {
            return Ok(Some(unsafe {
                char::from_u32_unchecked(
                    (u32::from(first & 0x0F)) << 12 |
                    (u32::from(second & 0x3F)) << 6 |
                    u32::from(third & 0x3F)
                )
            }))
        }
        let fourth = match self.0.next()? {
            Some(ch) => ch,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof, "unexpected EOF"
                ))
            }
        };
        if first > 0xF7 || fourth < 0x80 {
            return Err(Utf8Error.into())
        }
        Ok(Some(unsafe {
            char::from_u32_unchecked(
                (u32::from(first & 0x07)) << 18 |
                (u32::from(second & 0x3F)) << 12 |
                (u32::from(third & 0x3F)) << 6 |
                u32::from(fourth & 0x3F)
            )
        }))
    }
}


//------------ Utf8Error -----------------------------------------------------

/// An error happened while reading an ASCII-only file.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="invalid UTF-8 sequence")]
pub struct Utf8Error;

impl error::Error for Utf8Error { }

impl From<Utf8Error> for io::Error {
    fn from(err: Utf8Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}


//------------ OctetFile -----------------------------------------------------

//  This isn’t built atop a BufReader because we can optimize for our
//  strategy of reading from the buffer byte by byte.
pub struct OctetFile {
    file: File,
    buf: Option<(Box<[u8]>, usize, usize)>,
}

const CAP: usize = 8 * 1024;

impl OctetFile {
    pub fn new(file: File) -> Self {
        OctetFile {
            file,
            buf: unsafe {
                let mut buffer = Vec::with_capacity(CAP);
                buffer.set_len(CAP);
                Some((buffer.into_boxed_slice(), 0, 0))
            }
        }
    }

    /// Opens a file at the given path as an ASCII-only file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        File::open(path).map(Self::new)
    }

    #[inline]
    fn next(&mut self) -> Result<Option<u8>, io::Error> {
        let err = if let Some((ref mut buf, ref mut len, ref mut pos))
                                = self.buf {
            if *pos < *len {
                let res = buf[*pos];
                *pos += 1;
                return Ok(Some(res))
            }
            else {
                match self.file.read(buf) {
                    Ok(0) => Ok(None),
                    Ok(read_len) => {
                        *len = read_len;
                        let res = buf[0];
                        if res.is_ascii() {
                            *pos = 1;
                            return Ok(Some(res))
                        }
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData, AsciiError(res)
                        ))
                    }
                    Err(err) => Err(err)
                }
            }
        }
        else {
            return Ok(None);
        };
        self.buf = None;
        err
    }
}
