//! Character sources.
//!
//! This is here so we can read from things that aren’t ASCII or UTF-8.

use std::io;
use std::io::Read;
use std::fs::File;
use std::path::Path;
use failure::Fail;
use super::scan::CharSource;


//------------ str -----------------------------------------------------------

impl<'a> CharSource for &'a str {
    fn next(&mut self) -> Result<Option<char>, io::Error> {
        let res = match self.chars().next() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        *self = &self[res.len_utf8()..];
        return Ok(Some(res))
    }
}


//------------ AsciiFile -----------------------------------------------------

/// A file that is assumed to only contain ASCII characters.
pub struct AsciiFile {
    file: Option<File>,
}

impl AsciiFile {
    /// Creates a new value from the given file.
    pub fn new(file: File) -> Self {
        AsciiFile {
            file: Some(file)
        }
    }

    /// Opens a file at the given path as an ASCII-only file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        File::open(path).map(Self::new)
    }
}


impl CharSource for AsciiFile {
    fn next(&mut self) -> Result<Option<char>, io::Error> {
        let res = match self.file {
            Some(ref mut file) => {
                let mut buf = [0u8];
                match file.read(&mut buf)? {
                    1 => {
                        if buf[0].is_ascii() {
                            return Ok(Some(buf[0] as char));
                        }
                        Err(io::Error::new(io::ErrorKind::InvalidData,
                                           AsciiError(buf[0]).compat()))
                    }
                    0 => {
                        Ok(None)
                    }
                    _ => unreachable!(),
                }
            }
            None => return Ok(None),
        };
        self.file = None;
        res
    }
}


//------------ AsciiError ----------------------------------------------------

/// An error happened while reading an ASCII-only file.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="invalid ASCII character '{}'", _0)]
pub struct AsciiError(u8);

