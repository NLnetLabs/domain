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

/// A file that contains only ASCII characters.
///
//  This isn’t built atop a BufReader because we can optimize for our
//  strategy of reading from the buffer byte by byte.
pub struct AsciiFile {
    file: File,
    buf: Option<(Box<[u8]>, usize, usize)>,
}

const CAP: usize = 8 * 1024;

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
                    io::ErrorKind::InvalidData, AsciiError(res).compat()
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
                            io::ErrorKind::InvalidData,
                            AsciiError(res).compat()
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
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="invalid ASCII character '{}'", _0)]
pub struct AsciiError(u8);

