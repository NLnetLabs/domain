//! Character sources.
//!
//! This is here so we can read from things that aren’t ASCII or UTF-8.

use std::{error, fmt, io};
use std::ascii::AsciiExt;
use std::io::Read;
use std::fs::File;
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

pub struct AsciiFile {
    file: Option<File>,
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
                                           AsciiError(buf[0])))
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsciiError(u8);

impl error::Error for AsciiError {
    fn description(&self) -> &str {
        "invalid ASCII character"
    }
}

impl fmt::Display for AsciiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid ASCII character '{}'", self.0)
    }
}

