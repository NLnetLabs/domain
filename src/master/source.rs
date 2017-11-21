//! Character sources.
//!
//! This is here so we can read from things that aren’t ASCII or UTF-8.

use std::io;
use std::ascii::AsciiExt;
use std::io::Read;
use std::fs::File;


//------------ CharSource ----------------------------------------------------

pub trait CharSource {
    type Err;

    fn next(&mut self) -> Result<Option<char>, Self::Err>;
}


//------------ str -----------------------------------------------------------

impl<'a> CharSource for &'a str {
    type Err = ();

    fn next(&mut self) -> Result<Option<char>, ()> {
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
    type Err = AsciiFileError;

    fn next(&mut self) -> Result<Option<char>, Self::Err> {
        let res = match self.file {
            Some(ref mut file) => {
                let mut buf = [0u8];
                match file.read(&mut buf) {
                    Ok(1) => {
                        if buf[0].is_ascii() {
                            return Ok(Some(buf[0] as char));
                        }
                        Err(AsciiFileError::CharRange(buf[0]))
                    }
                    Ok(0) => {
                        Ok(None)
                    }
                    Ok(_) => unreachable!(),
                    Err(err) => {
                        Err(AsciiFileError::Io(err))
                    }
                }
            }
            None => return Ok(None),
        };
        self.file = None;
        res
    }
}


//------------ AsciiFileError ------------------------------------------------

pub enum AsciiFileError {
    CharRange(u8),
    Io(io::Error),
}



