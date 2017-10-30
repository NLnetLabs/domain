//! Creating domain names from strings.
//!
//! This module is used by `DNameBuf`’s `FromStr` implementation.
//!
//! # Todo
//!
//! This should probably be merge with or into ::master’s domain name
//! parsing.

use std::{error, fmt};
use super::builder::{DnameBuilder, PushError};
use super::dname::Dname;


//------------ Building Functions --------------------------------------------


pub fn from_str(s: &str) -> Result<Dname, FromStrError> {
    _from_chars(s.chars(), DnameBuilder::with_capacity(s.len()))
}

pub fn from_chars<C>(chars: C) -> Result<Dname, FromStrError>
                  where C: IntoIterator<Item=char> {
    _from_chars(chars.into_iter(), DnameBuilder::new())
}


fn _from_chars<C>(mut chars: C, mut target: DnameBuilder)
                  -> Result<Dname, FromStrError>
               where C: Iterator<Item=char> {
    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                if !target.in_label() {
                    return Err(FromStrError::EmptyLabel)
                }
                target.end_label();
            }
            '\\' => {
                let in_label = target.in_label();
                target.push(parse_escape(&mut chars, in_label)?)?;
            }
            ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                target.push(ch as u8)?
            }
            _ => return Err(FromStrError::IllegalCharacter)
        }
    }
    if target.in_label() || target.is_empty() {
        Ok(target.finish())
    }
    else {
        Ok(target.into_fqdn()?.into_dname())
    }
}

/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
fn parse_escape<C>(chars: &mut C, in_label: bool) -> Result<u8, FromStrError>
                where C: Iterator<Item=char> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch == '0' || ch == '1' || ch == '2' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        Ok(v as u8)
    }
    else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        }
        else {
            Err(FromStrError::BinaryLabel)
        }
    }
    else { Ok(ch as u8) }
}


//------------ FromStrError --------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// An empty label was encountered.
    EmptyLabel,

    /// A binary label was encountered.
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter,

    /// An illegal binary label sequence was encountered.
    IllegalBinary,

    /// A relative name was encountered.
    RelativeName,

    /// The name has more than 255 characters.
    LongName,
}

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => FromStrError::LongLabel,
            PushError::LongName => FromStrError::LongName,
        }
    }
}

impl error::Error for FromStrError {
    fn description(&self) -> &str {
        use self::FromStrError::*;

        match *self {
            UnexpectedEnd => "unexpected end of input",
            EmptyLabel => "an empty label was encountered",
            BinaryLabel => "a binary label was encountered",
            LongLabel => "domain name label with more than 63 octets",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
            IllegalBinary => "illegal binary label",
            RelativeName => "relative name",
            LongName => "domain name with more than 255 octets",
        }
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn single_binary() {
        assert_eq!(from_str("\\[b11010000011101]").unwrap(),
                   b"\x41\x0e\xd0\x74");
        assert_eq!(from_str("\\[o64072/14]").unwrap(),
                   b"\x41\x0e\xd0\x74");
        assert_eq!(from_str("\\[xd074/14]").unwrap(),
                   b"\x41\x0e\xd0\x74");
        assert_eq!(from_str("\\[208.116.0.0/14]").unwrap(),
                   b"\x41\x0e\xd0\x74");
    }

    #[test]
    fn two_binary() {
        assert_eq!(from_str("\\[b11101].\\[o640]").unwrap(),
                   b"\x41\x05\xe8\x41\x09\xd0\x00");
    }
}
