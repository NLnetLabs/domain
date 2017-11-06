//! Creating domain names from strings.
//!
//! # Todo
//!
//! This should probably be merge with or into `::master`’s domain name
//! parsing.

use super::builder::DnameBuilder;
use super::error::FromStrError;
use super::relative::RelativeDname;


pub fn from_str(s: &str) -> Result<RelativeDname, FromStrError> {
    _from_chars(s.chars(), DnameBuilder::with_capacity(s.len()))
}

pub fn from_chars<C>(chars: C) -> Result<RelativeDname, FromStrError>
                  where C: IntoIterator<Item=char> {
    _from_chars(chars.into_iter(), DnameBuilder::new())
}


fn _from_chars<C>(mut chars: C, mut target: DnameBuilder)
                  -> Result<RelativeDname, FromStrError>
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
        //Ok(target.into_fqdn()?.into_dname())
        unimplemented!()
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

