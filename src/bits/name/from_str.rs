//! Creating domain names from strings.
//!
//! This module is used by `DNameBuf`’s `FromStr` implementation.
//!
//! # Todo
//!
//! This should probably be merge with or into ::master’s domain name
//! parsing.

use std::str::Chars;
use super::FromStrError;


/// Returns owned bytes of the domain name resulting from a string.
pub fn from_str(s: &str) -> Result<Vec<u8>, FromStrError> {
    let mut target = Vec::new();
    let mut chars = s.chars();
    while try!(label(&mut chars, &mut target)) { }
    Ok(target)
}


/// Takes a label from the beginning of `chars` and appends it to `target`.
///
/// Returns `Ok(true)` if there are more labels or `Ok(false)` if that’s it.
fn label(chars: &mut Chars, target: &mut Vec<u8>)
             -> Result<bool, FromStrError> {
    if chars.as_str().is_empty() {
        // We are done. If there is something in target already, the last
        // char was a dot and we need to add the root label.
        if !target.is_empty() {
            target.push(0)
        }
        Ok(false)
    }
    else if chars.as_str().starts_with('.') {
        Err(FromStrError::EmptyLabel)
    }
    else if chars.as_str().starts_with("\\[") {
        binary_label(chars, target)
    }
    else {
        normal_label(chars, target)
    }
}

/// Takes a normal label from `chars` and appends it to `target`.
///
/// Returns `Ok(true)` if there are more labels or `Ok(false)` if that’s it.
fn normal_label(chars: &mut Chars, target: &mut Vec<u8>)
                -> Result<bool, FromStrError> {
    let start = target.len();
    target.push(0);
    while let Some(ch) = chars.next() {
        match ch {
            '.' => {
                let len = target.len() - start - 1;
                if len > 63 {
                    return Err(FromStrError::LongLabel)
                }
                target[start] = len as u8;
                return Ok(true)
            }
            '\\' => {
                target.push(try!(parse_escape(chars)))
            }
            ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                target.push(ch as u8);
            }
            _ => return Err(FromStrError::IllegalCharacter)
        }
    }
    let len = target.len() - start - 1;
    if len > 63 {
        return Err(FromStrError::LongLabel)
    }
    target[start] = len as u8;
    Ok(false)
}


/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
fn parse_escape(chars: &mut Chars) -> Result<u8, FromStrError> {
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
    else { Ok(ch as u8) }
}


/// Takes a normal label from `chars` and appends it to `target`.
///
/// Returns `Ok(true)` if there are more labels or `Ok(false)` if that’s it.
fn binary_label(chars: &mut Chars, target: &mut Vec<u8>)
                -> Result<bool, FromStrError> {
    chars.next(); chars.next(); // Skip "\\[".
    match chars.as_str().chars().next() {
        Some('o') | Some('O') => oct_binary_label(chars, target),
        Some('x') | Some('X') => hex_binary_label(chars, target),
        Some('b') | Some('B') => bin_binary_label(chars, target),
        Some('0' ... '9') => quad_binary_label(chars, target),
        _ => Err(FromStrError::IllegalBinary),
    }
}


/// Takes a binary label that is given in octal representation.
///
/// Such a label is starting with an `'o'` that is followed by up to 86
/// octal digits and an options decimal bit count separated by a slash.
fn oct_binary_label(chars: &mut Chars, target: &mut Vec<u8>)
                    -> Result<bool, FromStrError> {
    chars.next(); // Skip 'o'
    let mut digits = [0; 86];
    let (len, last) = try!(bit_digits(chars, &mut digits, 8));
    let mut count = if last == '/' { try!(binary_length(chars, 256)) }
                    else { len * 3 };
    if (count - 1) / 3 != len - 1 {
        return Err(FromStrError::IllegalBinary)
    }
    let bitslen = (count - 1) / 8 + 1;
    if count == 256 { count = 0 }
    target.push(0x41);
    target.push(count as u8);
    let oldlen = target.len();
    target.resize(oldlen + bitslen, 0);
    let bits = &mut target[oldlen..];
    for (i, ch) in digits.iter().enumerate() {
        if ch & 4 == 4 { try!(set_bit(bits, i * 3)) }
        if ch & 2 == 2 { try!(set_bit(bits, i * 3 + 1)) }
        if ch & 1 == 1 { try!(set_bit(bits, i * 3 + 2)) }
    }
    get_dot(chars)
}


/// Takes a binary label that is given in hex representation.
///
/// Such a label is starting with an `'x'` that is followed by up to 64
/// octal digits and an options decimal bit count separated by a slash.
fn hex_binary_label(chars: &mut Chars, target: &mut Vec<u8>)
                    -> Result<bool, FromStrError> {
    chars.next(); // Skip 'x'
    let mut digits = [0; 64];
    let (len, last) = try!(bit_digits(chars, &mut digits, 16));
    let mut count = if last == '/' { try!(binary_length(chars, 256)) }
                    else { len * 2 };
    if (count - 1) / 4 != len - 1 {
        return Err(FromStrError::IllegalBinary)
    }
    if count == 256 { count = 0 }
    target.push(0x41);
    target.push(count as u8);
    for chunk in digits[..len].chunks(2) {
        if chunk.len() == 2 {
            target.push(chunk[0] << 4 | chunk[1])
        }
        else {
            target.push(chunk[0] << 4)
        }
    }
    get_dot(chars)
}


/// Takes a binary label that is given in hex representation.
///
/// Such a label is starting with a `'b'` that is followed by up to 256
/// binary digits.
fn bin_binary_label(chars: &mut Chars, target: &mut Vec<u8>)
                    -> Result<bool, FromStrError> {
    chars.next(); // Skip 'b'
    let mut digits = [0; 256];
    let (len, last) = try!(bit_digits(chars, &mut digits, 2));
    let mut count = len;
    if last == '/' {
        return Err(FromStrError::IllegalBinary)
    }
    if count == 256 { count = 0 }
    target.push(0x41);
    target.push(count as u8);
    for chunk in digits[..len].chunks(8) {
        let mut byte = 0;
        for (i, ch) in chunk.iter().enumerate() {
            if *ch != 0 {
                byte |= 1 << (7 - i)
            }
        }
        target.push(byte)
    }
    get_dot(chars)
}

/// Takes the actual digits of a binary label.
///
/// The digits are taken from the beginning of `chars` and copied as their
/// byte value into `target` (ie., `'4'` becomes `4u8`). Up to the length
/// of `target` digits are take. They must be of the given `radix`.
///
/// The sequence ends successfully when either a `'/'` or a `']'` is
/// encountered. It ends in failure if any other non-digit is encountered
/// or there are too many digits.
///
/// The function returns the number of digits read and the delimiter.
fn bit_digits(chars: &mut Chars, target: &mut [u8], radix: u32)
              -> Result<(usize, char), FromStrError> {
    for (i, t) in target.iter_mut().enumerate() {
        match chars.next() {
            Some(ch) if ch.is_digit(radix) => {
                *t = ch.to_digit(radix).unwrap() as u8
            }
            Some(ch) if (ch == '/' || ch == ']') => {
                return Ok((i, ch))
            }
            Some(_) => return Err(FromStrError::IllegalBinary),
            None => return Err(FromStrError::UnexpectedEnd)
        }
    }
    match chars.next() {
        Some(ch) if (ch == '/' || ch == ']') => {
            Ok((target.len(), ch))
        }
        _ => Err(FromStrError::LongLabel)
    }
}


/// Sets the `count`th bit to `true`.
fn set_bit(bits: &mut [u8], count: usize) -> Result<(), FromStrError> {
    bits[count >> 3] |= 0x80 >> (count & 7);
    Ok(())
}


/// Takes a binary label that is given in IPv4 address representation.
///
/// This representation consists of four bytes in decimal representation
/// separated by a dot and optionally follwed by a slash and the decimal
/// number of bits.
fn quad_binary_label(chars: &mut Chars, target: &mut Vec<u8>)
                     -> Result<bool, FromStrError> {
    let mut bits = [0; 4];
    bits[0] = try!(dec_number(chars, true)).0;
    bits[1] = try!(dec_number(chars, true)).0;
    bits[2] = try!(dec_number(chars, true)).0;
    let (value, last) = try!(dec_number(chars, false));
    bits[3] = value;
    let count = if last == '/' { try!(binary_length(chars, 32)) }
                else { 32 };
    let bitslen = (count - 1) / 8 + 1;
    target.push(0x41);
    target.push(count as u8);
    target.extend_from_slice(&bits[..bitslen]);
    get_dot(chars)
}


/// Takes a decimal byte value.
///
/// Returns the value and the delimiter. If `more` is `true`, the delimiter
/// is always `'.'`, otherwise it can be `'/'` or `']'`.
fn dec_number(chars: &mut Chars, more: bool)
              -> Result<(u8, char), FromStrError> {
    let mut res = match chars.next() {
        Some(ch) if ch.is_digit(10) => ch.to_digit(10).unwrap(),
        Some(_) => return Err(FromStrError::IllegalBinary),
        None => return Err(FromStrError::UnexpectedEnd)
    };
    for _ in 0 .. 2 {
        match chars.next() {
            Some(ch) if ch.is_digit(10) => {
                res = res * 10 + ch.to_digit(10).unwrap()
            }
            Some('.') if more => return Ok((res as u8, '.')),
            Some(ch) if (ch == '/' || ch == ']') && !more => {
                return Ok((res as u8, ch))
            }
            Some(_) => return Err(FromStrError::IllegalBinary),
            None => return Err(FromStrError::UnexpectedEnd)
        }
    }
    let ch = match chars.next() {
        Some('.') if more => '.', 
        Some(ch) if (ch == '/' || ch == ']') && !more => ch,
        Some(_) => return Err(FromStrError::IllegalBinary),
        None => return Err(FromStrError::UnexpectedEnd)
    };
    if res > 255 { return Err(FromStrError::IllegalBinary) }
    Ok((res as u8, ch))
}


/// Reads the bit length.
///
/// This must be a slash followed by a decimal number between 1 and `max`.
fn binary_length(chars: &mut Chars, max: usize)
                 -> Result<usize, FromStrError> {
    // Let’s be generous and allow leading zeros
    let mut res = 0;
    loop {
        match chars.next() {
            Some('0') if res == 0 => { }
            Some(ch) if ch.is_digit(10) => {
                res = res * 10 + (ch.to_digit(10).unwrap() as usize);
                if res > max {
                    return Err(FromStrError::IllegalBinary)
                }
            }
            Some(']') => {
                return Ok(res)
            }
            Some(_) => return Err(FromStrError::IllegalBinary),
            None => return Err(FromStrError::UnexpectedEnd)
        }
    }
}


/// Takes a dot.
///
/// Returns `Ok(true)` if the next character in `chars` is a `'.'`,
/// `Ok(None)` if chars is empty, or an error otherwise.
fn get_dot(chars: &mut Chars) -> Result<bool, FromStrError> {
    match chars.next() {
        Some('.') => Ok(true),
        Some(_) => Err(FromStrError::IllegalBinary),
        None => Ok(false)
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
