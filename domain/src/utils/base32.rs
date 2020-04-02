//! Decoding and encoding of base 32.
//!
//! The base 32 encoding is defined in [RFC 4648]. It is essentially a
//! case-insensitive version of [base64] which is necessary when encoding
//! binary data in domain names. The RFC defines two separate encodings,
//! called *base32* and *base32hex*. The DNS uses the latter version,
//! particularly in [NSEC3], for encoding binary data in domain names, as it
//! has the property that the encoding maintains the order of the original
//! data.
//!
//! This module currently only implements *base32hex* but is prepared for
//! adding the other option by using the prefix `_hex` wherever distinction
//! is necessary.
//!
//! The module defines the type [`Decoder`] which keeps the state necessary
//! for decoding. The convenince functions `decode_hex` and `display_hex`
//! decode and encode octets using the *base32hex* encoding, respectively.
//!
//! Decoding currently requires the `bytes` feature as it is intended for
//! use by the master file parser. This will change when the parser will be
//! converted to work with any octets builder.
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648
//! [NSEC3]: ../../rdata/rfc5155/index.html
//! [`Decoder`]: struct.Decoder.html
//! [`decode_hex`]: fn.decode_hex.html
//! [`display_hex`]: fn.display_hex.html

use core::fmt;
#[cfg(feature="bytes")] use bytes::{BufMut, Bytes, BytesMut};
#[cfg(feature="bytes")] use super::base64::DecodeError;


//------------ Convenience Functions -----------------------------------------

/// Decodes a string with *base32hex* encoded data.
///
/// The function attempts to decode the entire string and returns the result
/// as a `Bytes` value.
#[cfg(feature="bytes")]
pub fn decode_hex(s: &str) -> Result<Bytes, DecodeError> {
    let mut decoder = Decoder::new_hex();
    for ch in s.chars() {
        decoder.push(ch)?;
    }
    decoder.finalize()
}


/// Encodes binary data in *base32hex* and writes it into a format stream.
///
/// This function is intended to be used in implementations of formatting
/// traits:
///
/// ```
/// use core::fmt;
/// use domain::utils::base32;
/// 
/// struct Foo<'a>(&'a [u8]);
///
/// impl<'a> fmt::Display for Foo<'a> {
///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
///         base32::display_hex(&self.0, f)
///     }
/// }
/// ```
pub fn display_hex<B, W>(bytes: &B, f: &mut W) -> fmt::Result
where B: AsRef<[u8]> + ?Sized, W: fmt::Write {
    fn ch(i: u8) -> char {
        ENCODE_HEX_ALPHABET[i as usize]
    }

    for chunk in bytes.as_ref().chunks(5) {
        f.write_char(ch(chunk[0] >> 3))?; // 0
        if chunk.len() == 1 {
            f.write_char(ch((chunk[0] & 0x07) << 2))?; // 1
            break;
        }
        f.write_char(ch((chunk[0] & 0x07) << 2 | chunk[1] >> 6))?; // 1
        f.write_char(ch((chunk[1] & 0x3F) >> 1))?; // 2
        if chunk.len() == 2 {
            f.write_char(ch((chunk[1] & 0x01) << 4))?; // 3
            break;
        }
        f.write_char(ch((chunk[1] & 0x01) << 4 | chunk[2] >> 4))?; // 3
        if chunk.len() == 3 {
            f.write_char(ch((chunk[2] & 0x0F) << 1))?; // 4
            break;
        }
        f.write_char(ch((chunk[2] & 0x0F) << 1 | chunk[3] >> 7))?; // 4
        f.write_char(ch((chunk[3] & 0x7F) >> 2))?; // 5
        if chunk.len() == 4 {
            f.write_char(ch((chunk[3] & 0x03) << 3))?; // 6
            break;
        }
        f.write_char(ch((chunk[3] & 0x03) << 3 | chunk[4] >> 5))?; // 6
        f.write_char(ch(chunk[4] & 0x1F))?; // 7
    }
    Ok(())
}


//------------ Decoder -------------------------------------------------------

/// A base 32 decoder.
///
/// This type keeps all the state for decoding a sequence of characters
/// representing data encoded in base 32. Upon success, the decoder returns
/// the decoded data in a `bytes::Bytes` value.
///
/// # Limitations
///
/// The decoder does not support padding.
#[cfg(feature="bytes")]
pub struct Decoder {
    /// The alphabet we are using.
    alphabet: &'static [u8; 128],

    /// A buffer for up to four characters.
    ///
    /// We only keep `u8`s here because only ASCII characters are used by
    /// Base64.
    buf: [u8; 8],

    /// The index in `buf` where we place the next character.
    next: usize,

    /// The target or an error if something went wrong.
    target: Result<BytesMut, DecodeError>,
}

#[cfg(feature="bytes")]
impl Decoder {
    /// Creates a new, empty decoder using the *base32hex* variant.
    pub fn new_hex() -> Self {
        Decoder {
            alphabet: &DECODE_HEX_ALPHABET,
            buf: [0; 8],
            next: 0,
            target: Ok(BytesMut::new())
        }
    }

    /// Finalizes decoding and returns the decoded data.
    pub fn finalize(mut self) -> Result<Bytes, DecodeError> {
        if let Err(err) = self.target {
            return Err(err)
        }

        match self.next {
            0 => { }
            1 | 3 | 6 => return Err(DecodeError::ShortInput),
            2 => {
                self.reserve(1);
                self.octet_0();
            }
            4 => {
                self.reserve(2);
                self.octet_0();
                self.octet_1();
            }
            5 => {
                self.reserve(3);
                self.octet_0();
                self.octet_1();
                self.octet_2();
            }
            7 => {
                self.reserve(4);
                self.octet_0();
                self.octet_1();
                self.octet_2();
                self.octet_3();
            }
            _ => unreachable!()
        }
        self.target.map(BytesMut::freeze)
    }

    /// Decodes one more character of data.
    ///
    /// Returns an error as soon as the encoded data is determined to be
    /// illegal. It is okay to push more data after the first error. The
    /// method will just keep returned errors.
    pub fn push(&mut self, ch: char) -> Result<(), DecodeError> {
        if ch > (127 as char) {
            return Err(DecodeError::IllegalChar(ch))
        }
        let val = self.alphabet[ch as usize];
        if val == 0xFF {
            return Err(DecodeError::IllegalChar(ch))
        }
        self.buf[self.next] = val;
        self.next += 1;

        if self.next == 8 {
            self.reserve(5);
            self.octet_0();
            self.octet_1();
            self.octet_2();
            self.octet_3();
            self.octet_4();
            self.next = 0;
        }
        Ok(())
    }

    /// Decodes the zeroth octet in a base 32 sequence.
    fn octet_0(&mut self) {
        let ch = self.buf[0] << 3 | self.buf[1] >> 2;
        self.append(ch)
    }

    /// Decodes the first octet in a base 32 sequence.
    fn octet_1(&mut self) {
        let ch = self.buf[1] << 6 | self.buf[2] << 1 | self.buf[3] >> 4;
        self.append(ch)
    }

    /// Decodes the second octet in a base 32 sequence.
    fn octet_2(&mut self) {
        let ch = self.buf[3] << 4 | self.buf[4] >> 1;
        self.append(ch)
    }

    /// Decodes the third octet in a base 32 sequence.
    fn octet_3(&mut self) {
        let ch = self.buf[4] << 7 | self.buf[5] << 2 | self.buf[6] >> 3;
        self.append(ch)
    }

    /// Decodes the forth octet in a base 32 sequence.
    fn octet_4(&mut self) {
        let ch = self.buf[6] << 5 | self.buf[7];
        self.append(ch)
    }

    /// Appends a decoded octet to the target.
    fn append(&mut self, value: u8) {
        self.target.as_mut().unwrap().put_u8(value);
    }

    /// Reserves `len` octets of space in the target.
    fn reserve(&mut self, len: usize) {
        let target = self.target.as_mut().unwrap();
        if target.remaining_mut() < len {
            target.reserve(len)
        }
    }
}


//------------ Constants -----------------------------------------------------

/// The alphabet used for decoding *base32hex.*
///
/// This maps encoding characters into their values. A value of 0xFF stands in
/// for illegal characters. We only provide the first 128 characters since the
/// alphabet will only use ASCII characters.
#[cfg(feature="bytes")]
const DECODE_HEX_ALPHABET: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x00 .. 0x07
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x08 .. 0x0F

    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x10 .. 0x17
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x18 .. 0x1F

    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x20 .. 0x27
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x28 .. 0x2F

    0x00, 0x01, 0x02, 0x03,   0x04, 0x05, 0x06, 0x07,  // 0x30 .. 0x37
    0x08, 0x09, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x38 .. 0x3F

    0xFF, 0x0a, 0x0b, 0x0c, 0x0d,   0x0e, 0x0f, 0x10,  // 0x40 .. 0x47
    0x11, 0x12, 0x13, 0x14, 0x15,   0x16, 0x17, 0x18,  // 0x48 .. 0x4F

    0x19, 0x1a, 0x1b, 0x1c, 0x1d,   0x1e, 0x1f, 0xFF,  // 0x50 .. 0x57
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x58 .. 0x5F

    0xFF, 0x0a, 0x0b, 0x0c, 0x0d,   0x0e, 0x0f, 0x10,  // 0x60 .. 0x67
    0x11, 0x12, 0x13, 0x14, 0x15,   0x16, 0x17, 0x18,  // 0x68 .. 0x6F

    0x19, 0x1a, 0x1b, 0x1c, 0x1d,   0x1e, 0x1f, 0xFF,  // 0x70 .. 0x77
    0xFF, 0xFF, 0xFF, 0xFF,   0xFF, 0xFF, 0xFF, 0xFF,  // 0x78 .. 0x7F
];


/// The alphabet used for encoding *base32hex.*
const ENCODE_HEX_ALPHABET: [char; 32] = [
    '0', '1', '2', '3',   '4', '5', '6', '7',   // 0x00 .. 0x07
    '8', '9', 'A', 'B',   'C', 'D', 'E', 'F',   // 0x08 .. 0x0F

    'G', 'H', 'I', 'J',   'K', 'L', 'M', 'N',   // 0x10 .. 0x17
    'O', 'P', 'Q', 'R',   'S', 'T', 'U', 'V',   // 0x18 .. 0x1F
];


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use std::string::String;
    use super::*;

    #[cfg(feature = "bytes")]
    #[test]
    fn test_decode_hex() {
        assert_eq!(decode_hex("").unwrap().as_ref(), b"");
        assert_eq!(decode_hex("CO").unwrap().as_ref(), b"f");
        assert_eq!(decode_hex("CPNG").unwrap().as_ref(), b"fo");
        assert_eq!(decode_hex("CPNMU").unwrap().as_ref(), b"foo");
        assert_eq!(decode_hex("CPNMUOG").unwrap().as_ref(), b"foob");
        assert_eq!(decode_hex("CPNMUOJ1").unwrap().as_ref(), b"fooba");
        assert_eq!(decode_hex("CPNMUOJ1E8").unwrap().as_ref(), b"foobar");
        assert_eq!(decode_hex("co").unwrap().as_ref(), b"f");
        assert_eq!(decode_hex("cpng").unwrap().as_ref(), b"fo");
        assert_eq!(decode_hex("cpnmu").unwrap().as_ref(), b"foo");
        assert_eq!(decode_hex("cpnmuog").unwrap().as_ref(), b"foob");
        assert_eq!(decode_hex("cpnmuoj1").unwrap().as_ref(), b"fooba");
        assert_eq!(decode_hex("cpnmuoj1e8").unwrap().as_ref(), b"foobar");
    }

    #[test]
    fn test_display_hex() {
        fn fmt(s: &[u8]) -> String {
            let mut out = String::new();
            display_hex(s, &mut out).unwrap();
            out
        }

        assert_eq!(fmt(b""), "");
        assert_eq!(fmt(b"f"), "CO");
        assert_eq!(fmt(b"fo"), "CPNG");
        assert_eq!(fmt(b"foo"), "CPNMU");
        assert_eq!(fmt(b"foob"), "CPNMUOG");
        assert_eq!(fmt(b"fooba"), "CPNMUOJ1");
        assert_eq!(fmt(b"foobar"), "CPNMUOJ1E8");
    }
}

