//! Decoding and encoding of Base32.

use core::fmt;
#[cfg(feature="bytes")] use bytes::{BufMut, Bytes, BytesMut};
#[cfg(feature="bytes")] use super::base64::DecodeError;


//------------ Convenience Functions -----------------------------------------

#[cfg(feature="bytes")]
pub fn decode_hex(s: &str) -> Result<Bytes, DecodeError> {
    let mut decoder = Decoder::new_hex();
    for ch in s.chars() {
        decoder.push(ch)?;
    }
    decoder.finalize()
}


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

/// A base32 decoder.
///
/// This doesn’t do padding.
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
    pub fn new_hex() -> Self {
        Decoder {
            alphabet: &DECODE_HEX_ALPHABET,
            buf: [0; 8],
            next: 0,
            target: Ok(BytesMut::new())
        }
    }

    pub fn finalize(mut self) -> Result<Bytes, DecodeError> {
        if let Err(err) = self.target {
            return Err(err)
        }

        match self.next {
            0 => { }
            1 | 3 | 6 => return Err(DecodeError::IncompleteInput),
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
}

#[cfg(feature="bytes")]
impl Decoder {
    fn octet_0(&mut self) {
        let ch = self.buf[0] << 3 | self.buf[1] >> 2;
        self.append(ch)
    }

    fn octet_1(&mut self) {
        let ch = self.buf[1] << 6 | self.buf[2] << 1 | self.buf[3] >> 4;
        self.append(ch)
    }

    fn octet_2(&mut self) {
        let ch = self.buf[3] << 4 | self.buf[4] >> 1;
        self.append(ch)
    }

    fn octet_3(&mut self) {
        let ch = self.buf[4] << 7 | self.buf[5] << 2 | self.buf[6] >> 3;
        self.append(ch)
    }

    fn octet_4(&mut self) {
        let ch = self.buf[6] << 5 | self.buf[7];
        self.append(ch)
    }

    fn append(&mut self, value: u8) {
        self.target.as_mut().unwrap().put_u8(value);
    }

    fn reserve(&mut self, len: usize) {
        let target = self.target.as_mut().unwrap();
        if target.remaining_mut() < len {
            target.reserve(len)
        }
    }
}


//------------ Constants -----------------------------------------------------

/// The alphabet used for decoding “base32hex.”
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


const ENCODE_HEX_ALPHABET: [char; 32] = [
    '0', '1', '2', '3',   '4', '5', '6', '7',   // 0x00 .. 0x07
    '8', '9', 'A', 'B',   'C', 'D', 'E', 'F',   // 0x08 .. 0x0F

    'G', 'H', 'I', 'J',   'K', 'L', 'M', 'N',   // 0x10 .. 0x17
    'O', 'P', 'Q', 'R',   'S', 'T', 'U', 'V',   // 0x18 .. 0x1F
];


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;

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

