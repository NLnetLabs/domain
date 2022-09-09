//! Decoding and encoding of Base 64.
//!
//! The Base 64 encoding is defined in [RFC 4648]. There are two variants
//! defined in the RFC, dubbed *base64* and *base64url* which are
//! differenciated by the last two characters in the alphabet. The DNS uses
//! only the original *base64* variant, so this is what is implemented by the
//! module for now.
//!
//! The module defines the type [`Decoder`] which keeps the state necessary
//! for decoding. The various functions offered use such a decoder to decode
//! and encode octets in various forms.
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648

use crate::base::octets::{
    EmptyBuilder, FromBuilder, OctetsBuilder, ShortBuf,
};
use crate::base::scan::{ConvertSymbols, EntrySymbol, ScannerError};
use core::fmt;
#[cfg(feature = "std")]
use std::string::String;

//------------ Convenience Functions -----------------------------------------

/// Decodes a string with *base64* encoded data.
///
/// The function attempts to decode the entire string and returns the result
/// as a `Bytes` value.
pub fn decode<Octets>(s: &str) -> Result<Octets, DecodeError>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    let mut decoder = Decoder::<<Octets as FromBuilder>::Builder>::new();
    for ch in s.chars() {
        decoder.push(ch)?;
    }
    decoder.finalize()
}

/// Encodes binary data in *base64* and writes it into a format stream.
///
/// This function is intended to be used in implementations of formatting
/// traits:
///
/// ```
/// use core::fmt;
/// use domain::utils::base64;
///
/// struct Foo<'a>(&'a [u8]);
///
/// impl<'a> fmt::Display for Foo<'a> {
///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
///         base64::display(&self.0, f)
///     }
/// }
/// ```
pub fn display<B, W>(bytes: &B, f: &mut W) -> fmt::Result
where
    B: AsRef<[u8]> + ?Sized,
    W: fmt::Write,
{
    fn ch(i: u8) -> char {
        ENCODE_ALPHABET[i as usize]
    }

    for chunk in bytes.as_ref().chunks(3) {
        match chunk.len() {
            1 => {
                f.write_char(ch(chunk[0] >> 2))?;
                f.write_char(ch((chunk[0] & 0x03) << 4))?;
                f.write_char('=')?;
                f.write_char('=')?;
            }
            2 => {
                f.write_char(ch(chunk[0] >> 2))?;
                f.write_char(ch((chunk[0] & 0x03) << 4 | chunk[1] >> 4))?;
                f.write_char(ch((chunk[1] & 0x0F) << 2))?;
                f.write_char('=')?;
            }
            3 => {
                f.write_char(ch(chunk[0] >> 2))?;
                f.write_char(ch((chunk[0] & 0x03) << 4 | chunk[1] >> 4))?;
                f.write_char(ch((chunk[1] & 0x0F) << 2 | chunk[2] >> 6))?;
                f.write_char(ch(chunk[2] & 0x3F))?;
            }
            _ => unreachable!(),
        }
    }
    Ok(())
}

/// Encodes binary data in *base64* and returns the encoded data as a string.
#[cfg(feature = "std")]
pub fn encode_string<B: AsRef<[u8]> + ?Sized>(bytes: &B) -> String {
    let mut res = String::with_capacity((bytes.as_ref().len() / 3 + 1) * 4);
    display(bytes, &mut res).unwrap();
    res
}

/// Returns a placeholder value that implements `Display` for encoded data.
pub fn encode_display<Octets: AsRef<[u8]>>(
    octets: &Octets,
) -> impl fmt::Display + '_ {
    struct Display<'a>(&'a [u8]);

    impl<'a> fmt::Display for Display<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            display(self.0, f)
        }
    }

    Display(octets.as_ref())
}

/// Serialize and deserialize octets Base64 encoded or binary.
///
/// This module can be used with Serde’s `with` attribute. It will serialize
/// an octets sequence as a Base64 encoded string with human readable
/// serializers or as a raw octets sequence for compact serializers.
#[cfg(feature = "serde")]
pub mod serde {
    use super::encode_display;
    use crate::base::octets::{
        DeserializeOctets, EmptyBuilder, FromBuilder, OctetsBuilder,
        SerializeOctets,
    };
    use core::fmt;

    pub fn serialize<Octets, S>(
        octets: &Octets,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        Octets: AsRef<[u8]> + SerializeOctets,
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&encode_display(octets))
        } else {
            octets.serialize_octets(serializer)
        }
    }

    pub fn deserialize<'de, Octets, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Octets, D::Error>
    where
        Octets: FromBuilder + DeserializeOctets<'de>,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        struct Visitor<'de, Octets: DeserializeOctets<'de>>(Octets::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for Visitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = Octets;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an Base64-encoded string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                super::decode(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value)
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor(Octets::visitor()))
        } else {
            Octets::deserialize_with_visitor(
                deserializer,
                Visitor(Octets::visitor()),
            )
        }
    }
}

//------------ Decoder -------------------------------------------------------

/// A base 64 decoder.
///
/// This type keeps all the state for decoding a sequence of characters
/// representing data encoded in base 32. Upon success, the decoder returns
/// the decoded data in a `bytes::Bytes` value.
pub struct Decoder<Builder> {
    /// A buffer for up to four characters.
    ///
    /// We only keep `u8`s here because only ASCII characters are used by
    /// Base64.
    buf: [u8; 4],

    /// The index in `buf` where we place the next character.
    ///
    /// We also abuse this to mark when we are done (because there was
    /// padding, in which case we set it to 0xF0).
    next: usize,

    /// The target or an error if something went wrong.
    target: Result<Builder, DecodeError>,
}

impl<Builder: EmptyBuilder> Decoder<Builder> {
    /// Creates a new empty decoder.
    pub fn new() -> Self {
        Decoder {
            buf: [0; 4],
            next: 0,
            target: Ok(Builder::empty()),
        }
    }
}

impl<Builder: OctetsBuilder> Decoder<Builder> {
    /// Finalizes decoding and returns the decoded data.
    pub fn finalize(self) -> Result<Builder::Octets, DecodeError> {
        let (target, next) = (self.target, self.next);
        target.and_then(|bytes| {
            // next is either 0 or 0xF0 for a completed group.
            if next & 0x0F != 0 {
                Err(DecodeError::ShortInput)
            } else {
                Ok(bytes.freeze())
            }
        })
    }

    /// Decodes one more character of data.
    ///
    /// Returns an error as soon as the encoded data is determined to be
    /// illegal. It is okay to push more data after the first error. The
    /// method will just keep returned errors.
    pub fn push(&mut self, ch: char) -> Result<(), DecodeError> {
        if self.next == 0xF0 {
            self.target = Err(DecodeError::TrailingInput);
            return Err(DecodeError::TrailingInput);
        }

        let val = if ch == PAD {
            // Only up to two padding characters possible.
            if self.next < 2 {
                return Err(DecodeError::IllegalChar(ch));
            }
            0x80 // Acts as a marker later on.
        } else {
            if ch > (127 as char) {
                return Err(DecodeError::IllegalChar(ch));
            }
            let val = DECODE_ALPHABET[ch as usize];
            if val == 0xFF {
                return Err(DecodeError::IllegalChar(ch));
            }
            val
        };
        self.buf[self.next] = val;
        self.next += 1;

        if self.next == 4 {
            let target = self.target.as_mut().unwrap(); // Err covered above.
            target.append_slice(&[self.buf[0] << 2 | self.buf[1] >> 4])?;
            if self.buf[2] != 0x80 {
                target
                    .append_slice(&[self.buf[1] << 4 | self.buf[2] >> 2])?;
            }
            if self.buf[3] != 0x80 {
                if self.buf[2] == 0x80 {
                    return Err(DecodeError::TrailingInput);
                }
                target.append_slice(&[(self.buf[2] << 6) | self.buf[3]])?;
                self.next = 0
            } else {
                self.next = 0xF0
            }
        }

        Ok(())
    }
}

//--- Default

#[cfg(feature = "bytes")]
impl<Builder: EmptyBuilder> Default for Decoder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//------------ SymbolConverter -----------------------------------------------

/// A Base 64 decoder that can be used as a converter with a scanner.
#[derive(Clone, Debug, Default)]
pub struct SymbolConverter {
    /// A buffer for up to four input characters.
    ///
    /// We only keep `u8`s here because only ASCII characters are used by
    /// Base64.
    input: [u8; 4],

    /// The index in `input` where we place the next character.
    ///
    /// We also abuse this to mark when we are done (because there was
    /// padding, in which case we set it to 0xF0).
    next: usize,

    /// A buffer to return a slice for the output.
    output: [u8; 3],
}

impl SymbolConverter {
    /// Creates a new symbol converter.
    pub fn new() -> Self {
        Default::default()
    }

    fn process_char<Error: ScannerError>(
        &mut self,
        ch: char,
    ) -> Result<Option<&[u8]>, Error> {
        if self.next == 0xF0 {
            return Err(Error::custom("trailing Base 64 data"));
        }

        let val = if ch == PAD {
            // Only up to two padding characters possible.
            if self.next < 2 {
                return Err(Error::custom("illegal Base 64 data"));
            }
            0x80 // Acts as a marker later on.
        } else {
            if ch > (127 as char) {
                return Err(Error::custom("illegal Base 64 data"));
            }
            let val = DECODE_ALPHABET[ch as usize];
            if val == 0xFF {
                return Err(Error::custom("illegal Base 64 data"));
            }
            val
        };
        self.input[self.next] = val;
        self.next += 1;

        if self.next == 4 {
            self.output[0] = self.input[0] << 2 | self.input[1] >> 4;
            if self.input[2] != 0x80 {
                self.output[1] = self.input[1] << 4 | self.input[2] >> 2;
            }
            if self.input[3] != 0x80 {
                if self.input[2] == 0x80 {
                    return Err(Error::custom("trailing Base 64 data"));
                }
                self.output[2] = (self.input[2] << 6) | self.input[3];
                self.next = 0
            } else {
                self.next = 0xF0
            }
            Ok(Some(&self.output))
        } else {
            Ok(None)
        }
    }
}

impl<Sym, Error> ConvertSymbols<Sym, Error> for SymbolConverter
where
    Sym: Into<EntrySymbol>,
    Error: ScannerError,
{
    fn process_symbol(
        &mut self,
        symbol: Sym,
    ) -> Result<Option<&[u8]>, Error> {
        match symbol.into() {
            EntrySymbol::Symbol(symbol) => self.process_char(
                symbol
                    .into_char()
                    .map_err(|_| Error::custom("illegal Base 64 data"))?,
            ),
            EntrySymbol::EndOfToken => Ok(None),
        }
    }

    fn process_tail(&mut self) -> Result<Option<&[u8]>, Error> {
        // next is either 0 or 0xF0 for a completed group.
        if self.next & 0x0F != 0 {
            Err(Error::custom("incomplete Base 64 data"))
        } else {
            Ok(None)
        }
    }
}

//============ Error Types ===================================================

//------------ DecodeError ---------------------------------------------------

/// An error happened while decoding a base 64 or base 32 encoded string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// A character was pushed that isn’t allowed in the encoding.
    IllegalChar(char),

    /// There was trailing data after a padding sequence.
    TrailingInput,

    /// The input ended with an incomplete sequence.
    ShortInput,

    /// The buffer to decode into is too short.
    ShortBuf,
}

impl From<ShortBuf> for DecodeError {
    fn from(_: ShortBuf) -> Self {
        DecodeError::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecodeError::TrailingInput => f.write_str("trailing input"),
            DecodeError::IllegalChar(ch) => {
                write!(f, "illegal character '{}'", ch)
            }
            DecodeError::ShortInput => f.write_str("incomplete input"),
            DecodeError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

//============ Constants =====================================================

/// The alphabet used by the decoder.
///
/// This maps encoding characters into their values. A value of 0xFF stands in
/// for illegal characters. We only provide the first 128 characters since the
/// alphabet will only use ASCII characters.
const DECODE_ALPHABET: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x00 .. 0x07
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x08 .. 0x0F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x10 .. 0x17
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x18 .. 0x1F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x20 .. 0x27
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, // 0x28 .. 0x2F
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, // 0x30 .. 0x37
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x38 .. 0x3F
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // 0x40 .. 0x47
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, // 0x48 .. 0x4F
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // 0x50 .. 0x57
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x58 .. 0x5F
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, // 0x60 .. 0x67
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // 0x68 .. 0x6F
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, // 0x70 .. 0x77
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x78 .. 0x7F
];

const ENCODE_ALPHABET: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', // 0x00 .. 0x07
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 0x08 .. 0x0F
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 0x10 .. 0x17
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', // 0x18 .. 0x1F
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', // 0x20 .. 0x27
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', // 0x28 .. 0x2F
    'w', 'x', 'y', 'z', '0', '1', '2', '3', // 0x30 .. 0x37
    '4', '5', '6', '7', '8', '9', '+', '/', // 0x38 .. 0x3F
];

/// The padding character
const PAD: char = '=';

//============ Test ==========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "std")]
    #[test]
    fn decode_str() {
        use super::DecodeError;

        fn decode(s: &str) -> Result<std::vec::Vec<u8>, DecodeError> {
            super::decode(s)
        }

        assert_eq!(&decode("").unwrap(), b"");
        assert_eq!(&decode("Zg==").unwrap(), b"f");
        assert_eq!(&decode("Zm8=").unwrap(), b"fo");
        assert_eq!(&decode("Zm9v").unwrap(), b"foo");
        assert_eq!(&decode("Zm9vYg==").unwrap(), b"foob");
        assert_eq!(&decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(&decode("Zm9vYmFy").unwrap(), b"foobar");

        assert_eq!(decode("FPucA").unwrap_err(), DecodeError::ShortInput);
        assert_eq!(
            decode("FPucA=").unwrap_err(),
            DecodeError::IllegalChar('=')
        );
        assert_eq!(decode("FPucAw=").unwrap_err(), DecodeError::ShortInput);
        assert_eq!(
            decode("FPucAw=a").unwrap_err(),
            DecodeError::TrailingInput
        );
        assert_eq!(
            decode("FPucAw==a").unwrap_err(),
            DecodeError::TrailingInput
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn display_bytes() {
        use super::*;

        fn fmt(s: &[u8]) -> String {
            let mut out = String::new();
            display(s, &mut out).unwrap();
            out
        }

        assert_eq!(fmt(b""), "");
        assert_eq!(fmt(b"f"), "Zg==");
        assert_eq!(fmt(b"fo"), "Zm8=");
        assert_eq!(fmt(b"foo"), "Zm9v");
        assert_eq!(fmt(b"foob"), "Zm9vYg==");
        assert_eq!(fmt(b"fooba"), "Zm9vYmE=");
        assert_eq!(fmt(b"foobar"), "Zm9vYmFy");
    }
}
