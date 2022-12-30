//! Decoding and encoding of base 32.
//!
//! The base 32 encoding is defined in [RFC 4648]. It is essentially a
//! case-insensitive version of [base64][super::base64] which is necessary
//! when encoding binary data in domain names. The RFC defines two separate
//! encodings, called *base32* and *base32hex*. The DNS uses the latter
//! version, particularly in [NSEC3], for encoding binary data in domain
//! names, because it has the property that the encoding maintains the order
//! of the original data.
//!
//! This module currently only implements *base32hex* but is prepared for
//! adding the other option by using the prefix `_hex` wherever distinction
//! is necessary.
//!
//! The module defines the type [`Decoder`] which keeps the state necessary
//! for decoding. The various functions offered use such a decoder to decode
//! and encode octets in various forms.
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648
//! [NSEC3]: ../../rdata/rfc5155/index.html
//! [`Decoder`]: struct.Decoder.html

use crate::base::octets::{EmptyBuilder, FromBuilder, OctetsBuilder};
use crate::base::scan::{ConvertSymbols, EntrySymbol, ScannerError};
use core::fmt;
use octseq::builder::FreezeBuilder;
#[cfg(feature = "std")]
use std::string::String;

//------------ Re-exports ----------------------------------------------------

pub use super::base64::DecodeError;

//------------ Convenience Functions -----------------------------------------

/// Decodes a string with *base32hex* encoded data.
///
/// The function attempts to decode the entire string and returns the result
/// as an `Octets` value.
pub fn decode_hex<Octets>(s: &str) -> Result<Octets, DecodeError>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
{
    let mut decoder = Decoder::<<Octets as FromBuilder>::Builder>::new_hex();
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
where
    B: AsRef<[u8]> + ?Sized,
    W: fmt::Write,
{
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

/// Encodes binary data in *base32hex* and returns the encoded data as a string.
#[cfg(feature = "std")]
pub fn encode_string_hex<B: AsRef<[u8]> + ?Sized>(bytes: &B) -> String {
    let mut res = String::with_capacity((bytes.as_ref().len() / 5 + 1) * 8);
    display_hex(bytes, &mut res).unwrap();
    res
}

/// Returns a placeholder value that implements `Display` for encoded data.
pub fn encode_display_hex<Octets: AsRef<[u8]>>(
    octets: &Octets,
) -> impl fmt::Display + '_ {
    struct Display<'a>(&'a [u8]);

    impl<'a> fmt::Display for Display<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            display_hex(self.0, f)
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
            serializer.collect_str(&super::encode_display_hex(octets))
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
            <Octets as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
        {
            type Value = Octets;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an Base32-encoded string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                super::decode_hex(v).map_err(E::custom)
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

/// A base 32 decoder.
///
/// This type keeps all the state for decoding a sequence of characters
/// representing data encoded in base 32. Upon success, the decoder returns
/// the decoded data.
///
/// # Limitations
///
/// The decoder does not support padding.
pub struct Decoder<Builder> {
    /// The alphabet we are using.
    alphabet: &'static [u8; 128],

    /// A buffer for up to eight characters.
    ///
    /// We only keep `u8`s here because only ASCII characters are used by
    /// Base32.
    buf: [u8; 8],

    /// The index in `buf` where we place the next character.
    next: usize,

    /// The target or an error if something went wrong.
    target: Result<Builder, DecodeError>,
}

impl<Builder: EmptyBuilder> Decoder<Builder> {
    /// Creates a new, empty decoder using the *base32hex* variant.
    pub fn new_hex() -> Self {
        Decoder {
            alphabet: &DECODE_HEX_ALPHABET,
            buf: [0; 8],
            next: 0,
            target: Ok(Builder::empty()),
        }
    }
}

impl<Builder: OctetsBuilder> Decoder<Builder> {
    /// Finalizes decoding and returns the decoded data.
    #[allow(clippy::question_mark)] // false positive
    pub fn finalize(mut self) -> Result<Builder::Octets, DecodeError>
    where Builder: FreezeBuilder {
        if let Err(err) = self.target {
            return Err(err);
        }

        match self.next {
            0 => {}
            1 | 3 | 6 => return Err(DecodeError::ShortInput),
            2 => {
                self.octet_0();
            }
            4 => {
                self.octet_0();
                self.octet_1();
            }
            5 => {
                self.octet_0();
                self.octet_1();
                self.octet_2();
            }
            7 => {
                self.octet_0();
                self.octet_1();
                self.octet_2();
                self.octet_3();
            }
            _ => unreachable!(),
        }
        self.target.map(FreezeBuilder::freeze)
    }

    /// Decodes one more character of data.
    ///
    /// Returns an error as soon as the encoded data is determined to be
    /// illegal. It is okay to push more data after the first error. The
    /// method will just keep returning errors.
    pub fn push(&mut self, ch: char) -> Result<(), DecodeError> {
        if ch > (127 as char) {
            self.target = Err(DecodeError::IllegalChar(ch));
            return Err(DecodeError::IllegalChar(ch));
        }
        let val = self.alphabet[ch as usize];
        if val == 0xFF {
            self.target = Err(DecodeError::IllegalChar(ch));
            return Err(DecodeError::IllegalChar(ch));
        }
        self.buf[self.next] = val;
        self.next += 1;

        if self.next == 8 {
            self.octet_0();
            self.octet_1();
            self.octet_2();
            self.octet_3();
            self.octet_4();
            self.next = 0;
        }
        match self.target {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
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
        let target = match self.target.as_mut() {
            Ok(target) => target,
            Err(_) => return,
        };
        if let Err(err) = target.append_slice(&[value]) {
            self.target = Err(err.into().into());
        }
    }
}

//------------ SymbolConverter -----------------------------------------------

/// A Base 32 decoder that can be used as a converter with a scanner.
#[derive(Clone, Debug)]
pub struct SymbolConverter {
    /// The alphabet we are using.
    alphabet: &'static [u8; 128],

    /// A buffer for up to eight input characters.
    ///
    /// We only keep `u8`s here because only ASCII characters are used by
    /// Base64.
    input: [u8; 8],

    /// The index in `input` where we place the next character.
    ///
    /// We also abuse this to mark when we are done (because there was
    /// padding, in which case we set it to 0xF0).
    next: usize,

    /// A buffer to return a slice for the output.
    output: [u8; 5],
}

impl Default for SymbolConverter {
    fn default() -> Self {
        SymbolConverter {
            alphabet: &DECODE_HEX_ALPHABET,
            input: [0; 8],
            next: 0,
            output: Default::default(),
        }
    }
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
        if ch > (127 as char) {
            return Err(Error::custom("illegal Base 32 data"));
        }
        let val = self.alphabet[ch as usize];
        if val == 0xFF {
            return Err(Error::custom("illegal Base 32 data"));
        }
        self.input[self.next] = val;
        self.next += 1;

        if self.next == 8 {
            self.output = [
                self.input[0] << 3 | self.input[1] >> 2,
                self.input[1] << 6 | self.input[2] << 1 | self.input[3] >> 4,
                self.input[3] << 4 | self.input[4] >> 1,
                self.input[4] << 7 | self.input[5] << 2 | self.input[6] >> 3,
                self.input[6] << 5 | self.input[7],
            ];
            self.next = 0;
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
                    .map_err(|_| Error::custom("illegal Base 32 data"))?,
            ),
            EntrySymbol::EndOfToken => Ok(None),
        }
    }

    /// Process the end of token.
    ///
    /// The method may return data to be added to the output octets sequence.
    fn process_tail(&mut self) -> Result<Option<&[u8]>, Error> {
        match self.next {
            0 => return Ok(None),
            1 | 3 | 6 => return Err(Error::custom("short Base 32 input")),
            _ => {}
        }
        self.output[0] = self.input[0] << 3 | self.input[1] >> 2;
        if self.next == 2 {
            return Ok(Some(&self.output[0..1]));
        }
        self.output[1] =
            self.input[1] << 6 | self.input[2] << 1 | self.input[3] >> 4;
        if self.next == 4 {
            return Ok(Some(&self.output[0..2]));
        }
        self.output[2] = self.input[3] << 4 | self.input[4] >> 1;
        if self.next == 5 {
            return Ok(Some(&self.output[0..3]));
        }
        self.output[3] =
            self.input[4] << 7 | self.input[5] << 2 | self.input[6] >> 3;
        Ok(Some(&self.output[0..4]))
    }
}

//------------ Constants -----------------------------------------------------

/// The alphabet used for decoding *base32hex.*
///
/// This maps encoding characters into their values. A value of 0xFF stands in
/// for illegal characters. We only provide the first 128 characters since the
/// alphabet will only use ASCII characters.
const DECODE_HEX_ALPHABET: [u8; 128] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x00 .. 0x07
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x08 .. 0x0F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x10 .. 0x17
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x18 .. 0x1F
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x20 .. 0x27
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x28 .. 0x2F
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 0x30 .. 0x37
    0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x38 .. 0x3F
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // 0x40 .. 0x47
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // 0x48 .. 0x4F
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xFF, // 0x50 .. 0x57
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x58 .. 0x5F
    0xFF, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // 0x60 .. 0x67
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // 0x68 .. 0x6F
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xFF, // 0x70 .. 0x77
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 0x78 .. 0x7F
];

/// The alphabet used for encoding *base32hex.*
const ENCODE_HEX_ALPHABET: [char; 32] = [
    '0', '1', '2', '3', '4', '5', '6', '7', // 0x00 .. 0x07
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', // 0x08 .. 0x0F
    'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', // 0x10 .. 0x17
    'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', // 0x18 .. 0x1F
];

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use std::string::String;

    #[test]
    #[cfg(feature = "bytes")]
    fn decode_str_hex() {
        use super::DecodeError;

        fn decode_hex(s: &str) -> Result<std::vec::Vec<u8>, DecodeError> {
            super::decode_hex(s)
        }

        assert_eq!(&decode_hex("").unwrap(), b"");
        assert_eq!(&decode_hex("CO").unwrap(), b"f");
        assert_eq!(&decode_hex("CPNG").unwrap(), b"fo");
        assert_eq!(&decode_hex("CPNMU").unwrap(), b"foo");
        assert_eq!(&decode_hex("CPNMUOG").unwrap(), b"foob");
        assert_eq!(&decode_hex("CPNMUOJ1").unwrap(), b"fooba");
        assert_eq!(&decode_hex("CPNMUOJ1E8").unwrap(), b"foobar");
        assert_eq!(&decode_hex("co").unwrap(), b"f");
        assert_eq!(&decode_hex("cpng").unwrap(), b"fo");
        assert_eq!(&decode_hex("cpnmu").unwrap(), b"foo");
        assert_eq!(&decode_hex("cpnmuog").unwrap(), b"foob");
        assert_eq!(&decode_hex("cpnmuoj1").unwrap(), b"fooba");
        assert_eq!(&decode_hex("cpnmuoj1e8").unwrap(), b"foobar");
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
