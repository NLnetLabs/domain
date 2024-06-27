//! Decoding and encoding of Base 16 a.k.a. hex digits.
//!
//! The Base 16 encoding is defined in [RFC 4648]. It really is just a normal
//! hex-encoding using the (case-insensitive) letters ‘A’ to ‘F’ as
//! additional values for the digits.
//!
//! The module defines the type [`Decoder`] which keeps the state necessary
//! for decoding. The various functions offered use such a decoder to decode
//! and encode octets in various forms.
//!
//! [RFC 4648]: https://tools.ietf.org/html/rfc4648

use crate::base::scan::{ConvertSymbols, EntrySymbol, ScannerError};
use core::fmt;
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder,
};
#[cfg(feature = "std")]
use std::string::String;

//------------ Re-exports ----------------------------------------------------

pub use super::base64::DecodeError;

//------------ Convenience Functions -----------------------------------------

/// Decodes a string with Base 16 encoded data.
///
/// The function attempts to decode the entire string and returns the result
/// as an `Octets` value.
pub fn decode<Octets>(s: &str) -> Result<Octets, DecodeError>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder,
{
    let mut decoder = Decoder::<<Octets as FromBuilder>::Builder>::new();
    for ch in s.chars() {
        decoder.push(ch)?;
    }
    decoder.finalize()
}

/// Decodes a string with Base 16 data and returns it as a vec.
#[cfg(feature = "std")]
pub fn decode_vec(s: &str) -> Result<std::vec::Vec<u8>, DecodeError> {
    decode(s)
}

/// Encodes binary data in Base 16 and writes it into a format stream.
///
/// This function is intended to be used in implementations of formatting
/// traits:
///
/// ```
/// use core::fmt;
/// use domain::utils::base16;
///
/// struct Foo<'a>(&'a [u8]);
///
/// impl<'a> fmt::Display for Foo<'a> {
///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
///         base16::display(&self.0, f)
///     }
/// }
/// ```
pub fn display<Octets, Target>(octets: &Octets, f: &mut Target) -> fmt::Result
where
    Octets: AsRef<[u8]> + ?Sized,
    Target: fmt::Write,
{
    for &octet in octets.as_ref() {
        f.write_str(ENCODE_ALPHABET[usize::from(octet)])?;
    }
    Ok(())
}

/// Encodes binary data in Base 16 and returns the encoded data as a string.
#[cfg(feature = "std")]
pub fn encode_string<B: AsRef<[u8]> + ?Sized>(bytes: &B) -> String {
    let mut res = String::with_capacity(bytes.as_ref().len() * 2);
    display(bytes, &mut res).unwrap();
    res
}

/// Returns a placeholder value that implements `Display` for encoded data.
pub fn encode_display<Octets: AsRef<[u8]> + ?Sized>(
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

/// Serialize and deserialize octets Base 16 encoded or binary.
///
/// This module can be used with Serde’s `with` attribute. It will serialize
/// an octets sequence as a Base 16 encoded string with human readable
/// serializers or as a raw octets sequence for compact serializers.
#[cfg(feature = "serde")]
pub mod serde {
    use core::fmt;
    use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder};
    use octseq::serde::DeserializeOctets;

    pub fn serialize<Octets, S>(
        octets: &Octets,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        Octets: AsRef<[u8]>,
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&super::encode_display(octets))
        } else {
            octseq::serde::serialize(octets, serializer)
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
                f.write_str("an Base16-encoded string")
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

/// A Base 16 decoder.
///
/// This type keeps all the state for decoding a sequence of characters
/// representing data encoded in Base 16. Upon success, the decoder returns
/// the decoded data.
pub struct Decoder<Builder> {
    /// A buffer for the first half of an octet.
    buf: Option<u8>,

    /// The target or an error if something went wrong.
    target: Result<Builder, DecodeError>,
}

impl<Builder: EmptyBuilder> Decoder<Builder> {
    /// Creates a new, empty decoder using the *base32hex* variant.
    #[must_use]
    pub fn new() -> Self {
        Decoder {
            buf: None,
            target: Ok(Builder::empty()),
        }
    }
}

impl<Builder: OctetsBuilder> Decoder<Builder> {
    /// Finalizes decoding and returns the decoded data.
    pub fn finalize(self) -> Result<Builder::Octets, DecodeError>
    where
        Builder: FreezeBuilder,
    {
        if self.buf.is_some() {
            return Err(DecodeError::ShortInput);
        }

        self.target.map(FreezeBuilder::freeze)
    }

    /// Decodes one more character of data.
    ///
    /// Returns an error as soon as the encoded data is determined to be
    /// illegal. It is okay to push more data after the first error. The
    /// method will just keep returning errors.
    pub fn push(&mut self, ch: char) -> Result<(), DecodeError> {
        let value = match ch.to_digit(16) {
            Some(value) => value as u8,
            None => {
                self.target = Err(DecodeError::IllegalChar(ch));
                return Err(DecodeError::IllegalChar(ch));
            }
        };
        if let Some(upper) = self.buf.take() {
            self.append(upper | value);
        } else {
            self.buf = Some(value << 4)
        }
        match self.target {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
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

impl<Builder: EmptyBuilder> Default for Decoder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//------------ SymbolConverter -----------------------------------------------

/// A Base 16 decoder that can be used as a converter for a scanner.
#[derive(Clone, Debug, Default)]
pub struct SymbolConverter {
    /// A buffer for the returned data.
    buf: [u8; 1],

    /// Do we already have the upper half in `buf`?
    pending: bool,
}

impl SymbolConverter {
    /// Creates a new symbol converter.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
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
            EntrySymbol::Symbol(symbol) => {
                let symbol = symbol
                    .into_char()
                    .map_err(|_| Error::custom("expected hex digits"))?
                    .to_digit(16)
                    .ok_or_else(|| Error::custom("expected hex digits"))?;

                if self.pending {
                    self.buf[0] |= symbol as u8;
                    self.pending = false;
                    Ok(Some(&self.buf))
                } else {
                    self.buf[0] = (symbol << 4) as u8;
                    self.pending = true;
                    Ok(None)
                }
            }
            EntrySymbol::EndOfToken => Ok(None),
        }
    }

    /// Process the end of token.
    ///
    /// The method may return data to be added to the output octets sequence.
    fn process_tail(&mut self) -> Result<Option<&[u8]>, Error> {
        if self.pending {
            Err(Error::custom("uneven number of hex digits"))
        } else {
            Ok(None)
        }
    }
}

//------------ Constants -----------------------------------------------------

/// The alphabet used for encoding.
///
/// We have to have this because `char::from_digit` prefers lower case letters
/// while the RFC prefers upper case.
const ENCODE_ALPHABET: [&str; 256] = [
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B",
    "0C", "0D", "0E", "0F", "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", "20", "21", "22", "23",
    "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
    "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B",
    "3C", "3D", "3E", "3F", "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", "50", "51", "52", "53",
    "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
    "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B",
    "6C", "6D", "6E", "6F", "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", "80", "81", "82", "83",
    "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B",
    "9C", "9D", "9E", "9F", "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
    "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", "B0", "B1", "B2", "B3",
    "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
    "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB",
    "CC", "CD", "CE", "CF", "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
    "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", "E0", "E1", "E2", "E3",
    "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
    "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB",
    "FC", "FD", "FE", "FF",
];

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "bytes")]
    fn decode_str() {
        use super::DecodeError;

        fn decode(s: &str) -> Result<std::vec::Vec<u8>, DecodeError> {
            super::decode(s)
        }

        assert_eq!(&decode("").unwrap(), b"");
        assert_eq!(&decode("F0").unwrap(), b"\xF0");
        assert_eq!(&decode("F00f").unwrap(), b"\xF0\x0F");
    }

    #[test]
    fn test_display() {
        fn fmt(s: &[u8]) -> String {
            let mut out = String::new();
            display(s, &mut out).unwrap();
            out
        }

        assert_eq!(fmt(b""), "");
        assert_eq!(fmt(b"\xf0"), "F0");
        assert_eq!(fmt(b"\xf0\x0f"), "F00F");
    }
}
