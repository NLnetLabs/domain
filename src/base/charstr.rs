//! Character strings.
//!
//! The somewhat ill-named `<character-string>` is defined in [RFC 1035] as
//! binary information of up to 255 octets. As such, it doesn’t necessarily
//! contain (ASCII-) characters nor is it a string in a Rust-sense.
//!
//! An existing, immutable character string is represented by the type
//! [`CharStr`]. The type [`CharStrBuilder`] allows constructing a character
//! string from individual octets or octets slices.
//!
//! In wire-format, character strings are encoded as one octet giving the
//! length followed by the actual data in that many octets. The length octet
//! is not part of the content wrapped by [`CharStr`], it contains the data
//! only.
//!
//! A [`CharStr`] can be constructed from a string via the `FromStr`
//! trait. In this case, the string must consist only of printable ASCII
//! characters. Space and double quote are allowed and will be accepted with
//! their ASCII value. Other values need to be escaped via a backslash
//! followed by the three-digit decimal representation of the value. In
//! addition, a backslash followed by a non-digit printable ASCII character
//! is accepted, too, with the ASCII value of this character used.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use super::cmp::CanonicalOrd;
use super::scan::{BadSymbol, Scanner, Symbol, SymbolCharsError};
use super::wire::{Compose, ParseError};
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::{cmp, fmt, hash, str};
use octseq::builder::FreezeBuilder;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};
use octseq::{
    EmptyBuilder, FromBuilder, IntoBuilder, Octets, OctetsBuilder,
    OctetsFrom, Parser, ShortBuf, Truncate,
};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ CharStr -------------------------------------------------------

/// The content of a DNS character string.
///
/// A character string consists of up to 255 octets of binary data. This type
/// wraps an octets sequence. It is guaranteed to always be at most 255 octets
/// in length. It derefs into the underlying octets for working with the
/// content in a familiar way.
///
/// As per [RFC 1035], character strings compare ignoring ASCII case.
/// `CharStr`’s implementations of the `std::cmp` traits act accordingly.
///
/// # Presentation format
///
/// The text representation of a character string comes in two flavors:
/// Quoted and unquoted. In both cases, the content is interpreted as ASCII
/// text and those octets that aren’t printable ASCII characters, as well as
/// some special symbols, are escaped.
///
/// There are two escaping mechanisms: octets that are printable ASCII
/// characters but need to be escaped anyway use what we call a “simple
/// escape” that precedes the character with an ASCII backslash. For all
/// non-printable octets “decimal escapes” are used: an ASCII backslash is
/// followed by three decimal digits representing the decimal value of the
/// octet. A consequence if this is that you cannot escape the digits 0, 1,
/// and 2 using simple escapes and you probably shouldn’t do it for the other
/// digits.
///
/// In the quoted form, the content is preceded and followed by exactly one
/// ASCII double quote. Inside, only double quotes, backslashes, and
/// non-printable octets need to be escaped.
///
/// In the unquoted form, the content is formatted without any explicit
/// delimiters. Instead, it ends at the first ASCII space or any other
/// delimiting symbol, normally ASCII control characters or an ASCII
/// semicolon which marks the start of a comment. These characters, as well
/// as the double quote, also need to be escaped.
///
/// # `Display` and `FromStr`
///
/// When formatting a character string using the `Display` trait, a variation
/// of the unquoted form is used where only backslashes and non-printable
/// octets are escaped. Two methods are available that make it possible to
/// format the character string in quoted and unquoted formats,
/// [`display_quoted`][Self::display_quoted] and
/// [`display_unquoted`][Self::display_unquoted]. They return a temporary
/// value that can be given to a formatting macro.
///
/// The `FromStr` implementation reads a character string from a Rust string
/// in the format created by `Display` but is more relaxed about escape
/// sequences – it accepts all of them as long as they lead to a valid
/// character string.
///
/// # Serde support
///
/// When the `serde` feature is enabled, the type supports serialization and
/// deserialization. The format differs for human readable and compact
/// serialization formats.
///
/// For human readable formats, character strings are serialized as a newtype
/// `CharStr` wrapping a string with the content as an ASCII string.
/// Non-printable ASCII characters (i.e., those with a byte value below 32
/// and above 176) are escaped using the decimal escape sequences as used by
/// the presentation format. In addition, backslashes are escaped using a
/// simple escape sequence and thus are doubled.
///
/// This leads to a slightly unfortunate situation in serialization formats
/// that in turn use backslash as an escape sequence marker in their own
/// string representation, such as JSON, where a backslash ends up as four
/// backslashes.
///
/// When deserializing, escape sequences are excepted for all octets and
/// translated. Non-ASCII characters are not accepted and lead to error.
///
/// For compact formats, character strings are serialized as a
/// newtype `CharStr` wrapping a byte array with the content as is.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone)]
pub struct CharStr<Octs: ?Sized>(Octs);

impl CharStr<()> {
    /// Character strings have a maximum length of 255 octets.
    pub const MAX_LEN: usize = 255;
}

impl<Octs: ?Sized> CharStr<Octs> {
    /// Creates a new empty character string.
    #[must_use]
    pub fn empty() -> Self
    where
        Octs: From<&'static [u8]>,
    {
        CharStr(b"".as_ref().into())
    }

    /// Creates a new character string from an octets value.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octs) -> Result<Self, CharStrError>
    where
        Octs: AsRef<[u8]> + Sized,
    {
        CharStr::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a character string from octets without length check.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is at most 255 octets
    /// long. Otherwise, the behavior is undefined.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self
    where
        Octs: Sized,
    {
        CharStr(octets)
    }
}

impl CharStr<[u8]> {
    /// Creates a character string from an octets slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, CharStrError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a new empty character string on an octets slice.
    #[must_use]
    pub fn empty_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"".as_ref()) }
    }

    /// Creates a character string from an octets slice without checking.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is at most 255 octets
    /// long. Otherwise, the behaviour is undefined.
    #[must_use]
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    /// Creates a character string from a mutable slice without checking.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is at most 255 octets
    /// long. Otherwise, the behaviour is undefined.
    unsafe fn from_slice_mut_unchecked(slice: &mut [u8]) -> &mut Self {
        &mut *(slice as *mut [u8] as *mut Self)
    }

    /// Checks whether an octets slice contains a correct character string.
    fn check_slice(slice: &[u8]) -> Result<(), CharStrError> {
        if slice.len() > CharStr::MAX_LEN {
            Err(CharStrError)
        } else {
            Ok(())
        }
    }
}

impl<Octs: ?Sized> CharStr<Octs> {
    /// Creates a new empty builder for this character string type.
    #[must_use]
    pub fn builder() -> CharStrBuilder<Octs::Builder>
    where
        Octs: IntoBuilder,
        Octs::Builder: EmptyBuilder,
    {
        CharStrBuilder::new()
    }

    /// Converts the character string into a builder.
    pub fn into_builder(self) -> CharStrBuilder<Octs::Builder>
    where
        Octs: IntoBuilder + Sized,
        <Octs as IntoBuilder>::Builder: AsRef<[u8]>,
    {
        unsafe {
            CharStrBuilder::from_builder_unchecked(IntoBuilder::into_builder(
                self.0,
            ))
        }
    }

    /// Converts the character string into its underlying octets value.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.0
    }

    /// Returns a character string atop a slice of the content.
    pub fn for_slice(&self) -> &CharStr<[u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe { CharStr::from_slice_unchecked(self.0.as_ref()) }
    }

    /// Returns a character string atop a mutable slice of the content.
    pub fn for_slice_mut(&mut self) -> &mut CharStr<[u8]>
    where
        Octs: AsMut<[u8]>,
    {
        unsafe { CharStr::from_slice_mut_unchecked(self.0.as_mut()) }
    }

    /// Returns a reference to a slice of the character string’s data.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a reference to a mutable slice of the character string’s data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octs: AsMut<[u8]>,
    {
        self.0.as_mut()
    }

    /// Parses a character string from the beginning of a parser.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError>
    where
        Octs: Sized,
    {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|bytes| unsafe { Self::from_octets_unchecked(bytes) })
            .map_err(Into::into)
    }
}

impl CharStr<[u8]> {
    /// Parses a character string from a parser atop a slice.
    pub fn parse_slice<'a>(
        parser: &mut Parser<'a, [u8]>,
    ) -> Result<&'a Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|bytes| unsafe { Self::from_slice_unchecked(bytes) })
            .map_err(Into::into)
    }

    /// Decodes the readable presentation and appends it to a builder.
    ///
    /// This is a helper function used both by the `FromStr` impl and
    /// deserialization. It reads the string in unquoted form and appends its
    /// wire format to the builder. Note that this does _not_ contain the
    /// length octet. The function does, however, return the value of the
    /// length octet.
    ///
    /// The function is here on `CharStr<[u8]>` so that it can be called
    /// simply via `CharStr::append_from_str` without having to provide a
    /// type argument.
    fn append_from_str(
        s: &str,
        target: &mut impl OctetsBuilder,
    ) -> Result<u8, FromStrError> {
        let mut len = 0u8;
        let mut chars = s.chars();
        while let Some(symbol) = Symbol::from_chars(&mut chars)? {
            // We have the max length but there’s another character. Error!
            if len == u8::MAX {
                return Err(FromStrError::LongString);
            }
            target
                .append_slice(&[symbol.into_octet()?])
                .map_err(Into::into)?;
            len += 1;
        }
        Ok(len)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> CharStr<Octs> {
    /// Returns the length of the character string.
    ///
    /// This is the length of the content only, i.e., without the extra
    /// length octet added for the wire format.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns whether the character string is empty.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Returns an iterator over the octets of the character string.
    pub fn iter(&self) -> Iter {
        Iter {
            octets: self.as_slice(),
        }
    }
}

impl CharStr<[u8]> {
    /// Skips over a character string at the beginning of a parser.
    pub fn skip<Src: Octets + ?Sized>(
        parser: &mut Parser<Src>,
    ) -> Result<(), ParseError> {
        let len = parser.parse_u8()?;
        parser.advance(len.into()).map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> CharStr<Octs> {
    /// Returns the length of the wire format representation.
    pub fn compose_len(&self) -> u16 {
        u16::try_from(self.0.as_ref().len() + 1).expect("long charstr")
    }

    /// Appends the wire format representation to an octets builder.
    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        u8::try_from(self.0.as_ref().len())
            .expect("long charstr")
            .compose(target)?;
        target.append_slice(self.0.as_ref())
    }
}

impl<Octs> CharStr<Octs> {
    /// Scans the presentation format from a scanner.
    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_charstr()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> CharStr<Octs> {
    /// Returns an object that formats in quoted presentation format.
    ///
    /// The returned object will display the content surrounded by double
    /// quotes. It will escape double quotes, backslashes, and non-printable
    /// octets only.
    pub fn display_quoted(&self) -> DisplayQuoted {
        DisplayQuoted(self.for_slice())
    }

    /// Returns an object that formats in unquoted presentation format.
    ///
    /// The returned object will display the content without explicit
    /// delimiters and escapes space, double quotes, semicolons, backslashes,
    /// and non-printable octets.
    pub fn display_unquoted(&self) -> DisplayUnquoted {
        DisplayUnquoted(self.for_slice())
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<CharStr<SrcOcts>> for CharStr<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: CharStr<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- FromStr

impl<Octets> str::FromStr for CharStr<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: OctetsBuilder
        + FreezeBuilder<Octets = Octets>
        + EmptyBuilder
        + AsRef<[u8]>,
{
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Most likely, everything is ASCII so take `s`’s length as capacity.
        let mut builder =
            CharStrBuilder::<<Octets as FromBuilder>::Builder>::with_capacity(
                s.len(),
            );
        CharStr::append_from_str(s, &mut builder)?;
        Ok(builder.finish())
    }
}

//--- AsRef and AsMut
//
// No Borrow as character strings compare ignoring case.

impl<Octets: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for CharStr<Octets> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<Octets: AsMut<U> + ?Sized, U: ?Sized> AsMut<U> for CharStr<Octets> {
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}

//--- PartialEq and Eq

impl<T, U> PartialEq<U> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &U) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Eq for CharStr<T> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<T, U> PartialOrd<U> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &U) -> Option<cmp::Ordering> {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .partial_cmp(other.as_ref().iter().map(u8::to_ascii_lowercase))
    }
}

impl<T: AsRef<[u8]> + ?Sized> Ord for CharStr<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(other.0.as_ref().iter().map(u8::to_ascii_lowercase))
    }
}

impl<T, U> CanonicalOrd<CharStr<U>> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &CharStr<U>) -> cmp::Ordering {
        match self.0.as_ref().len().cmp(&other.0.as_ref().len()) {
            cmp::Ordering::Equal => {}
            other => return other,
        }
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<T: AsRef<[u8]> + ?Sized> hash::Hash for CharStr<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .for_each(|ch| ch.hash(state))
    }
}

//--- Display and Debug

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_ref() {
            fmt::Display::fmt(&Symbol::display_from_octet(ch), f)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::LowerHex for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::UpperHex for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Debug for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("CharStr")
            .field(&format_args!("{}", self))
            .finish()
    }
}

//--- IntoIterator

impl<T: AsRef<[u8]>> IntoIterator for CharStr<T> {
    type Item = u8;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self.0)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized + 'a> IntoIterator for &'a CharStr<T> {
    type Item = u8;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self.0.as_ref())
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<T> serde::Serialize for CharStr<T>
where
    T: AsRef<[u8]> + SerializeOctets + ?Sized,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "CharStr",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "CharStr",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for CharStr<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder: OctetsBuilder
        + FreezeBuilder<Octets = Octets>
        + EmptyBuilder
        + AsRef<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder: OctetsBuilder
                + FreezeBuilder<Octets = Octets>
                + EmptyBuilder
                + AsRef<[u8]>,
        {
            type Value = CharStr<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                CharStr::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    CharStr::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    CharStr::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder: OctetsBuilder
                + FreezeBuilder<Octets = Octets>
                + EmptyBuilder
                + AsRef<[u8]>,
        {
            type Value = CharStr<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "CharStr",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ CharStrBuilder ------------------------------------------------

/// A builder for a character string.
///
/// This type wraps an [`OctetsBuilder`] and in turn implements the
/// [`OctetsBuilder`] trait, making sure that the content cannot grow beyond
/// the 255 octet limit of a character string.
#[derive(Clone)]
pub struct CharStrBuilder<Builder>(Builder);

impl<Builder: EmptyBuilder> CharStrBuilder<Builder> {
    /// Creates a new empty builder with default capacity.
    #[must_use]
    pub fn new() -> Self {
        CharStrBuilder(Builder::empty())
    }

    /// Creates a new empty builder with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        CharStrBuilder(Builder::with_capacity(capacity))
    }
}

impl<Builder: OctetsBuilder + AsRef<[u8]>> CharStrBuilder<Builder> {
    /// Creates a character string builder from an octet sequence unchecked.
    ///
    /// Since the buffer may already be longer than it is allowed to be, this
    /// is unsafe.
    unsafe fn from_builder_unchecked(builder: Builder) -> Self {
        CharStrBuilder(builder)
    }

    /// Creates a character string builder from an octet sequence.
    ///
    /// If the octet sequence is longer than 255 octets, an error is
    /// returned.
    pub fn from_builder(builder: Builder) -> Result<Self, CharStrError> {
        if builder.as_ref().len() > CharStr::MAX_LEN {
            Err(CharStrError)
        } else {
            Ok(unsafe { Self::from_builder_unchecked(builder) })
        }
    }
}

#[cfg(feature = "std")]
impl CharStrBuilder<Vec<u8>> {
    /// Creates a new empty characater string builder atop an octets vec.
    #[must_use]
    pub fn new_vec() -> Self {
        Self::new()
    }

    /// Creates a new empty builder atop an octets vec with a given capacity.
    #[must_use]
    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

#[cfg(feature = "bytes")]
impl CharStrBuilder<BytesMut> {
    /// Creates a new empty builder for a bytes value.
    pub fn new_bytes() -> Self {
        Self::new()
    }

    /// Creates a new empty builder for a bytes value with a given capacity.
    pub fn bytes_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl<Builder> CharStrBuilder<Builder> {
    /// Returns an octet slice of the string assembled so far.
    pub fn as_slice(&self) -> &[u8]
    where
        Builder: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Converts the builder into an imutable character string.
    pub fn finish(self) -> CharStr<Builder::Octets>
    where
        Builder: FreezeBuilder,
    {
        unsafe { CharStr::from_octets_unchecked(self.0.freeze()) }
    }
}

impl<Builder: AsRef<[u8]>> CharStrBuilder<Builder> {
    /// Returns the length of the assembled character string.
    ///
    /// This is the length of the content only, i.e., without the extra
    /// length octet added for the wire format.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns whether the character string is empty.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

//--- Default

impl<Builder: EmptyBuilder> Default for CharStrBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//--- OctetsBuilder and Truncate

impl<Builder> OctetsBuilder for CharStrBuilder<Builder>
where
    Builder: OctetsBuilder + AsRef<[u8]>,
{
    type AppendError = ShortBuf;

    fn append_slice(
        &mut self,
        slice: &[u8],
    ) -> Result<(), Self::AppendError> {
        if self.0.as_ref().len() + slice.len() > CharStr::MAX_LEN {
            return Err(ShortBuf);
        }
        self.0.append_slice(slice).map_err(Into::into)
    }
}

impl<Builder: Truncate> Truncate for CharStrBuilder<Builder> {
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

//--- AsRef and AsMut

impl<Builder: AsRef<[u8]>> AsRef<[u8]> for CharStrBuilder<Builder> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Builder: AsMut<[u8]>> AsMut<[u8]> for CharStrBuilder<Builder> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

//------------ IntoIter ------------------------------------------------------

/// The iterator type for `IntoIterator` for a character string itself.
pub struct IntoIter<T> {
    octets: T,
    len: usize,
    pos: usize,
}

impl<T: AsRef<[u8]>> IntoIter<T> {
    pub(crate) fn new(octets: T) -> Self {
        IntoIter {
            len: octets.as_ref().len(),
            octets,
            pos: 0,
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for IntoIter<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.len {
            None
        } else {
            let res = self.octets.as_ref()[self.pos];
            self.pos += 1;
            Some(res)
        }
    }
}

//------------ Iter ----------------------------------------------------------

/// The iterator type for `IntoIterator` for a reference to a character string.
pub struct Iter<'a> {
    octets: &'a [u8],
}

impl<'a> Iter<'a> {
    pub(crate) fn new(octets: &'a [u8]) -> Self {
        Iter { octets }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, octets) = self.octets.split_first()?;
        self.octets = octets;
        Some(*res)
    }
}

//------------ DisplayQuoted -------------------------------------------------

/// Helper struct for displaying in quoted presentation format.
///
/// A value of this type can be obtained via `CharStr::display_quoted`.
#[derive(Clone, Copy, Debug)]
pub struct DisplayQuoted<'a>(&'a CharStr<[u8]>);

impl<'a> fmt::Display for DisplayQuoted<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("\"")?;
        for &ch in self.0.as_ref() {
            fmt::Display::fmt(&Symbol::quoted_from_octet(ch), f)?;
        }
        f.write_str("\"")
    }
}

//------------ DisplayUnquoted -----------------------------------------------

/// Helper struct for displaying in serialization format.
///
/// A value of this type can be obtained via `CharStr::display_serialized`.
#[derive(Clone, Copy, Debug)]
pub struct DisplayUnquoted<'a>(&'a CharStr<[u8]>);

impl<'a> fmt::Display for DisplayUnquoted<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_ref() {
            fmt::Display::fmt(&Symbol::from_octet(ch), f)?;
        }
        Ok(())
    }
}

//------------ DeserializeCharStrSeed ----------------------------------------

/// A helper type to deserialize a character string into an octets builder.
///
/// This type can be used when deserializing a type that keeps a character
/// string in wire format as part of a longer octets sequence. It uses the
/// `DeserializeSeed` trait to append the content to an octets builder and
/// returns `()` as the actual value.
#[cfg(feature = "serde")]
pub struct DeserializeCharStrSeed<'a, Builder> {
    builder: &'a mut Builder,
}

#[cfg(feature = "serde")]
impl<'a, Builder> DeserializeCharStrSeed<'a, Builder> {
    /// Creates a new value wrapping a ref mut to the builder to append to.
    pub fn new(builder: &'a mut Builder) -> Self {
        Self { builder }
    }
}

#[cfg(feature = "serde")]
impl<'de, 'a, Builder> serde::de::DeserializeSeed<'de>
    for DeserializeCharStrSeed<'a, Builder>
where
    Builder: OctetsBuilder + AsMut<[u8]>,
{
    // We don’t return anything but append the value to `self.builder`.
    type Value = ();

    fn deserialize<D: serde::de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        // Here’s how this all hangs together: CharStr serializes as a
        // newtype, so we have a visitor for that. It dispatches to an
        // inner vistor that differs for binary and human-readable formats.
        // All of them just wrap around the `self` we’ve been given.

        // Visitor for the outer newtype
        struct NewtypeVisitor<'a, Builder>(
            DeserializeCharStrSeed<'a, Builder>,
        );

        impl<'de, 'a, Builder> serde::de::Visitor<'de> for NewtypeVisitor<'a, Builder>
        where
            Builder: OctetsBuilder + AsMut<[u8]>,
        {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer.deserialize_str(ReadableVisitor(self.0))
                } else {
                    deserializer.deserialize_bytes(BinaryVisitor(self.0))
                }
            }
        }

        // Visitor for a human readable inner value
        struct ReadableVisitor<'a, Builder>(
            DeserializeCharStrSeed<'a, Builder>,
        );

        impl<'de, 'a, Builder> serde::de::Visitor<'de>
            for ReadableVisitor<'a, Builder>
        where
            Builder: OctetsBuilder + AsMut<[u8]>,
        {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> Result<Self::Value, E> {
                // Append a placeholder for the length octet, remember its
                // index.
                let start = self.0.builder.as_mut().len();
                self.0
                    .builder
                    .append_slice(&[0])
                    .map_err(|_| E::custom(ShortBuf))?;

                // Decode and append the string.
                let len = CharStr::append_from_str(value, self.0.builder)
                    .map_err(E::custom)?;

                // Update the length octet.
                self.0.builder.as_mut()[start] = len;
                Ok(())
            }
        }

        // Visitor for a binary inner value
        struct BinaryVisitor<'a, Builder>(
            DeserializeCharStrSeed<'a, Builder>,
        );

        impl<'de, 'a, Builder> serde::de::Visitor<'de> for BinaryVisitor<'a, Builder>
        where
            Builder: OctetsBuilder,
        {
            type Value = ();

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_bytes<E: serde::de::Error>(
                self,
                value: &[u8],
            ) -> Result<Self::Value, E> {
                CharStr::from_slice(value)
                    .map_err(E::custom)?
                    .compose(self.0.builder)
                    .map_err(|_| E::custom(ShortBuf))
            }
        }

        deserializer
            .deserialize_newtype_struct("CharStr", NewtypeVisitor(self))
    }
}

//============ Error Types ===================================================

//------------ CharStrError --------------------------------------------------

/// A byte sequence does not represent a valid character string.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CharStrError;

impl fmt::Display for CharStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("long character string")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CharStrError {}

//------------ FromStrError --------------------------------------------

/// An error happened when converting a Rust string to a DNS character string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FromStrError {
    /// A character string has more than 255 octets.
    LongString,

    SymbolChars(SymbolCharsError),

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    BadSymbol(BadSymbol),

    /// The octet builder’s buffer was too short for the data.
    ShortBuf,
}

//--- From

impl From<SymbolCharsError> for FromStrError {
    fn from(err: SymbolCharsError) -> FromStrError {
        FromStrError::SymbolChars(err)
    }
}

impl From<BadSymbol> for FromStrError {
    fn from(err: BadSymbol) -> FromStrError {
        FromStrError::BadSymbol(err)
    }
}

impl From<ShortBuf> for FromStrError {
    fn from(_: ShortBuf) -> FromStrError {
        FromStrError::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FromStrError::LongString => {
                f.write_str("character string with more than 255 octets")
            }
            FromStrError::SymbolChars(ref err) => err.fmt(f),
            FromStrError::BadSymbol(ref err) => err.fmt(f),
            FromStrError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use octseq::builder::infallible;
    use std::vec::Vec;

    type CharStrRef<'a> = CharStr<&'a [u8]>;

    #[test]
    fn from_slice() {
        assert_eq!(
            CharStr::from_slice(b"01234").unwrap().as_slice(),
            b"01234"
        );
        assert_eq!(CharStr::from_slice(b"").unwrap().as_slice(), b"");
        assert!(CharStr::from_slice(&vec![0; 255]).is_ok());
        assert!(CharStr::from_slice(&vec![0; 256]).is_err());
    }

    #[test]
    fn from_octets() {
        assert_eq!(
            CharStr::from_octets("01234").unwrap().as_slice(),
            b"01234"
        );
        assert_eq!(CharStr::from_octets("").unwrap().as_slice(), b"");
        assert!(CharStr::from_octets(vec![0; 255]).is_ok());
        assert!(CharStr::from_octets(vec![0; 256]).is_err());
    }

    #[test]
    fn from_str() {
        use std::str::{from_utf8, FromStr};

        type Cs = CharStr<Vec<u8>>;

        assert_eq!(Cs::from_str("foo").unwrap().as_slice(), b"foo");
        assert_eq!(Cs::from_str("f\\oo").unwrap().as_slice(), b"foo");
        assert_eq!(Cs::from_str("foo\\112").unwrap().as_slice(), b"foo\x70");
        assert_eq!(
            Cs::from_str("\"foo\\\"2\"").unwrap().as_slice(),
            b"\"foo\"2\""
        );
        assert_eq!(Cs::from_str("06 dii").unwrap().as_slice(), b"06 dii");
        assert!(Cs::from_str("0\\").is_err());
        assert!(Cs::from_str("0\\2").is_err());
        assert!(Cs::from_str("0\\2a").is_err());
        assert!(Cs::from_str("ö").is_err());
        assert!(Cs::from_str("\x06").is_err());
        assert!(Cs::from_str(from_utf8(&[b'a'; 256]).unwrap()).is_err());
    }

    #[test]
    fn parse() {
        let mut parser = Parser::from_static(b"12\x03foo\x02bartail");
        parser.advance(2).unwrap();
        let foo = CharStrRef::parse(&mut parser).unwrap();
        let bar = CharStrRef::parse(&mut parser).unwrap();
        assert_eq!(foo.as_slice(), b"foo");
        assert_eq!(bar.as_slice(), b"ba");
        assert_eq!(parser.peek_all(), b"rtail");

        assert!(
            CharStrRef::parse(&mut Parser::from_static(b"\x04foo")).is_err(),
        )
    }

    #[test]
    fn compose() {
        let mut target = Vec::new();
        let val = CharStr::from_slice(b"foo").unwrap();
        infallible(val.compose(&mut target));
        assert_eq!(target, b"\x03foo".as_ref());

        let mut target = Vec::new();
        let val = CharStr::from_slice(b"").unwrap();
        infallible(val.compose(&mut target));
        assert_eq!(target, &b"\x00"[..]);
    }

    fn are_eq(l: &[u8], r: &[u8]) -> bool {
        CharStr::from_slice(l).unwrap() == CharStr::from_slice(r).unwrap()
    }

    #[test]
    fn eq() {
        assert!(are_eq(b"abc", b"abc"));
        assert!(!are_eq(b"abc", b"def"));
        assert!(!are_eq(b"abc", b"ab"));
        assert!(!are_eq(b"abc", b"abcd"));
        assert!(are_eq(b"ABC", b"abc"));
        assert!(!are_eq(b"ABC", b"def"));
        assert!(!are_eq(b"ABC", b"ab"));
        assert!(!are_eq(b"ABC", b"abcd"));
        assert!(are_eq(b"", b""));
        assert!(!are_eq(b"", b"A"));
    }

    fn is_ord(l: &[u8], r: &[u8], order: cmp::Ordering) {
        assert_eq!(
            CharStr::from_slice(l)
                .unwrap()
                .cmp(CharStr::from_slice(r).unwrap()),
            order
        )
    }

    #[test]
    fn ord() {
        use std::cmp::Ordering::*;

        is_ord(b"abc", b"ABC", Equal);
        is_ord(b"abc", b"a", Greater);
        is_ord(b"abc", b"A", Greater);
        is_ord(b"a", b"BC", Less);
    }

    #[test]
    fn append_slice() {
        let mut o = CharStrBuilder::new_vec();
        o.append_slice(b"foo").unwrap();
        assert_eq!(o.finish().as_slice(), b"foo");

        let mut o = CharStrBuilder::from_builder(vec![0; 254]).unwrap();
        o.append_slice(b"f").unwrap();
        assert_eq!(o.len(), 255);
        assert!(o.append_slice(b"f").is_err());

        let mut o =
            CharStrBuilder::from_builder(vec![b'f', b'o', b'o']).unwrap();
        o.append_slice(b"bar").unwrap();
        assert_eq!(o.as_ref(), b"foobar");
        assert!(o.append_slice(&[0u8; 250][..]).is_err());
        o.append_slice(&[0u8; 249][..]).unwrap();
        assert_eq!(o.len(), 255);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        assert_tokens(
            &CharStr::from_octets(Vec::from(b"fo\x12 bar".as_ref()))
                .unwrap()
                .compact(),
            &[
                Token::NewtypeStruct { name: "CharStr" },
                Token::ByteBuf(b"fo\x12 bar"),
            ],
        );

        assert_tokens(
            &CharStr::from_octets(Vec::from(b"fo\x12 bar".as_ref()))
                .unwrap()
                .readable(),
            &[
                Token::NewtypeStruct { name: "CharStr" },
                Token::Str("fo\\018 bar"),
            ],
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn cycle_serde_json() {
        let json = r#""foo bar\" \\018;""#;

        let cstr: CharStr<Vec<u8>> = serde_json::from_str(json).unwrap();
        assert_eq!(cstr.as_slice(), b"foo bar\" \x12;");
        assert_eq!(serde_json::to_string(&cstr).unwrap(), json);
    }

    #[test]
    fn display() {
        fn cmp(input: &[u8], normal: &str, quoted: &str, unquoted: &str) {
            let s = CharStr::from_octets(input).unwrap();
            assert_eq!(format!("{}", s), normal);
            assert_eq!(format!("{}", s.display_quoted()), quoted);
            assert_eq!(format!("{}", s.display_unquoted()), unquoted);
        }

        cmp(br#"foo"#, r#"foo"#, r#""foo""#, r#"foo"#);
        cmp(br#"f oo"#, r#"f oo"#, r#""f oo""#, r#"f\ oo"#);
        cmp(br#"f"oo"#, r#"f"oo"#, r#""f\"oo""#, r#"f\"oo"#);
        cmp(br#"f\oo"#, r#"f\\oo"#, r#""f\\oo""#, r#"f\\oo"#);
        cmp(br#"f;oo"#, r#"f;oo"#, r#""f;oo""#, r#"f\;oo"#);
        cmp(b"f\noo", r#"f\010oo"#, r#""f\010oo""#, r#"f\010oo"#);
    }
}
