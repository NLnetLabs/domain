//! Record data for the TXT record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::charstr::CharStr;
#[cfg(feature = "serde")]
use crate::base::charstr::DeserializeCharStrSeed;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::scan::Scanner;
#[cfg(feature = "serde")]
use crate::base::scan::Symbol;
use crate::base::show::{self, Presenter, Show};
use crate::base::wire::{Composer, FormError, ParseError};
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::cmp::Ordering;
use core::convert::{Infallible, TryFrom};
use core::{fmt, hash, mem, str};
use octseq::builder::{
    infallible, EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder,
    ShortBuf,
};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};

//------------ Txt ----------------------------------------------------------

/// TXT record data.
///
/// TXT records hold descriptive text. While it may appear as a single text,
/// it internally consists of a sequence of one or more
/// [character strings][CharStr]. The type holds this sequence in its encoded
/// form, i.e., each character string is at most 255 octets long and preceded
/// by an octet with its length.
///
/// The type provides means to iterate over these strings, either as
/// [`CharStr`s][CharStr] via [`iter_charstrs`][Self::iter_charstrs] or
/// as plain octets slices via [`iter`][Self::iter]. There is a short cut for
/// the most common case of there being exactly one character string in
/// [`as_flat_slice`][Self::as_flat_slice]. Finally, the two methods
/// [`text`][Self::text] and [`try_text`][Self::try_text] allow combining the
/// content into one single octets sequence.
///
/// The TXT record type is defined in [RFC 1035, section 3.3.14].
///
/// # Presentation format
///
/// TXT record data appears in zone files as the white-space delimited
/// sequence of its constituent [character strings][CharStr]. This means that
/// if these strings are not quoted, each “word” results in a character string
/// of its own. Thus, the quoted form of the character string’s presentation
/// format is preferred.
///
/// # `Display`
///
/// The `Display` implementation prints the sequence of character strings in
/// their quoted presentation format separated by a single space.
///
/// # Serde support
///
/// When the `serde` feature is enabled, the type supports serialization and
/// deserialization. The format differs for human readable and compact
/// serialization formats.
///
/// For human-readable formats, the type serializes into a newtype `Txt`
/// wrapping a sequence of serialized [`CharStr`]s. The deserializer supports
/// a non-canonical form as a single string instead of the sequence. In this
/// case the string is broken up into chunks of 255 octets if it is longer.
/// However, not all format implementations support alternative
/// deserialization based on the encountered type. In particular,
/// _serde-json_ doesn’t, so it will only accept sequences.
///
/// For compact formats, the type serializes as a newtype `Txt` that contains
/// a byte array of the wire format representation of the content.
///
/// [RFC 1035, section 3.3.14]: https://tools.ietf.org/html/rfc1035#section-3.3.14
#[derive(Clone)]
#[repr(transparent)]
pub struct Txt<Octs: ?Sized>(Octs);

impl Txt<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::TXT;
}

impl<Octs: FromBuilder> Txt<Octs> {
    /// Creates a new Txt record from a single slice.
    ///
    /// If the slice is longer than 255 octets, it will be broken up into
    /// multiple character strings where all but the last string will be
    /// 255 octets long.
    ///
    /// If the slice is longer than 65,535 octets or longer than what fits
    /// into the octets type used, an error is returned.
    pub fn build_from_slice(text: &[u8]) -> Result<Self, TxtAppendError>
    where
        <Octs as FromBuilder>::Builder:
            EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut builder = TxtBuilder::<Octs::Builder>::new();
        builder.append_slice(text)?;
        builder.finish().map_err(Into::into)
    }
}

impl<Octs> Txt<Octs> {
    /// Creates new TXT record data from its encoded content.
    ///
    /// The `octets` sequence most contain correctly encoded TXT record
    /// data. That is, it must contain a sequence of at least one character
    /// string of at most 255 octets each preceded by a length octet. An
    /// empty sequence is not allowed.
    ///
    /// Returns an error if `octets` does not contain correctly encoded TXT
    /// record data.
    pub fn from_octets(octets: Octs) -> Result<Self, TxtError>
    where
        Octs: AsRef<[u8]>,
    {
        Txt::check_slice(octets.as_ref())?;
        Ok(unsafe { Txt::from_octets_unchecked(octets) })
    }

    /// Creates new TXT record data without checking.
    ///
    /// # Safety
    ///
    /// The passed octets must contain correctly encoded TXT record data.
    /// See [`from_octets][Self::from_octets] for the required content.
    unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Txt(octets)
    }
}

impl Txt<[u8]> {
    /// Creates new TXT record data on an octets slice.
    ///
    /// The slice must contain correctly encoded TXT record data,
    /// that is a sequence of encoded character strings. See
    pub fn from_slice(slice: &[u8]) -> Result<&Self, TxtError> {
        Txt::check_slice(slice)?;
        Ok(unsafe { Txt::from_slice_unchecked(slice) })
    }

    /// Creates new TXT record data on an octets slice without checking.
    ///
    /// # Safety
    ///
    /// The passed octets must contain correctly encoded TXT record data.
    /// See [`from_octets][Self::from_octets] for the required content.
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: Txt has repr(transparent)
        mem::transmute(slice)
    }

    /// Checks that a slice contains correctly encoded TXT data.
    fn check_slice(mut slice: &[u8]) -> Result<(), TxtError> {
        if slice.is_empty() {
            return Err(TxtError(TxtErrorInner::Empty))
        }
        LongRecordData::check_len(slice.len())?;
        while let Some(&len) = slice.first() {
            let len = usize::from(len);
            if slice.len() <= len {
                return Err(TxtError(TxtErrorInner::ShortInput));
            }
            slice = &slice[len + 1..];
        }
        Ok(())
    }
}

impl<Octs> Txt<Octs> {
    /// Parses TXT record data from the beginning of a parser.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError>
    where
        Octs: AsRef<[u8]>,
    {
        let len = parser.remaining();
        let text = parser.parse_octets(len)?;
        let mut tmp = Parser::from_ref(text.as_ref());
        while tmp.remaining() != 0 {
            CharStr::skip(&mut tmp)?
        }
        Ok(Txt(text))
    }

    /// Scans TXT record data.
    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_charstr_entry().map(Txt)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Txt<Octs> {
    /// Returns an iterator over the character strings as slices.
    ///
    /// The returned iterator will always return at least one octets slice.
    pub fn iter(&self) -> TxtIter {
        TxtIter(self.iter_charstrs())
    }

    /// Returns an iterator over the character strings.
    ///
    /// The returned iterator will always return at least one octets slice.
    pub fn iter_charstrs(&self) -> TxtCharStrIter {
        TxtCharStrIter(Parser::from_ref(self.0.as_ref()))
    }

    /// Returns the content if it consists of a single character string.
    pub fn as_flat_slice(&self) -> Option<&[u8]> {
        if usize::from(self.0.as_ref()[0]) == self.0.as_ref().len() - 1 {
            Some(&self.0.as_ref()[1..])
        } else {
            None
        }
    }

    /// Returns the length of the TXT record data.
    ///
    /// Note that this is the length of the encoded record data and therefore
    /// never the length of the text, not even if there is only a single
    /// character string – it is still preceded by a length octet.
    ///
    /// Note further that TXT record data is not allowed to be empty, so there
    /// is no `is_empty` method.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// Returns the text content.
    ///
    /// The method appends the content of each character string to a newly
    /// created octets builder. It does not add any delimiters between the
    /// character string.
    ///
    /// If your octets builder is not space limited, you can use
    /// [`text`][Self::text] instead.
    pub fn try_text<T: FromBuilder>(
        &self,
    ) -> Result<T, <<T as FromBuilder>::Builder as OctetsBuilder>::AppendError>
    where
        <T as FromBuilder>::Builder: EmptyBuilder,
    {
        // Capacity will be a few bytes too much. Probably better than
        // re-allocating.
        let mut res = T::Builder::with_capacity(self.len());
        for item in self.iter() {
            res.append_slice(item)?;
        }
        Ok(res.freeze())
    }

    /// Returns the text content.
    ///
    /// The method appends the content of each character string to a newly
    /// created octets builder. It does not add any delimiters between the
    /// character string.
    ///
    /// This method is only available for octets builder types that are not
    /// space limited. You can use [`try_text`][Self::try_text] with all
    /// builder types.
    pub fn text<T: FromBuilder>(&self) -> T
    where
        <T as FromBuilder>::Builder: EmptyBuilder,
        <<T as FromBuilder>::Builder as OctetsBuilder>::AppendError:
            Into<Infallible>,
    {
        infallible(self.try_text())
    }
}

impl<SrcOcts> Txt<SrcOcts> {
    /// Converts the octets type.
    ///
    /// This is used by the macros that create enum types.
    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<SrcOcts>>(
        self,
    ) -> Result<Txt<Target>, Target::Error> {
        Ok(Txt(self.0.try_octets_into()?))
    }

    /// Flattens the contents.
    ///
    /// This is used by the macros that create enum types.
    pub(in crate::rdata) fn flatten<Octs: OctetsFrom<SrcOcts>>(
        self,
    ) -> Result<Txt<Octs>, Octs::Error> {
        self.convert_octets()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Txt<SrcOcts>> for Txt<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Txt<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0).map(Self)
    }
}

//--- IntoIterator

impl<'a, Octs: AsRef<[u8]>> IntoIterator for &'a Txt<Octs> {
    type Item = &'a [u8];
    type IntoIter = TxtIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Txt<Other>) -> bool {
        self.0.as_ref().eq(other.0.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for Txt<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Txt<Other>) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.0.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Txt<Other>> for Txt<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Txt<Other>) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for Txt<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Txt<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Txt<Octs> {
    fn rtype(&self) -> Rtype {
        Txt::RTYPE
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Txt<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Txt::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Txt<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(u16::try_from(self.0.as_ref().len()).expect("long TXT rdata"))
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Txt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for slice in self.iter_charstrs() {
            if !first {
                f.write_str(" ")?;
            }
            else {
                first = false;
            }
            write!(f, "{}", slice.display_quoted())?;
        }
        Ok(())
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Txt<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Txt(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//--- Show

impl<Octs: AsRef<[u8]>> Show for Txt<Octs> {
    fn show(&self, p: &mut Presenter) -> show::Result {
        let mut block = p.block();
        for slice in self.iter_charstrs() {
            block.write_token(slice.display_quoted());
        }
        block.finish()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octs> serde::Serialize for Txt<Octs>
where
    Octs: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;

        struct TxtSeq<'a, Octs>(&'a Txt<Octs>);

        impl<'a, Octs> serde::Serialize for TxtSeq<'a, Octs>
        where
            Octs: AsRef<[u8]> + SerializeOctets,
        {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let mut serializer = serializer.serialize_seq(None)?;
                for item in self.0.iter_charstrs() {
                    serializer.serialize_element(item)?;
                }
                serializer.end()
            }
        }

        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct("Txt", &TxtSeq(self))
        }
        else {
            serializer.serialize_newtype_struct(
                "Txt",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octs> serde::Deserialize<'de> for Txt<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
        {
            type Value = Txt<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer.deserialize_seq(ReadableVisitor(PhantomData))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        CompactVisitor(Octs::visitor()),
                    )
                }
            }
        }

        struct ReadableVisitor<Octs>(PhantomData<Octs>);

        impl<'de, Octs> serde::de::Visitor<'de> for ReadableVisitor<Octs>
        where
            Octs: FromBuilder,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
        {
            type Value = Txt<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                // This is a non-canonical serialization. We accept strings
                // of any length and break them down into chunks.
                let mut builder =
                    TxtBuilder::<<Octs as FromBuilder>::Builder>::new();
                let mut chars = v.chars();
                while let Some(ch) =
                    Symbol::from_chars(&mut chars).map_err(E::custom)?
                {
                    builder
                        .append_u8(ch.into_octet().map_err(E::custom)?)
                        .map_err(E::custom)?;
                }
                builder.finish().map_err(E::custom)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut builder = <Octs as FromBuilder>::Builder::empty();
                while seq.next_element_seed(
                    DeserializeCharStrSeed::new(&mut builder)
                )?.is_some() {
                    LongRecordData::check_len(
                        builder.as_ref().len()
                    ).map_err(serde::de::Error::custom)?;
                }
                if builder.as_ref().is_empty() {
                    builder.append_slice(b"\0").map_err(|_| {
                        serde::de::Error::custom(ShortBuf)
                    })?;
                }
                Ok(Txt(builder.freeze()))
            }
        }

        struct CompactVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for CompactVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
        {
            type Value = Txt<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TXT record data")
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    Txt::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    Txt::from_octets(octets).map_err(E::custom)
                })
            }
        }

        deserializer.deserialize_newtype_struct(
            "Txt", NewtypeVisitor(PhantomData)
        )
    }
}

//------------ TxtCharStrIter ------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone)]
pub struct TxtCharStrIter<'a>(Parser<'a, [u8]>);

impl<'a> Iterator for TxtCharStrIter<'a> {
    type Item = &'a CharStr<[u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining() == 0 {
            None
        } else {
            Some(CharStr::parse_slice(&mut self.0).unwrap())
        }
    }
}

//------------ TxtIter -------------------------------------------------------

/// An iterator over the character strings of a Txt record.
#[derive(Clone)]
pub struct TxtIter<'a>(TxtCharStrIter<'a>);

impl<'a> Iterator for TxtIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(CharStr::as_slice)
    }
}

//------------ TxtBuilder ---------------------------------------------------

/// Iteratively build TXT record data.
///
/// This type allows building TXT record data by starting with empty data
/// and appending either complete character strings or slices of data.
#[derive(Clone, Debug)]
pub struct TxtBuilder<Builder> {
    /// The underlying builder.
    builder: Builder,

    /// The index of the start of the current char string.
    ///
    /// If this is `None`, there currently is no char string being worked on.
    start: Option<usize>,
}

impl<Builder: OctetsBuilder + EmptyBuilder> TxtBuilder<Builder> {
    /// Creates a new, empty TXT builder.
    #[must_use]
    pub fn new() -> Self {
        TxtBuilder {
            builder: Builder::empty(),
            start: None,
        }
    }
}

#[cfg(feature = "bytes")]
impl TxtBuilder<BytesMut> {
    /// Creates a new, empty TXT builder using `BytesMut`.
    pub fn new_bytes() -> Self {
        Self::new()
    }
}

impl<Builder: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>> TxtBuilder<Builder> {
    /// Tries appending a slice.
    ///
    /// Errors out if either appending the slice would result in exceeding the
    /// record data length limit or the underlying builder runs out of space.
    fn builder_append_slice(
        &mut self, slice: &[u8]
    ) -> Result<(), TxtAppendError> {
        LongRecordData::check_append_len(
            self.builder.as_ref().len(), slice.len()
        )?;
        self.builder.append_slice(slice)?;
        Ok(())
    }

    /// Appends a slice to the builder.
    ///
    /// The method breaks up the slice into individual octets strings if
    /// necessary. If a previous call has started a new octets string, it
    /// fills this one up first before creating a new one. Thus, by using
    /// this method only, the resulting TXT record data will consist of
    /// character strings where all but the last one are 255 octets long.
    ///
    /// You can force a character string break by calling
    /// [`close_charstr`][Self::close_charstr].
    ///
    /// The method will return an error if appending the slice would result
    /// in exceeding the record data length limit or the underlying builder
    /// runs out of space. In this case, the method may have appended some
    /// data already. I.e., you should consider the builder corrupt if the
    /// method returns an error.
    pub fn append_slice(
        &mut self, mut slice: &[u8]
    ) -> Result<(), TxtAppendError> {
        if let Some(start) = self.start {
            let left = 255 - (self.builder.as_ref().len() - (start + 1));
            if slice.len() < left {
                self.builder_append_slice(slice)?;
                return Ok(());
            }
            let (append, left) = slice.split_at(left);
            self.builder_append_slice(append)?;
            self.builder.as_mut()[start] = 255;
            slice = left;
        }
        for chunk in slice.chunks(255) {
            // Remember offset of this incomplete chunk
            self.start = if chunk.len() == 255 {
                None
            } else {
                Some(self.builder.as_ref().len())
            };
            self.builder_append_slice(&[chunk.len() as u8])?;
            self.builder_append_slice(chunk)?;
        }
        Ok(())
    }

    /// Appends a single octet.
    ///
    /// This method calls [`append_slice`][Self::append_slice], so all the
    /// caveats described there apply.
    pub fn append_u8(&mut self, ch: u8) -> Result<(), TxtAppendError> {
        self.append_slice(&[ch])
    }

    /// Appends a complete character string.
    ///
    /// If a character string had previously been started by a call to
    /// [`append_slice`][Self::append_slice], this string is closed before
    /// appending the provided character string.
    ///
    /// The method will return an error if appending the slice would result
    /// in exceeding the record data length limit or the underlying builder
    /// runs out of space. In this case, the method may have appended some
    /// data already. I.e., you should consider the builder corrupt if the
    /// method returns an error.
    pub fn append_charstr<Octs: AsRef<[u8]> + ?Sized>(
        &mut self, s: &CharStr<Octs>
    ) -> Result<(), TxtAppendError> {
        self.close_charstr();
        LongRecordData::check_append_len(
            self.builder.as_ref().len(),
            usize::from(s.compose_len())
        )?;
        s.compose(&mut self.builder)?;
        Ok(())
    }

    /// Ends a character string.
    ///
    /// If a previous call to [`append_slice`][Self::append_slice] started a
    /// new character string, a call to this method will close it.
    pub fn close_charstr(&mut self) {
        if let Some(start) = self.start {
            let last_slice_len = self.builder.as_ref().len() - (start + 1);
            self.builder.as_mut()[start] = last_slice_len as u8;
            self.start = None;
        }
    }

    /// Finishes the builder and returns TXT record data.
    ///
    /// If the builder is empty, appends an empty character string before
    /// returning. If that fails because the builder does not have enough
    /// space, returns an error.
    pub fn finish(mut self) -> Result<Txt<Builder::Octets>, TxtAppendError>
    where
        Builder: FreezeBuilder,
    {
        self.close_charstr();
        if self.builder.as_ref().is_empty() {
            self.builder.append_slice(b"\0")?;
        }
        Ok(Txt(self.builder.freeze()))
    }
}

impl<Builder: OctetsBuilder + EmptyBuilder> Default for TxtBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//============ Error Types ===================================================

//------------ TxtError ------------------------------------------------------

/// An octets sequence does not form valid TXT record data.
#[derive(Clone, Copy, Debug)]
pub struct TxtError(TxtErrorInner);

#[derive(Clone, Copy, Debug)]
enum TxtErrorInner {
    Empty,
    Long(LongRecordData),
    ShortInput,
}

impl TxtError {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self.0 {
            TxtErrorInner::Empty => "empty TXT record",
            TxtErrorInner::Long(err) => err.as_str(),
            TxtErrorInner::ShortInput => "short input",
        }
    }
}

impl From<LongRecordData> for TxtError {
    fn from(err: LongRecordData) -> TxtError {
        TxtError(TxtErrorInner::Long(err))
    }
}

impl From<TxtError> for FormError {
    fn from(err: TxtError) -> FormError {
        FormError::new(err.as_str())
    }
}

impl fmt::Display for TxtError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//------------ TxtAppendError ------------------------------------------------

/// An error occurred while append to TXT record data.
#[derive(Clone, Copy, Debug)]
pub enum TxtAppendError {
    /// Appending would have caused the record data to be too long.
    LongRecordData,

    /// The octets builder did not have enough space.
    ShortBuf
}

impl TxtAppendError {
    /// Returns a static string with the error reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TxtAppendError::LongRecordData => "record data too long",
            TxtAppendError::ShortBuf => "buffer size exceeded"
        }
    }
}

impl From<LongRecordData> for TxtAppendError {
    fn from(_: LongRecordData) -> TxtAppendError {
        TxtAppendError::LongRecordData
    }
}

impl<T: Into<ShortBuf>> From<T> for TxtAppendError {
    fn from(_: T) -> TxtAppendError {
        TxtAppendError::ShortBuf
    }
}

impl fmt::Display for TxtAppendError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use std::vec::Vec;



    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn txt_compose_parse_scan() {
        let rdata = Txt::from_octets(b"\x03foo\x03bar".as_ref()).unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Txt::parse(parser));
        test_scan(&["foo", "bar"], Txt::scan, &rdata);
    }

    #[test]
    fn txt_from_slice() {
        assert!(Txt::from_octets(b"").is_err());

        let short = b"01234";
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(short).unwrap();
        assert_eq!(Some(&short[..]), txt.as_flat_slice());
        assert_eq!(short.to_vec(), txt.text::<Vec<u8>>());

        // One full slice
        let full = short.repeat(51);
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(&full).unwrap();
        assert_eq!(Some(&full[..]), txt.as_flat_slice());
        assert_eq!(full.to_vec(), txt.text::<Vec<u8>>());

        // Two slices: 255, 5
        let long = short.repeat(52);
        let txt: Txt<Vec<u8>> = Txt::build_from_slice(&long).unwrap();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(long.to_vec(), txt.text::<Vec<u8>>());

        // Partial
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        for chunk in long.chunks(9) {
            builder.append_slice(chunk).unwrap();
        }
        let txt = builder.finish().unwrap();
        assert_eq!(None, txt.as_flat_slice());
        assert_eq!(long.to_vec(), txt.text::<Vec<u8>>());

        // Empty
        let builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        let txt = builder.finish().unwrap();
        assert_eq!(Some(b"".as_ref()), txt.as_flat_slice());

        // Empty
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        builder.append_slice(b"").unwrap();
        let txt = builder.finish().unwrap();
        assert_eq!(Some(b"".as_ref()), txt.as_flat_slice());

        // Invalid
        let mut parser = Parser::from_static(b"\x01");
        assert!(Txt::parse(&mut parser).is_err());

        // Too long
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        assert!(builder
            .append_slice(&b"\x00".repeat(u16::MAX as usize))
            .is_err());

        // Incremental, reserve space for offsets
        let mut builder: TxtBuilder<Vec<u8>> = TxtBuilder::new();
        assert!(builder
            .append_slice(&b"\x00".repeat(u16::MAX as usize - 512))
            .is_ok());
        assert!(builder.append_slice(&b"\x00".repeat(512)).is_err());
    }

    #[test]
    fn txt_canonical_compare() {
        let data = [
            "mailru-verification: 14505c6eb222c847",
            "yandex-verification: 6059b187e78de544",
            "v=spf1 include:_spf.protonmail.ch ~all",
            "swisssign-check=CF0JHMTlTDNoES3rrknIRggocffSwqmzMb9X8YbjzK",
            "google-site-\
                verification=aq9zJnp3H3bNE0Y4D4rH5I5Dhj8VMaLYx0uQ7Rozfgg",
            "ahrefs-site-verification_\
                4bdac6bbaa81e0d591d7c0f3ef238905c0521b69bf3d74e64d3775bc\
                b2743afd",
            "brave-ledger-verification=\
                66a7f27fb99949cc0c564ab98efcc58ea1bac3e97eb557c782ab2d44b\
                49aefd7",
        ];

        let records = data
            .iter()
            .map(|e| {
                let mut builder = TxtBuilder::<Vec<u8>>::new();
                builder.append_slice(e.as_bytes()).unwrap();
                builder.finish().unwrap()
            })
            .collect::<Vec<_>>();

        // The canonical sort must sort by TXT labels which are prefixed by
        // length byte first.
        let mut sorted = records.clone();
        sorted.sort_by(|a, b| a.canonical_cmp(b));

        for (a, b) in records.iter().zip(sorted.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn txt_strings_eq() {
        let records = [["foo", "bar"], ["foob", "ar"], ["foo", "bar"]];

        let records = records
            .iter()
            .map(|strings| {
                let mut builder = TxtBuilder::<Vec<u8>>::new();
                for string in strings {
                    builder
                        .append_charstr(
                            CharStr::from_slice(string.as_bytes()).unwrap(),
                        )
                        .unwrap();
                }
                builder.finish().unwrap()
            })
            .collect::<Vec<_>>();

        assert_ne!(records[0], records[1]);
        assert_eq!(records[0], records[2]);
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn txt_ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let txt = Txt::from_octets(Vec::from(b"\x03foo".as_ref())).unwrap();
        assert_tokens(
            &txt.clone().compact(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::ByteBuf(b"\x03foo"),
            ],
        );
        assert_tokens(
            &txt.readable(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::Seq { len: None },
                Token::NewtypeStruct { name: "CharStr" },
                Token::BorrowedStr("foo"),
                Token::SeqEnd,
            ],
        );

        let txt = Txt::from_octets(
            Vec::from(b"\x03foo\x04\\bar".as_ref())
        ).unwrap();
        assert_tokens(
            &txt.clone().compact(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::ByteBuf(b"\x03foo\x04\\bar"),
            ],
        );
        assert_tokens(
            &txt.readable(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::Seq { len: None },
                Token::NewtypeStruct { name: "CharStr" },
                Token::BorrowedStr("foo"),
                Token::NewtypeStruct { name: "CharStr" },
                Token::BorrowedStr("\\\\bar"),
                Token::SeqEnd,
            ],
        );
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn txt_de_str() {
        use serde_test::{assert_de_tokens, Configure, Token};

        assert_de_tokens(
            &Txt::from_octets(Vec::from(b"\x03foo".as_ref()))
                .unwrap()
                .readable(),
            &[
                Token::NewtypeStruct { name: "Txt" },
                Token::BorrowedStr("foo"),
            ],
        );
    }

    #[test]
    fn txt_display() {
        fn cmp(input: &[u8], output: &str) {
            assert_eq!(
                format!("{}", Txt::from_octets(input).unwrap()),
                output
            );
        }

        cmp(b"\x03foo", "\"foo\"");
        cmp(b"\x03foo\x03bar", "\"foo\" \"bar\"");
        cmp(b"\x03fo\"\x04bar ", "\"fo\\\"\" \"bar \"");
        // I don’t think we need more escaping tests since the impl defers
        // to CharStr::display_quoted which is tested ...
    }
}

