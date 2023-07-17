//! Parsed domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! module.

use super::super::cmp::CanonicalOrd;
use super::super::wire::{FormError, ParseError};
use super::dname::Dname;
use super::label::{Label, LabelTypeError};
use super::relative::RelativeDname;
use super::traits::{FlattenInto, ToDname, ToLabelIter};
use core::{cmp, fmt, hash};
use octseq::builder::{
    BuilderAppendError, EmptyBuilder, FreezeBuilder, FromBuilder,
    OctetsBuilder,
};
use octseq::octets::Octets;
use octseq::parse::Parser;

//------------ ParsedDname ---------------------------------------------------

/// A domain name parsed from a DNS message.
///
/// In an attempt to keep messages small, DNS uses a procedure called ‘name
/// compression.’ It tries to minimize the space used for repeatedly
/// appearing domain names by simply refering to the first occurence of the
/// name. This works not only for complete names but also for suffixes. In
/// this case, the first unique labels of the name are included and then a
/// pointer is included for the remainder of the name.
///
/// A consequence of this is that when parsing a domain name, its labels can
/// be scattered all over the message and we would need to allocate some
/// space to re-assemble the original name. However, in many cases we don’t
/// need the complete name. Many operations can be performed by just
/// iterating over the labels which we can do in place.
///
/// `ParsedDname` deals with such names. It takes a copy of a [`Parser`]
/// representing a reference to the underlying DNS message and, if nedded,
/// traverses over the name starting at the current position of the parser.
/// When being created, the type quickly walks over the name to check that it
/// is, indeed, a valid name. While this does take a bit of time, it spares
/// you having to deal with possible parse errors later on.
///
/// `ParsedDname` implementes the [`ToDname`] trait, so you can use it
/// everywhere where a generic absolute domain name is accepted. In
/// particular, you can compare it to other names or chain it to the end of a
/// relative name. If necessary, [`ToDname::to_name`] can be used to produce
/// a flat, self-contained [`Dname`].
///
/// [`Dname`]: struct.Dname.html
/// [`Parser`]: ../parse/struct.Parser.html
/// [`ToDname`]: trait.ToDname.html
/// [`ToDname::to_name`]: trait.ToDname.html#method.to_name
#[derive(Clone, Copy)]
pub struct ParsedDname<Octs> {
    /// The octets the name is embedded in.
    ///
    /// This needs to be the full message as compression pointers in the name
    /// are indexes into this sequence.
    octets: Octs,

    /// The start position of the name within `octets`.
    pos: usize,

    /// The length of the uncompressed name in octets.
    ///
    /// We need this for implementing `ToLabelIter`.
    name_len: u16,

    /// Whether the name is compressed.
    ///
    /// This allows various neat optimizations for the case where it isn’t.
    compressed: bool,
}

impl<Octs> ParsedDname<Octs> {
    /// Returns whether the name is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.name_len == 1
    }

    /// Returns a correctly positioned parser.
    fn parser(&self) -> Parser<Octs>
    where
        Octs: AsRef<[u8]>,
    {
        let mut res = Parser::from_ref(&self.octets);
        res.advance(self.pos).expect("illegal pos in ParsedDname");
        res
    }

    /// Returns an equivalent name for a reference to the contained octets.
    pub fn ref_octets(&self) -> ParsedDname<&Octs> {
        ParsedDname {
            octets: &self.octets,
            pos: self.pos,
            name_len: self.name_len,
            compressed: self.compressed,
        }
    }
}

impl<'a, Octs: Octets + ?Sized> ParsedDname<&'a Octs> {
    pub fn deref_octets(&self) -> ParsedDname<Octs::Range<'a>> {
        ParsedDname {
            octets: self.octets.range(..),
            pos: self.pos,
            name_len: self.name_len,
            compressed: self.compressed,
        }
    }
}

/// # Working with Labels
///
impl<Octs: AsRef<[u8]>> ParsedDname<Octs> {
    /// Returns an iterator over the labels of the name.
    pub fn iter(&self) -> ParsedDnameIter {
        ParsedDnameIter::new(self.octets.as_ref(), self.pos, self.name_len)
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> ParsedSuffixIter<Octs> {
        ParsedSuffixIter::new(self)
    }

    /// Returns the number of labels in the domain name.
    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    /// Returns a reference to the first label.
    pub fn first(&self) -> &Label {
        self.iter().next().unwrap()
    }

    /// Returns a reference to the last label.
    ///
    /// Because the last label in an absolute name is always the root label,
    /// this method can return a static reference. It is also a wee bit silly,
    /// but here for completeness.
    pub fn last(&self) -> &'static Label {
        Label::root()
    }

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<N: ToLabelIter>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToLabelIter>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns `None` and does nothing.
    pub fn split_first(&mut self) -> Option<RelativeDname<Octs::Range<'_>>>
    where
        Octs: Octets,
    {
        if self.name_len == 1 {
            return None;
        }
        let mut name_len = self.name_len;
        let range = {
            let mut parser = self.parser();
            let len = loop {
                match LabelType::peek(&mut parser).unwrap() {
                    LabelType::Normal(0) => {
                        unreachable!()
                    }
                    LabelType::Normal(label_len) => break label_len + 1,
                    LabelType::Compressed(pos) => {
                        parser.seek(pos).unwrap();
                    }
                }
            };
            name_len -= len;
            parser.pos()..parser.pos() + usize::from(len)
        };
        self.pos = range.end;
        self.name_len = name_len;
        Some(unsafe {
            RelativeDname::from_octets_unchecked(self.octets.range(range))
        })
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `false` and does
    /// nothing. Otherwise, drops the first label and returns `true`.
    pub fn parent(&mut self) -> bool {
        if self.name_len == 1 {
            return false;
        }
        let (pos, len) = {
            let mut parser = self.parser();
            let len = loop {
                match LabelType::peek(&mut parser).unwrap() {
                    LabelType::Normal(0) => {
                        unreachable!()
                    }
                    LabelType::Normal(label_len) => break label_len + 1,
                    LabelType::Compressed(pos) => {
                        parser.seek(pos).unwrap();
                    }
                }
            };
            (parser.pos() + usize::from(len), len)
        };
        self.name_len -= len;
        self.pos = pos;
        true
    }
}

impl<Octs> ParsedDname<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        ParsedDname::parse_ref(parser).map(|res| res.deref_octets())
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParsedDname<&'a Octs> {
    pub fn parse_ref(
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Self, ParseError> {
        let mut name_len = 0;
        let mut pos = parser.pos();

        // Phase One: No compression pointers have been found yet.
        //
        // Parse labels. If we encounter the root label, return an
        // uncompressed name. Otherwise continue to phase two.
        let mut ptr = loop {
            match LabelType::parse(parser)? {
                LabelType::Normal(0) => {
                    // Root label.
                    name_len += 1;
                    return Ok(ParsedDname {
                        octets: parser.octets_ref(),
                        pos,
                        name_len,
                        compressed: false,
                    });
                }
                LabelType::Normal(label_len) => {
                    parser.advance(usize::from(label_len))?;
                    name_len += label_len + 1;
                    if name_len >= 255 {
                        return Err(ParsedDnameError::LongName.into());
                    }
                }
                LabelType::Compressed(ptr) => {
                    break ptr;
                }
            }
        };

        // Phase Two: Compression has occured.
        //
        // Now we need to add up label lengths until we encounter the root
        // label or the name becomes too long.
        //
        // We are going to work on a temporary parser so we can jump around.
        // The actual parser has already reached the end of the name, so we
        // can just shadow it. (Because parsers are copy, dereferencing them
        // clones them.)
        let mut parser = *parser;
        let mut compressed = true;
        loop {
            // Check that the compression pointer points backwards. Because
            // it is 16 bit long and the current position is behind the label
            // header, it needs to less than the current position minus 2 --
            // less so can’t point to itself.
            if ptr >= parser.pos() - 2 {
                return Err(ParsedDnameError::ExcessiveCompression.into());
            }

            // If this is the first label, the returned name may as well start
            // here.
            if name_len == 0 {
                pos = ptr;
                compressed = false;
            }

            // Reposition and read next label.
            parser.seek(ptr)?;

            loop {
                match LabelType::parse(&mut parser)? {
                    LabelType::Normal(0) => {
                        // Root label.
                        name_len += 1;
                        return Ok(ParsedDname {
                            octets: parser.octets_ref(),
                            pos,
                            name_len,
                            compressed,
                        });
                    }
                    LabelType::Normal(label_len) => {
                        parser.advance(usize::from(label_len))?;
                        name_len += label_len + 1;
                        if name_len >= 255 {
                            return Err(ParsedDnameError::LongName.into());
                        }
                    }
                    LabelType::Compressed(new_ptr) => {
                        ptr = new_ptr;
                        compressed = true;
                        break;
                    }
                }
            }
        }
    }
}

impl ParsedDname<()> {
    /// Skip over a domain name.
    ///
    /// This will only check the uncompressed part of the name. If the name
    /// is compressed but the compression pointer is invalid or the name
    /// pointed to is invalid or too long, the function will still succeed.
    ///
    /// If you need to check that the name you are skipping over is valid, you
    /// will have to use `parse` and drop the result.
    pub fn skip<Src: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Src>,
    ) -> Result<(), ParseError> {
        let mut len = 0;
        loop {
            match LabelType::parse(parser) {
                Ok(LabelType::Normal(0)) => {
                    len += 1;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName.into());
                    }
                    return Ok(());
                }
                Ok(LabelType::Normal(label_len)) => {
                    parser.advance(label_len.into())?;
                    len += label_len + 1;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName.into());
                    }
                }
                Ok(LabelType::Compressed(_)) => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }
}

//--- From

impl<Octs: AsRef<[u8]>> From<Dname<Octs>> for ParsedDname<Octs> {
    fn from(name: Dname<Octs>) -> ParsedDname<Octs> {
        let name_len = name.compose_len();
        ParsedDname {
            octets: name.into_octets(),
            pos: 0,
            name_len,
            compressed: false,
        }
    }
}

//--- FlattenInto

impl<Octs, Target> FlattenInto<Dname<Target>> for ParsedDname<Octs>
where
    Octs: Octets,
    Target: FromBuilder,
    <Target as FromBuilder>::Builder: EmptyBuilder,
{
    type AppendError = BuilderAppendError<Target>;

    fn try_flatten_into(self) -> Result<Dname<Target>, Self::AppendError> {
        let mut builder =
            Target::Builder::with_capacity(self.compose_len().into());
        if let Some(slice) = self.as_flat_slice() {
            builder.append_slice(slice)?;
        } else {
            self.iter_labels()
                .try_for_each(|label| label.compose(&mut builder))?;
        }
        Ok(unsafe { Dname::from_octets_unchecked(builder.freeze()) })
    }
}

//--- PartialEq and Eq

impl<Octs, N> PartialEq<N> for ParsedDname<Octs>
where
    Octs: AsRef<[u8]>,
    N: ToDname + ?Sized,
{
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<Octs: AsRef<[u8]>> Eq for ParsedDname<Octs> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octs, N> PartialOrd<N> for ParsedDname<Octs>
where
    Octs: AsRef<[u8]>,
    N: ToDname + ?Sized,
{
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl<Octs: AsRef<[u8]>> Ord for ParsedDname<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

impl<Octs, N> CanonicalOrd<N> for ParsedDname<Octs>
where
    Octs: AsRef<[u8]>,
    N: ToDname + ?Sized,
{
    fn canonical_cmp(&self, other: &N) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for ParsedDname<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}

//--- ToLabelIter and ToDname

impl<Octs: AsRef<[u8]>> ToLabelIter for ParsedDname<Octs> {
    type LabelIter<'s> = ParsedDnameIter<'s> where Octs: 's;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        self.iter()
    }

    fn compose_len(&self) -> u16 {
        self.name_len
    }
}

impl<Octs: AsRef<[u8]>> ToDname for ParsedDname<Octs> {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        if self.compressed {
            None
        } else {
            Some(
                &self.octets.as_ref()
                    [self.pos..self.pos + usize::from(self.name_len)],
            )
        }
    }
}

//--- IntoIterator

impl<'a, Octs> IntoIterator for &'a ParsedDname<Octs>
where
    Octs: AsRef<[u8]>,
{
    type Item = &'a Label;
    type IntoIter = ParsedDnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for ParsedDname<Octs> {
    /// Formats the domain name.
    ///
    /// This will produce the domain name in common display format without
    /// the trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        write!(f, "{}", iter.next().unwrap())?;
        for label in iter {
            if !label.is_root() {
                write!(f, ".{}", label)?
            }
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for ParsedDname<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ParsedDname({}.)", self)
    }
}

//------------ ParsedDnameIter -----------------------------------------------

/// An iterator over the labels in a parsed domain name.
#[derive(Clone)]
pub struct ParsedDnameIter<'a> {
    slice: &'a [u8],
    pos: usize,
    len: u16,
}

impl<'a> ParsedDnameIter<'a> {
    /// Creates a new iterator from the parser and the name length.
    ///
    /// The parser must be positioned at the beginning of the name.
    pub(crate) fn new(slice: &'a [u8], pos: usize, len: u16) -> Self {
        ParsedDnameIter { slice, pos, len }
    }

    /// Returns the next label.
    ///
    /// This just assumes that there is a label at the current beginning
    /// of the parser. This may lead to funny results if there isn’t,
    /// including panics if the label head is illegal or points beyond the
    /// end of the message.
    fn get_label(&mut self) -> &'a Label {
        let end = loop {
            let ltype = self.slice[self.pos];
            self.pos += 1;
            match ltype {
                0..=0x3F => break self.pos + (ltype as usize),
                0xC0..=0xFF => {
                    self.pos = (self.slice[self.pos] as usize)
                        | (((ltype as usize) & 0x3F) << 8);
                }
                _ => panic!("bad label"),
            }
        };
        let res = unsafe {
            Label::from_slice_unchecked(&self.slice[self.pos..end])
        };
        self.pos = end;
        self.len -= res.compose_len();
        res
    }
}

impl<'a> Iterator for ParsedDnameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None;
        }
        Some(self.get_label())
    }
}

impl<'a> DoubleEndedIterator for ParsedDnameIter<'a> {
    fn next_back(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None;
        }
        let mut tmp = self.clone();
        let label = loop {
            let label = tmp.get_label();
            if tmp.len == 0 {
                break label;
            }
        };
        self.len -= label.compose_len();
        Some(label)
    }
}

//------------ ParsedSuffixIter ----------------------------------------------

/// An iterator over ever shorter suffixes of a parsed domain name.
#[derive(Clone)]
pub struct ParsedSuffixIter<'a, Octs: ?Sized> {
    name: Option<ParsedDname<&'a Octs>>,
}

impl<'a, Octs> ParsedSuffixIter<'a, Octs> {
    /// Creates a new iterator cloning `name`.
    fn new(name: &'a ParsedDname<Octs>) -> Self {
        ParsedSuffixIter {
            name: Some(name.ref_octets()),
        }
    }
}

impl<'a, Octs: Octets + ?Sized> Iterator for ParsedSuffixIter<'a, Octs> {
    type Item = ParsedDname<Octs::Range<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let name = match self.name {
            Some(ref mut name) => name,
            None => return None,
        };
        let res = name.deref_octets();
        if !name.parent() {
            self.name = None
        }
        Some(res)
    }
}

//------------ LabelType -----------------------------------------------------

/// The type of a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LabelType {
    /// A normal label with its size in octets.
    Normal(u16),

    /// A compressed label with the position of where to continue.
    Compressed(usize),
}

impl LabelType {
    /// Attempts to take a label type from the beginning of `parser`.
    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        let ltype = parser.parse_u8()?;
        match ltype {
            0..=0x3F => Ok(LabelType::Normal(ltype.into())),
            0xC0..=0xFF => {
                let res = usize::from(parser.parse_u8()?);
                let res = res | ((usize::from(ltype) & 0x3F) << 8);
                Ok(LabelType::Compressed(res))
            }
            _ => Err(ParseError::Form(FormError::new("invalid label type"))),
        }
    }

    /// Returns the label type at the beginning of `parser` without advancing.
    pub fn peek<Ref: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Ref>,
    ) -> Result<Self, ParseError> {
        let ltype = parser.peek(1)?[0];
        match ltype {
            0..=0x3F => Ok(LabelType::Normal(ltype.into())),
            0xC0..=0xFF => {
                let res = usize::from(parser.peek(2)?[1]);
                let res = res | ((usize::from(ltype) & 0x3F) << 8);
                Ok(LabelType::Compressed(res))
            }
            _ => Err(ParseError::Form(FormError::new("invalid label type"))),
        }
    }
}

//------------ ParsedDnameError ----------------------------------------------

/// Parsing a domain name failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedDnameError {
    /// A bad label was encountered.
    BadLabel(LabelTypeError),

    /// The name is longer than the 255 octets allowed.
    LongName,

    /// Too many compression pointers.
    ExcessiveCompression,
}

impl fmt::Display for ParsedDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        FormError::from(*self).fmt(f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsedDnameError {}

impl From<LabelTypeError> for ParsedDnameError {
    fn from(err: LabelTypeError) -> Self {
        ParsedDnameError::BadLabel(err)
    }
}

impl From<ParsedDnameError> for FormError {
    fn from(err: ParsedDnameError) -> FormError {
        match err {
            ParsedDnameError::BadLabel(_) => {
                FormError::new("invalid label type")
            }
            ParsedDnameError::LongName => FormError::new("long domain name"),
            ParsedDnameError::ExcessiveCompression => {
                FormError::new("too many compression pointers")
            }
        }
    }
}

impl From<ParsedDnameError> for ParseError {
    fn from(err: ParsedDnameError) -> ParseError {
        ParseError::Form(err.into())
    }
}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::name::{Dname, RelativeDname};

    macro_rules! name {
        (root) => {
            name!(b"123\0", 3, 1, false)
        };
        (flat) => {
            name!(b"\x03www\x07example\x03com\0\xc0\0", 0, 17, false)
        };
        (copy) => {
            name!(b"\x03www\x07example\x03com\0\xc0\0", 17, 17, false)
        };
        (once) => {
            name!(b"\x03com\0\x03www\x07example\xC0\0", 5, 17, true)
        };
        (twice) => {
            name!(b"\x03com\0\x07example\xc0\0\x03www\xc0\x05", 15, 17, true)
        };

        ($bytes:expr, $start:expr, $len:expr, $compressed:expr) => {{
            let mut parser = Parser::from_ref($bytes.as_ref());
            parser.advance($start).unwrap();
            ParsedDname {
                octets: $bytes.as_ref(),
                pos: $start,
                name_len: $len,
                compressed: $compressed,
            }
        }};
    }

    static WECR: &[u8] = b"\x03www\x07example\x03com\0";

    #[test]
    fn len() {
        assert_eq!(name!(root).compose_len(), 1);
        assert_eq!(name!(flat).compose_len(), 17);
        assert_eq!(name!(once).compose_len(), 17);
        assert_eq!(name!(twice).compose_len(), 17);
    }

    #[test]
    fn is_compressed() {
        assert!(!name!(root).is_compressed());
        assert!(!name!(flat).is_compressed());
        assert!(name!(once).is_compressed());
        assert!(name!(twice).is_compressed());
    }

    #[test]
    fn is_root() {
        assert!(name!(root).is_root());
        assert!(!name!(flat).is_root());
        assert!(!name!(once).is_root());
        assert!(!name!(twice).is_root());
    }

    #[test]
    fn iter() {
        use crate::base::name::dname::test::cmp_iter;

        let labels: &[&[u8]] = &[b"www", b"example", b"com", b""];
        cmp_iter(name!(root).iter(), &[b""]);
        cmp_iter(name!(flat).iter(), labels);
        cmp_iter(name!(once).iter(), labels);
        cmp_iter(name!(twice).iter(), labels);
    }

    #[test]
    fn iter_back() {
        use crate::base::name::dname::test::cmp_iter_back;

        let labels: &[&[u8]] = &[b"", b"com", b"example", b"www"];
        cmp_iter_back(name!(root).iter(), &[b""]);
        cmp_iter_back(name!(flat).iter(), labels);
        cmp_iter_back(name!(once).iter(), labels);
        cmp_iter_back(name!(twice).iter(), labels);
    }

    fn cmp_iter_suffixes<'a, I>(iter: I, labels: &[&[u8]])
    where
        I: Iterator<Item = ParsedDname<&'a [u8]>>,
    {
        for (name, labels) in iter.zip(labels) {
            let mut iter = name.iter();
            let labels = Dname::from_slice(labels).unwrap();
            let mut labels_iter = labels.iter();
            loop {
                match (iter.next(), labels_iter.next()) {
                    (Some(left), Some(right)) => assert_eq!(left, right),
                    (None, None) => break,
                    (_, None) => panic!("extra items in iterator"),
                    (None, _) => panic!("missing items in iterator"),
                }
            }
        }
    }

    #[test]
    fn iter_suffixes() {
        let suffixes: &[&[u8]] = &[
            b"\x03www\x07example\x03com\0",
            b"\x07example\x03com\0",
            b"\x03com\0",
            b"\0",
        ];
        cmp_iter_suffixes(name!(root).iter_suffixes(), &[b"\0"]);
        cmp_iter_suffixes(name!(flat).iter_suffixes(), suffixes);
        cmp_iter_suffixes(name!(once).iter_suffixes(), suffixes);
        cmp_iter_suffixes(name!(twice).iter_suffixes(), suffixes);
    }

    #[test]
    fn label_count() {
        assert_eq!(name!(root).label_count(), 1);
        assert_eq!(name!(flat).label_count(), 4);
        assert_eq!(name!(once).label_count(), 4);
        assert_eq!(name!(twice).label_count(), 4);
    }

    #[test]
    fn first() {
        assert_eq!(name!(root).first().as_slice(), b"");
        assert_eq!(name!(flat).first().as_slice(), b"www");
        assert_eq!(name!(once).first().as_slice(), b"www");
        assert_eq!(name!(twice).first().as_slice(), b"www");
    }

    #[test]
    fn starts_with() {
        let root = name!(root);
        let flat_wec = name!(flat);
        let once_wec = name!(once);
        let twice_wec = name!(twice);

        let test = Dname::root_ref();
        assert!(root.starts_with(&test));
        assert!(!flat_wec.starts_with(&test));
        assert!(!once_wec.starts_with(&test));
        assert!(!twice_wec.starts_with(&test));

        let test = RelativeDname::empty_ref();
        assert!(root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test =
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!flat_wec.starts_with(&test));
        assert!(!once_wec.starts_with(&test));
        assert!(!twice_wec.starts_with(&test));

        let test = RelativeDname::from_octets(b"\x03www".as_ref())
            .unwrap()
            .chain(
                RelativeDname::from_octets(b"\x07example".as_ref()).unwrap(),
            )
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = test
            .chain(RelativeDname::from_octets(b"\x03com".as_ref()).unwrap())
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = name!(root);
        let flat_wec = name!(flat);
        let once_wec = name!(once);
        let twice_wec = name!(twice);
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        for name in wecr.iter_suffixes() {
            if name.is_root() {
                assert!(root.ends_with(&name))
            } else {
                assert!(!root.ends_with(&name))
            }
            assert!(flat_wec.ends_with(&name));
            assert!(once_wec.ends_with(&name));
            assert!(twice_wec.ends_with(&name));
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn split_first() {
        fn split_first_wec(mut name: ParsedDname<&[u8]>) {
            assert_eq!(
                name.to_vec().as_slice(),
                b"\x03www\x07example\x03com\0"
            );
            assert_eq!(
                name.split_first().unwrap().as_slice(),
                b"\x03www".as_ref()
            );
            assert_eq!(name.to_vec().as_slice(), b"\x07example\x03com\0");
            assert_eq!(
                name.split_first().unwrap().as_slice(),
                b"\x07example".as_ref()
            );
            assert_eq!(name.to_vec().as_slice(), b"\x03com\0");
            assert_eq!(
                name.split_first().unwrap().as_slice(),
                b"\x03com".as_ref()
            );
            assert_eq!(name.to_vec().as_slice(), b"\0");
            assert_eq!(name.split_first(), None);
            assert_eq!(name.split_first(), None);
        }

        split_first_wec(name!(flat));
        split_first_wec(name!(once));
        split_first_wec(name!(twice));
    }

    #[test]
    #[cfg(feature = "std")]
    fn parent() {
        fn parent_wec(mut name: ParsedDname<&[u8]>) {
            assert_eq!(
                name.to_vec().as_slice(),
                b"\x03www\x07example\x03com\0"
            );
            assert!(name.parent());
            assert_eq!(name.to_vec().as_slice(), b"\x07example\x03com\0");
            assert!(name.parent());
            assert_eq!(name.to_vec().as_slice(), b"\x03com\0");
            assert!(name.parent());
            assert_eq!(name.to_vec().as_slice(), b"\0");
            assert!(!name.parent());
            assert!(!name.parent());
        }

        parent_wec(name!(flat));
        parent_wec(name!(once));
        parent_wec(name!(twice));
    }

    #[test]
    #[cfg(feature = "std")]
    fn parse_and_skip() {
        use std::vec::Vec;

        fn name_eq(parsed: ParsedDname<&[u8]>, name: ParsedDname<&[u8]>) {
            assert_eq!(parsed.octets, name.octets);
            assert_eq!(parsed.pos, name.pos);
            assert_eq!(parsed.name_len, name.name_len);
            assert_eq!(parsed.compressed, name.compressed);
        }

        fn parse(
            mut parser: Parser<&[u8]>,
            equals: ParsedDname<&[u8]>,
            compose_len: usize,
        ) {
            let end = parser.pos() + compose_len;
            name_eq(ParsedDname::parse(&mut parser).unwrap(), equals);
            assert_eq!(parser.pos(), end);
        }

        fn skip(name: ParsedDname<&[u8]>, len: usize) {
            let mut parser = name.parser();
            let pos = parser.pos();
            assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
            assert_eq!(parser.pos(), pos + len);
        }

        fn p(slice: &[u8], pos: usize) -> Parser<[u8]> {
            let mut res = Parser::from_ref(slice);
            res.advance(pos).unwrap();
            res
        }

        // Correctly formatted names.
        parse(name!(root).parser(), name!(root), 1);
        parse(name!(flat).parser(), name!(flat), 17);
        parse(name!(copy).parser(), name!(flat), 2);
        parse(name!(once).parser(), name!(once), 14);
        parse(name!(twice).parser(), name!(twice), 6);
        skip(name!(root), 1);
        skip(name!(flat), 17);
        skip(name!(copy), 2);
        skip(name!(once), 14);
        skip(name!(twice), 6);

        // Short buffer in the middle of a label.
        let mut parser = p(b"\x03www\x07exam", 0);
        assert_eq!(
            ParsedDname::parse(&mut parser.clone()),
            Err(ParseError::ShortInput)
        );
        assert_eq!(
            ParsedDname::skip(&mut parser),
            Err(ParseError::ShortInput)
        );

        // Short buffer at end of label.
        let mut parser = p(b"\x03www\x07example", 0);
        assert_eq!(
            ParsedDname::parse(&mut parser.clone()),
            Err(ParseError::ShortInput)
        );
        assert_eq!(
            ParsedDname::skip(&mut parser),
            Err(ParseError::ShortInput)
        );

        // Compression pointer beyond the end of buffer.
        let mut parser = p(b"\x03www\xc0\xee12", 0);
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Compression pointer to itself
        assert!(ParsedDname::parse(&mut p(b"\x03www\xc0\x0412", 4)).is_err());

        // Compression pointer forward
        assert!(ParsedDname::parse(&mut p(b"\x03www\xc0\x0612", 4)).is_err());

        // Bad label header.
        let mut parser = p(b"\x03www\x07example\xbffoo", 0);
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert!(ParsedDname::skip(&mut parser).is_err());

        // Long name: 255 bytes is fine.
        let mut buf = Vec::from(&b"\x03123\0"[..]);
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        buf.extend_from_slice(b"\xc0\x0012");
        let mut parser = Parser::from_ref(buf.as_slice());
        parser.advance(5).unwrap();
        let name = ParsedDname::parse(&mut parser.clone()).unwrap();
        assert_eq!(name.compose_len(), 255);
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Long name: 256 bytes are bad.
        let mut buf = Vec::from(&b"\x041234\x00"[..]);
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        buf.extend_from_slice(b"\xc0\x0012");
        let mut parser = Parser::from_ref(buf.as_slice());
        parser.advance(6).unwrap();
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Long name through recursion
        let mut parser = p(b"\x03www\xc0\x0012", 0);
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Single-step infinite recursion
        let mut parser = p(b"\xc0\x0012", 0);
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Two-step infinite recursion
        let mut parser = p(b"\xc0\x02\xc0\x0012", 2);
        assert!(ParsedDname::parse(&mut parser.clone()).is_err());
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);
    }

    #[test]
    #[cfg(feature = "std")]
    fn compose() {
        use octseq::builder::infallible;
        use std::vec::Vec;

        fn step(name: ParsedDname<&[u8]>, result: &[u8]) {
            let mut buf = Vec::new();
            infallible(name.compose(&mut buf));
            assert_eq!(buf.as_slice(), result);
        }

        step(name!(root), b"\x00");
        step(name!(flat), WECR);
        step(name!(once), WECR);
        step(name!(twice), WECR);
    }

    // XXX TODO compose_canonical

    #[test]
    fn as_flat_slice() {
        assert_eq!(name!(root).as_flat_slice(), Some(b"\x00".as_ref()));
        assert_eq!(name!(flat).as_flat_slice(), Some(WECR));
        assert_eq!(name!(once).as_flat_slice(), None);
        assert_eq!(name!(twice).as_flat_slice(), None);
    }

    #[test]
    fn eq() {
        fn step<N: ToDname + fmt::Debug>(name: N) {
            assert_eq!(name!(flat), &name);
            assert_eq!(name!(once), &name);
            assert_eq!(name!(twice), &name);
        }

        fn ne_step<N: ToDname + fmt::Debug>(name: N) {
            assert_ne!(name!(flat), &name);
            assert_ne!(name!(once), &name);
            assert_ne!(name!(twice), &name);
        }

        step(name!(flat));
        step(name!(once));
        step(name!(twice));

        step(Dname::from_slice(b"\x03www\x07example\x03com\x00").unwrap());
        step(Dname::from_slice(b"\x03wWw\x07EXAMPLE\x03com\x00").unwrap());
        step(
            RelativeDname::from_octets(b"\x03www\x07example\x03com")
                .unwrap()
                .chain_root(),
        );
        step(
            RelativeDname::from_octets(b"\x03www\x07example")
                .unwrap()
                .chain(Dname::from_octets(b"\x03com\x00").unwrap())
                .unwrap(),
        );

        ne_step(Dname::from_slice(b"\x03ww4\x07EXAMPLE\x03com\x00").unwrap());
    }

    // XXX TODO Test for cmp and hash.
}
