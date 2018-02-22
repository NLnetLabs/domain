//! Parsed domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! module.

use std::{cmp, fmt, hash};
use bytes::{BufMut, Bytes};
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::parse::{Parse, ParseAll, Parser, ParseAllError, ParseOpenError,
                    ShortBuf};
use super::label::{Label, LabelTypeError};
use super::traits::{ToLabelIter, ToDname};
use super::relative::RelativeDname;


//------------ ParsedDname ---------------------------------------------------

/// A domain name parsed from a DNS message.
///
/// In an attempt to keep messages small, DNS uses a procedure called ‘name
/// compression.’ It tries to minimize the space used for repeatedly
/// appearing domain names by simply refering to the first occurence of the
/// name. This works not only for complete names but also for suffixes. In
/// this case, the first unique labels of the name are included and then a
/// pointer is included for the rest of the name.
///
/// A consequence of this is that when parsing a domain name, its labels can
/// be scattered all over the message and we would need to allocate some
/// space to re-assemble the original name. However, in many cases we don’t
/// need the complete name. Many operations can be performed by just
/// iterating over the labels which we can do in place.
///
/// `ParsedDname` deals with such names. It takes a copy of [`Parser`]
/// representing the underlying DNS message and, if nedded, traverses over
/// the name starting at the current position of the parser. When being
/// created, the type quickly walks over the name to check that it is, indeed,
/// a valid name. While this does take a bit of time, it spares you having to
/// deal with possible parse errors later.
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
#[derive(Clone)]
pub struct ParsedDname {
    /// A parser positioned at the beginning of the name.
    parser: Parser,

    /// The length of the uncompressed name in bytes.
    ///
    /// We need this for implementing `Compose`.
    len: usize,

    /// Whether the name is compressed.
    ///
    /// This allows various neat optimizations for the case where it isn’t.
    compressed: bool,
}

/// # Conversion
/// 
/// For a conversion into a regular [`Dname`], see [`ToDname::to_name`].
///
/// [`Dname`]: struct.Dname.html
/// [`ToDname::to_name`]: trait.ToDname.html#method.to_name
impl ParsedDname {
    /// Converts the name into a bytes value with its flat representation.
    pub fn into_bytes(self) -> Bytes {
        self.to_name().into_bytes()
    }
}


/// # Properties
///
impl ParsedDname {
    /// Returns the length of the name in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the name is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.len == 1
    }
}

/// # Working with Labels
///
impl ParsedDname {
    /// Returns an iterator over the labels of the name.
    pub fn iter(&self) -> ParsedDnameIter {
        ParsedDnameIter::new(&self.parser, self.len)
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> ParsedSuffixIter {
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
    pub fn starts_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns `None` and does nothing.
    pub fn split_first(&mut self) -> Option<RelativeDname> {
        if self.len == 1 {
            return None
        }
        let len = loop {
            match LabelType::peek(&mut self.parser).unwrap() {
                LabelType::Normal(0) => {
                    unreachable!()
                }
                LabelType::Normal(label_len) => {
                    break label_len + 1
                }
                LabelType::Compressed(pos) => {
                    self.parser.seek(pos).unwrap();
                }
            }
        };
        self.len -= len;
        Some(unsafe {
            RelativeDname::from_bytes_unchecked(
                self.parser.parse_bytes(len).unwrap()
            )
        })
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `false` and does
    /// nothing. Otherwise, drops the first label and returns `true`.
    pub fn parent(&mut self) -> bool {
        self.split_first().is_some()
    }
}


//--- Parse, Compose, and Compress

impl Parse for ParsedDname {
    type Err = ParsedDnameError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        // We will walk over the entire name to ensure it is valid. Because
        // we need to clone the original parser for the result, anyway, it is
        // okay to clone the input parser into a temporary parser to do the
        // checking on.
        let mut res = parser.clone();
        let mut tmp = parser.clone();

        // Name compression can lead to infinite recursion. The easiest way
        // to protect against that is by limiting the number of compression
        // pointers we allow. Since the largest number of labels in a name is
        // 128 (the shortest possible label is two bytes long plus the root
        // label is one byte), this seems a reasonable upper limit. We’ll
        // keep a counter of the numbers of pointers encountered. Plus, when
        // we encounter our first pointer, it marks the end of the name in
        // the original parser, so we update that at that point.
        let mut ptrs = 0;

        // We’ll also keep track of the length of the uncompressed version of
        // the name which musn’t exceed 255 bytes and whether compression has
        // occured yet. As you’ll see below, this cannot necessarily be
        // determined by checking if prts is still zero.
        let mut len = 0;
        let mut compressed = false;

        loop {
            match LabelType::parse(&mut tmp)? {
                LabelType::Normal(0) => {
                    len += 1;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName)
                    }
                    if ptrs == 0 {
                        parser.seek(tmp.pos()).unwrap();
                    }
                    break;
                }
                LabelType::Normal(label_len) => {
                    len += label_len + 1;
                    tmp.advance(label_len)?;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName)
                    }
                }
                LabelType::Compressed(pos) => {
                    if ptrs >= 127 {
                        return Err(ParsedDnameError::ExcessiveCompression)
                    }
                    if ptrs == 0 {
                        parser.seek(tmp.pos()).unwrap();
                    }
                    if len == 0 {
                        // If no normal labels have occured yet, we can
                        // reposition the result’s parser to the pointed to
                        // position and pretend we don’t have a compressed
                        // name.
                        res.seek(pos)?;
                    }
                    else {
                        compressed = true;
                    }
                    ptrs += 1;
                    tmp.seek(pos)?
                }
            }
        }
        Ok(ParsedDname { parser: res, len, compressed })
    }

    /// Skip over a domain name.
    ///
    /// This will only check the uncompressed part of the name. If the name
    /// is compressed but the compression pointer is invalid or the name
    /// pointed to is invalid or too long, the function will still succeed.
    ///
    /// If you need to check that the name you are skipping over is valid, you
    /// will have to use `parse` and drop the result.
    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        let mut len = 0;
        loop {
            match LabelType::parse(parser) {
                Ok(LabelType::Normal(0)) => {
                    len += 1;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName)
                    }
                    return Ok(())
                }
                Ok(LabelType::Normal(label_len)) => {
                    if let Err(err) = parser.advance(label_len) {
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        return Err(ParsedDnameError::LongName)
                    }
                }
                Ok(LabelType::Compressed(_)) => {
                    return Ok(())
                }
                Err(err) => {
                    return Err(err)
                }
            }
        }
    }
}

impl ParseAll for ParsedDname {
    type Err = ParsedDnameAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let mut tmp = parser.clone();
        let end = tmp.pos() + len;
        let res = Self::parse(&mut tmp)?;
        if tmp.pos() < end {
            println!("pos: {}, end: {}", tmp.pos(), end);
            return Err(ParsedDnameAllError::TrailingData)
        }
        else if tmp.pos() > end {
            return Err(ShortBuf.into())
        }
        parser.advance(len)?;
        Ok(res)
    }
}
               

impl Compose for ParsedDname {
    fn compose_len(&self) -> usize {
        self.len
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        if self.compressed {
            for label in self.iter() {
                label.compose(buf)
            }
        }
        else {
            buf.put_slice(self.parser.peek(self.len).unwrap())
        }
    }
}

impl Compress for ParsedDname {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compress_name(self)
    }
}


//--- ToLabelIter and ToDname

impl<'a> ToLabelIter<'a> for ParsedDname {
    type LabelIter = ParsedDnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToDname for ParsedDname {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        if self.compressed {
            None
        }
        else {
            Some(self.parser.peek(self.len).unwrap())
        }
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a ParsedDname {
    type Item = &'a Label;
    type IntoIter = ParsedDnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl<N: ToDname> PartialEq<N> for ParsedDname {
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl Eq for ParsedDname { }


//--- PartialOrd and Ord

impl<N: ToDname> PartialOrd<N> for ParsedDname {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl Ord for ParsedDname {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}


//--- Hash

impl hash::Hash for ParsedDname {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Display

impl fmt::Display for ParsedDname {
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


//--- Debug

impl fmt::Debug for ParsedDname {
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
    len: usize,
}

impl<'a> ParsedDnameIter<'a> {
    /// Creates a new iterator from the parser and the name length.
    ///
    /// The parser must be positioned at the beginning of the name.
    fn new(parser: &'a Parser, len: usize) -> Self {
        ParsedDnameIter { slice: parser.as_slice(), pos: parser.pos(), len }
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
                0 ... 0x3F => break self.pos + (ltype as usize),
                0xC0 ... 0xFF => {
                    self.pos = (self.slice[self.pos] as usize)
                             | (((ltype as usize) & 0x3F) << 8);
                }
                _ => panic!("bad label")
            }
        };
        let res = unsafe {
            Label::from_slice_unchecked(&self.slice[self.pos..end])
        };
        self.pos = end;
        self.len -= res.len() + 1;
        res
    }
}

impl<'a> Iterator for ParsedDnameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None
        }
        Some(self.get_label())
    }
}

impl<'a> DoubleEndedIterator for ParsedDnameIter<'a> {
    fn next_back(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None
        }
        let mut tmp = self.clone();
        let label = loop {
            let label = tmp.get_label();
            if tmp.len == 0 {
                break label
            }
        };
        self.len -= label.len() + 1;
        Some(label)
    }
}


//------------ ParsedSuffixIter ----------------------------------------------

/// An iterator over ever shorter suffixes of a parsed domain name.
#[derive(Clone, Debug)]
pub struct ParsedSuffixIter {
    name: Option<ParsedDname>,
}

impl ParsedSuffixIter {
    /// Creates a new iterator cloning `name`.
    fn new(name: &ParsedDname) -> Self {
        ParsedSuffixIter { name: Some(name.clone()) }
    }
}

impl Iterator for ParsedSuffixIter {
    type Item = ParsedDname;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, ok) = match self.name {
            Some(ref mut name) => (name.clone(), name.parent()),
            None => return None
        };
        if !ok {
            self.name = None
        }
        Some(res)
    }
}


//------------ LabelType -----------------------------------------------------

/// The type of a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LabelType {
    /// A normal label with its size in bytes.
    Normal(usize),

    /// A compressed label with the position of where to continue.
    Compressed(usize),
}

impl LabelType {
    /// Attempts to take a label type from the beginning of `parser`.
    pub fn parse(parser: &mut Parser) -> Result<Self, ParsedDnameError> {
        let ltype = parser.parse_u8()?;
        match ltype {
            0 ... 0x3F => Ok(LabelType::Normal(ltype as usize)),
            0xC0 ... 0xFF => {
                let res = parser.parse_u8()? as usize;
                let res = res | (((ltype as usize) & 0x3F) << 8);
                Ok(LabelType::Compressed(res))
            }
            0x40 ... 0x4F => Err(LabelTypeError::Extended(ltype).into()),
            _ => Err(LabelTypeError::Undefined.into())
        }
    }

    /// Returns the label type at the beginning of `parser` without advancing.
    pub fn peek(parser: &mut Parser) -> Result<Self, ParsedDnameError> {
        let ltype = parser.peek(1)?[0];
        match ltype {
            0 ... 0x3F => Ok(LabelType::Normal(ltype as usize)),
            0xC0 ... 0xFF => {
                let res = (parser.peek(2)?[1]) as usize;
                let res = res | (((ltype as usize) & 0x3F) << 8);
                Ok(LabelType::Compressed(res))
            }
            0x40 ... 0x4F => Err(LabelTypeError::Extended(ltype).into()),
            _ => Err(LabelTypeError::Undefined.into())
        }
    }
}


//------------ ParsedDnameError ----------------------------------------------

/// Parsing a domain name failed.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParsedDnameError {
    /// A bad label was encountered.
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    /// The name is longer than the 255 bytes limit.
    #[fail(display="long domain name")]
    LongName,

    /// Too many compression pointers.
    #[fail(display="too many compression pointers")]
    ExcessiveCompression,

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl From<LabelTypeError> for ParsedDnameError {
    fn from(err: LabelTypeError) -> Self {
        ParsedDnameError::BadLabel(err)
    }
}

impl From<ShortBuf> for ParsedDnameError {
    fn from(_: ShortBuf) -> Self {
        ParsedDnameError::ShortBuf
    }
}


//------------ ParsedDnameAllError -------------------------------------------

/// An error happened while parsing a compressed domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParsedDnameAllError {
    #[fail(display="{}", _0)]
    Parse(ParsedDnameError),

    #[fail(display="trailing data")]
    TrailingData,

    #[fail(display="short field")]
    ShortField,

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl From<ParsedDnameError> for ParsedDnameAllError {
    fn from(err: ParsedDnameError) -> Self {
        ParsedDnameAllError::Parse(err)
    }
}

impl From<ParseOpenError> for ParsedDnameAllError {
    fn from(err: ParseOpenError) -> Self {
        match err {
            ParseOpenError::ShortField => ParsedDnameAllError::ShortField,
            ParseOpenError::ShortBuf => ParsedDnameAllError::ShortBuf,
        }
    }
}

impl From<ParseAllError> for ParsedDnameAllError {
    fn from(err: ParseAllError) -> Self {
        match err {
            ParseAllError::TrailingData => ParsedDnameAllError::TrailingData,
            ParseAllError::ShortField => ParsedDnameAllError::ShortField,
            ParseAllError::ShortBuf => ParsedDnameAllError::ShortBuf,
        }
    }
}

impl From<ShortBuf> for ParsedDnameAllError {
    fn from(_: ShortBuf) -> Self {
        ParsedDnameAllError::ShortBuf
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use bytes::BytesMut;
    use ::bits::parse::Parser;
    use ::bits::name::Dname;

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

        ($bytes:expr, $start:expr, $len:expr, $compressed:expr) => {
            {
                let mut parser = Parser::from_static($bytes);
                parser.advance($start).unwrap();
                ParsedDname { parser, len: $len, compressed: $compressed }
            }
        }
    }

    static WECR: &[u8] = b"\x03www\x07example\x03com\0";

    #[test]
    fn into_bytes() {
        assert_eq!(name!(root).into_bytes(), b"\0".as_ref());
        assert_eq!(name!(flat).into_bytes(), WECR);
        assert_eq!(name!(once).into_bytes(), WECR);
        assert_eq!(name!(twice).into_bytes(), WECR);
    }

    #[test]
    fn len() {
        assert_eq!(name!(root).len(), 1);
        assert_eq!(name!(flat).len(), 17);
        assert_eq!(name!(once).len(), 17);
        assert_eq!(name!(twice).len(), 17);
    }

    #[test]
    fn is_compressed() {
        assert_eq!(name!(root).is_compressed(), false);
        assert_eq!(name!(flat).is_compressed(), false);
        assert_eq!(name!(once).is_compressed(), true);
        assert_eq!(name!(twice).is_compressed(), true);
    }

    #[test]
    fn is_root() {
        assert_eq!(name!(root).is_root(), true);
        assert_eq!(name!(flat).is_root(), false);
        assert_eq!(name!(once).is_root(), false);
        assert_eq!(name!(twice).is_root(), false);
    }

    #[test]
    fn iter() {
        use ::bits::name::dname::test::cmp_iter;

        let labels: &[&[u8]] = &[b"www", b"example", b"com", b""];
        cmp_iter(name!(root).iter(), &[b""]);
        cmp_iter(name!(flat).iter(), labels);
        cmp_iter(name!(once).iter(), labels);
        cmp_iter(name!(twice).iter(), labels);
    }

    #[test]
    fn iter_back() {
        use ::bits::name::dname::test::cmp_iter_back;

        let labels: &[&[u8]] = &[b"", b"com", b"example", b"www"];
        cmp_iter_back(name!(root).iter(), &[b""]);
        cmp_iter_back(name!(flat).iter(), labels);
        cmp_iter_back(name!(once).iter(), labels);
        cmp_iter_back(name!(twice).iter(), labels);
    }

    fn cmp_iter_suffixes<I>(iter: I, labels: &[&[u8]])
    where I: Iterator<Item=ParsedDname> {
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
        let suffixes: &[&[u8]] = &[b"\x03www\x07example\x03com\0",
                                   b"\x07example\x03com\0", b"\x03com\0",
                                   b"\0"];
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

        let test = Dname::root();
        assert!( root.starts_with(&test));
        assert!(!flat_wec.starts_with(&test));
        assert!(!once_wec.starts_with(&test));
        assert!(!twice_wec.starts_with(&test));

        let test = RelativeDname::empty();
        assert!(root.starts_with(&test));
        assert!(flat_wec.starts_with(&test));
        assert!(once_wec.starts_with(&test));
        assert!(twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));
        
        let test = RelativeDname::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www\x07example\x03com")
                                 .unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));

        let test = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!flat_wec.starts_with(&test));
        assert!(!once_wec.starts_with(&test));
        assert!(!twice_wec.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www").unwrap()
                    .chain(RelativeDname::from_slice(b"\x07example").unwrap())
                    .unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));

        let test = test.chain(RelativeDname::from_slice(b"\x03com")
                                            .unwrap())
                       .unwrap();
        assert!(!root.starts_with(&test));
        assert!( flat_wec.starts_with(&test));
        assert!( once_wec.starts_with(&test));
        assert!( twice_wec.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = name!(root);
        let flat_wec = name!(flat);
        let once_wec = name!(once);
        let twice_wec = name!(twice);
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        for name in wecr.iter_suffixes() {
            if name.is_root() {
                assert!(root.ends_with(&name))
            }
            else {
                assert!(!root.ends_with(&name))
            }
            assert!(flat_wec.ends_with(&name));
            assert!(once_wec.ends_with(&name));
            assert!(twice_wec.ends_with(&name));
        }
    }

    fn split_first_wec(mut name: ParsedDname) {
        assert_eq!(name.clone().into_bytes(),
                   b"\x03www\x07example\x03com\0".as_ref());
        assert_eq!(name.split_first().unwrap().as_slice(),
                   b"\x03www".as_ref());
        assert_eq!(name.clone().into_bytes(),
                   b"\x07example\x03com\0".as_ref());
        assert_eq!(name.split_first().unwrap().as_slice(),
                   b"\x07example".as_ref());
        assert_eq!(name.clone().into_bytes(),
                   b"\x03com\0".as_ref());
        assert_eq!(name.split_first().unwrap().as_slice(),
                   b"\x03com".as_ref());
        assert_eq!(name.clone().into_bytes(),
                   b"\0".as_ref());
        assert_eq!(name.split_first(), None);
        assert_eq!(name.split_first(), None);
    }

    #[test]
    fn split_first() {
        split_first_wec(name!(flat));
        split_first_wec(name!(once));
        split_first_wec(name!(twice));
    }

    fn parent_wec(mut name: ParsedDname) {
        assert_eq!(name.clone().into_bytes(),
                   b"\x03www\x07example\x03com\0".as_ref());
        assert_eq!(name.parent(), true);
        assert_eq!(name.clone().into_bytes(),
                   b"\x07example\x03com\0".as_ref());
        assert_eq!(name.parent(), true);
        assert_eq!(name.clone().into_bytes(),
                   b"\x03com\0".as_ref());
        assert_eq!(name.parent(), true);
        assert_eq!(name.clone().into_bytes(),
                   b"\0".as_ref());
        assert_eq!(name.parent(), false);
        assert_eq!(name.parent(), false);
    } 

    #[test]
    fn parent() {
        parent_wec(name!(flat));
        parent_wec(name!(once));
        parent_wec(name!(twice));
    }

    fn name_eq(parsed: ParsedDname, name: ParsedDname) {
        assert_eq!(parsed.parser.as_slice(), name.parser.as_slice());
        assert_eq!(parsed.parser.pos(), name.parser.pos());
        assert_eq!(parsed.len, name.len);
        assert_eq!(parsed.compressed, name.compressed);
    }

    fn parse(mut parser: Parser, equals: ParsedDname, compose_len: usize) {
        let end = parser.pos() + compose_len;
        name_eq(ParsedDname::parse(&mut parser).unwrap(), equals);
        assert_eq!(parser.pos(), end);
    }

    fn skip(mut name: ParsedDname, len: usize) {
        let end = name.parser.pos() + len;
        assert_eq!(ParsedDname::skip(&mut name.parser), Ok(()));
        assert_eq!(name.parser.pos(), end);
    }

    fn p(slice: &'static [u8], pos: usize) -> Parser {
        let mut res = Parser::from_static(slice);
        res.advance(pos).unwrap();
        res
    }

    #[test]
    fn parse_and_skip() {
        // Correctly formatted names.
        parse(name!(root).parser, name!(root), 1);
        parse(name!(flat).parser, name!(flat), 17);
        parse(name!(copy).parser, name!(flat), 2);
        parse(name!(once).parser, name!(once), 14);
        parse(name!(twice).parser, name!(twice), 6);
        skip(name!(root), 1);
        skip(name!(flat), 17);
        skip(name!(copy), 2);
        skip(name!(once), 14);
        skip(name!(twice), 6);

        // Short buffer in the middle of a label.
        let mut parser = p(b"\x03www\x07exam", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ShortBuf.into()));
        assert_eq!(ParsedDname::skip(&mut parser),
                   Err(ShortBuf.into()));

        // Short buffer at end of label.
        let mut parser = p(b"\x03www\x07example", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ShortBuf.into()));
        assert_eq!(ParsedDname::skip(&mut parser),
                   Err(ShortBuf.into()));

        // Compression pointer beyond the end of buffer.
        let mut parser = p(b"\x03www\xc0\xee12", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ShortBuf.into()));
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Bad label header.
        let mut parser = p(b"\x03www\x07example\xbffoo", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(LabelTypeError::Undefined.into()));
        assert_eq!(ParsedDname::skip(&mut parser),
                   Err(LabelTypeError::Undefined.into()));

        // Long name: 255 bytes is fine.
        let mut buf = Vec::from(&b"\x03123\0"[..]);
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        buf.extend_from_slice(b"\xc0\012");
        let mut parser = Parser::from_bytes(buf.into());
        parser.advance(5).unwrap();
        let name = ParsedDname::parse(&mut parser.clone()).unwrap();
        assert_eq!(name.len(), 255);
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Long name: 256 bytes are bad.
        let mut buf = Vec::from(&b"\x041234\0"[..]);
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        buf.extend_from_slice(b"\xc0\012");
        let mut parser = Parser::from_bytes(buf.into());
        parser.advance(6).unwrap();
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ParsedDnameError::LongName));
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Long name through recursion
        let mut parser = p(b"\x03www\xc0\012", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ParsedDnameError::LongName));
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Single-step infinite recursion
        let mut parser = p(b"\xc0\012", 0);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ParsedDnameError::ExcessiveCompression));
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);

        // Two-step infinite recursion
        let mut parser = p(b"\xc0\x02\xc0\012", 2);
        assert_eq!(ParsedDname::parse(&mut parser.clone()),
                   Err(ParsedDnameError::ExcessiveCompression));
        assert_eq!(ParsedDname::skip(&mut parser), Ok(()));
        assert_eq!(parser.remaining(), 2);
    }

    #[test]
    fn parse_all() {
        // The current implementation defers to `Dname::from_bytes`. As there
        // are test cases for the error cases with that function, all we need
        // to do is make sure it defers correctly.
        
        name_eq(ParsedDname::parse_all(&mut name!(root).parser, 1).unwrap(),
                name!(root));
        name_eq(ParsedDname::parse_all(&mut name!(flat).parser, 17).unwrap(),
                name!(flat));
        name_eq(ParsedDname::parse_all(&mut name!(copy).parser, 2).unwrap(),
                name!(flat));
        name_eq(ParsedDname::parse_all(&mut name!(once).parser, 14).unwrap(),
                name!(once));
        name_eq(ParsedDname::parse_all(&mut name!(twice).parser, 6).unwrap(),
                name!(twice));
    }

    #[test]
    fn compose() {
        fn step(name: ParsedDname, result: &[u8]) {
            assert_eq!(name.compose_len(), result.len());
            let mut buf = BytesMut::with_capacity(result.len());
            name.compose(&mut buf);
            let buf = buf.freeze();
            assert_eq!(buf, result);
        }

        step(name!(root), b"\0");
        step(name!(flat), WECR);
        step(name!(once), WECR);
        step(name!(twice), WECR);
    }

    // Compress is tested with Compressor.

    #[test]
    fn as_flat_slice() {
        assert_eq!(name!(root).as_flat_slice(), Some(b"\0".as_ref()));
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

        step(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap());
        step(Dname::from_slice(b"\x03wWw\x07EXAMPLE\x03com\0").unwrap());
        step(RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap()
                           .chain_root());
        step(RelativeDname::from_slice(b"\x03www\x07example").unwrap()
                           .chain(Dname::from_slice(b"\x03com\0").unwrap())
                           .unwrap());

        ne_step(Dname::from_slice(b"\x03ww4\x07EXAMPLE\x03com\0").unwrap());
    }

    // XXX TODO Test for cmp and hash.
}

