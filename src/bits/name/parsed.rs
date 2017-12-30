//! Parsed domain names.

use std::{cmp, fmt, hash};
use bytes::BufMut;
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::parse::{Parse, ParseAll, Parser, ParseAllError, ParseOpenError,
                    ShortBuf};
use super::error::{LabelTypeError};
use super::label::Label;
use super::traits::{ToLabelIter, ToDname};


//------------ ParsedDname ---------------------------------------------------

/// A domain name parsed from a DNS message.
///
/// In an attempt to keep messages small, DNS uses a procedure called name
/// compression. It tries to minimize the space used for repeated domain names
/// by simply refering to the first occurence of the name. This works not only
/// for complete names but also for suffixes. In this case, the first unique
/// labels of the name are included and then a pointer is included for the
/// rest of the name.
///
/// A consequence of this is that when parsing a domain name, its labels can
/// be scattered all over the message and we would need to allocate some
/// space to re-assemble the original name. However, in many cases we don’t
/// need the complete message. Many operations can be completed by just
/// iterating over the labels which we can do in place.
///
/// `ParsedDname` deals with such names. It takes a copy of [`Parser`]
/// representing the underlying DNS message and, if nedded, can traverse over
/// the name starting at the current position of the parser. When being
/// created, the type quickly walks over the name to check that it is, indeed,
/// a valid name. While this does take a bit of time, it spares you having to
/// deal with possible parse errors later.
///
/// `ParsedDname` implementes the [`ToDname`] trait, so you can use it
/// everywhere where an absolute domain name is accepted. In particular,
/// you can compare it to other names or chain it to the end of a relative
/// name.
///
/// [`Parser`]: ../parse/struct.Parser.html
/// [`ToDname`]: trait.ToDname.html
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

impl ParsedDname {
    /// Returns whether the name is compressed.
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    /// Returns an iterator over the labels of the name.
    pub fn iter(&self) -> ParsedDnameIter {
        ParsedDnameIter::new(&self.parser, self.len)
    }
}


//--- Parse, Compose, and Compress

impl Parse for ParsedDname {
    type Err = ParsedDnameError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let start = parser.pos();
        let mut len = 0;

        // Phase 1: Take labels from the parser until the root label or the
        //          first compressed label. In the latter case, remember where
        //          the actual name ended.
        let mut parser = loop {
            match LabelType::parse(parser) {
                Ok(LabelType::Normal(0)) => {
                    len += 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
                    }
                    let mut res = parser.clone();
                    res.seek(start).unwrap();
                    return Ok(ParsedDname { parser: res, len,
                                            compressed: false })
                }
                Ok(LabelType::Normal(label_len)) => {
                    if let Err(err) = parser.advance(label_len) {
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
                    }
                }
                Ok(LabelType::Compressed(pos)) => {
                    let mut parser = parser.clone();
                    if let Err(err) = parser.seek(pos) {
                        return Err(err.into())
                    }
                    break parser
                }
                Err(err) => {
                    return Err(err)
                }
            }
        };

        // Phase 2: Follow offsets so we can get the length.
        loop {
            match LabelType::parse(&mut parser)? {
                LabelType::Normal(0) => {
                    len += 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
                    }
                    break;
                }
                LabelType::Normal(label_len) => {
                    if let Err(err) = parser.advance(label_len) {
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
                    }
                }
                LabelType::Compressed(pos) => {
                    if let Err(err) = parser.seek(pos) {
                        return Err(err.into())
                    }
                }
            }
        }

        // Phase 3: Profit
        parser.seek(start).unwrap();
        Ok(ParsedDname { parser, len, compressed: true })
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        let mut len = 0;
        loop {
            match LabelType::parse(parser) {
                Ok(LabelType::Normal(0)) => {
                    len += 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
                    }
                    return Ok(())
                }
                Ok(LabelType::Normal(label_len)) => {
                    if let Err(err) = parser.advance(label_len) {
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        return Err(BadParsedDname::LongName.into())
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
        for label in self.iter() {
            label.compose(buf)
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

impl ToDname for ParsedDname { }


//--- IntoIterator

impl<'a> IntoIterator for &'a ParsedDname {
    type Item = &'a Label;
    type IntoIter = ParsedDnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq
//
//    XXX TODO PartialEq can be optimized for all cases where the name isn’t
//             compressed. So, move this to separate impls for Dname and
//             Self and have different code paths in them.

impl<N: ToDname> PartialEq<N> for ParsedDname {
    fn eq(&self, other: &N) -> bool {
        self.iter().eq(other.iter_labels())
    }
}

impl Eq for ParsedDname { }


//--- PartialOrd and Ord

impl<N: ToDname> PartialOrd<N> for ParsedDname {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter_labels())
    }
}

impl Ord for ParsedDname {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
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
        res
    }
}

impl<'a> Iterator for ParsedDnameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None
        }
        let res = self.get_label();
        self.len -= res.len() + 1;
        Some(res)
    }
}

impl<'a> DoubleEndedIterator for ParsedDnameIter<'a> {
    fn next_back(&mut self) -> Option<&'a Label> {
        while self.len > 0 {
            let label = self.get_label();
            self.len -= label.len() +1;
            if self.len == 0 {
                return Some(label)
            }
        }
        None
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
}


//------------ BadParsedDname ------------------------------------------------

/// A parsed domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum BadParsedDname {
    /// A bad label was encountered.
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    /// The name is longer than the 255 bytes limit.
    #[fail(display="long domain name")]
    LongName,
}

impl From<LabelTypeError> for BadParsedDname {
    fn from(err: LabelTypeError) -> BadParsedDname {
        BadParsedDname::BadLabel(err)
    }
}


//------------ ParsedDnameError ----------------------------------------------

/// Parsing a domain name failed.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParsedDnameError {
    #[fail(display="{}", _0)]
    BadName(BadParsedDname),

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl<T: Into<BadParsedDname>> From<T> for ParsedDnameError {
    fn from(err: T) -> Self {
        ParsedDnameError::BadName(err.into())
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
    BadName(BadParsedDname),

    #[fail(display="trailing data")]
    TrailingData,

    #[fail(display="short field")]
    ShortField,

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl<T: Into<BadParsedDname>> From<T> for ParsedDnameAllError {
    fn from(err: T) -> Self {
        ParsedDnameAllError::BadName(err.into())
    }
}

impl From<ParsedDnameError> for ParsedDnameAllError {
    fn from(err: ParsedDnameError) -> Self {
        match err {
            ParsedDnameError::BadName(err)
                => ParsedDnameAllError::BadName(err),
            ParsedDnameError::ShortBuf => ParsedDnameAllError::ShortBuf,
        }
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

