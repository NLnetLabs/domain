
use std::{cmp, error, fmt, hash, ops};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::parse::{Parseable, Parser, ShortParser};
use super::label::{Label, SplitLabelError};
use super::relname::{RelativeDname, RelativeDnameError, DnameIter};
use super::traits::{ToLabelIter, ToDname};


//------------ Dname ---------------------------------------------------------

#[derive(Clone)]
pub struct Dname {
    bytes: Bytes
}


/// # Creation and Conversion
///
impl Dname {
    pub fn root() -> Self {
        Dname { bytes: Bytes::from_static(b"\0") }
    }

    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Dname { bytes }
    }

    pub fn from_bytes(_bytes: Bytes) -> Result<Self, DnameError> {
        unimplemented!()
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}


/// # Working with Labels
///
impl Dname {
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.bytes.as_ref())
    }

    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    pub fn last(&self) -> Option<&Label> {
        self.iter().next_back()
    }

    pub fn starts_with(&self, base: &RelativeDname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let start = &self.bytes.as_ref()[..base.len()];
        base.as_slice().eq_ignore_ascii_case(start)
    }

    pub fn ends_with(&self, base: &RelativeDname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let (_, right) = match self.split_at(self.len() - base.len()) {
            Ok(res) => res,
            Err(_) => return false,
        };
        right.bytes.as_ref().eq_ignore_ascii_case(base.as_slice())
    }

    pub fn split_at(&self, mid: usize)
                    -> Result<(RelativeDname, Self), RelativeDnameError> {
        assert!(mid <= self.len());
        let left = RelativeDname::from_bytes(self.bytes.slice_to(mid))?;
        let right = unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_from(mid))
        };
        Ok((left, right))
    }

    pub fn split_first(&self) -> (RelativeDname, Option<Self>) {
        /*
        let (left, right) = self.clone().into_dname().split_first().unwrap();
        (left, right.into_fqdn().ok())
        */
        unimplemented!()
    }

    pub fn parent(&self) -> Option<Self> {
        self.split_first().1
    }

    /*
    pub fn strip_suffix(&self, base: &Self)
                        -> Result<RelativeDname, StripSuffixError> {
    }
    */
}

//--- Parseable and Composable

impl Parseable for Dname {
    type Err = ParseDnameError;

    fn parse(parser: &mut Parser) -> Result<Self, ParseDnameError> {
        let len = {
            let mut tmp = parser.peek();
            loop {
                if tmp.is_empty() {
                    return Err(ParseDnameError::ShortParser)
                }
                let (label, tail) = Label::split_from(tmp)?;
                tmp = tail;
                if label.is_root() {
                    break;
                }
            }
            parser.remaining() - tmp.len()
        };
        if len > 255 {
            return Err(ParseDnameError::BadDname(RelativeDnameError::TooLong));
        }
        Ok(unsafe {
            Self::from_bytes_unchecked(parser.parse_bytes(len).unwrap())
        })
    }
}

impl Composable for Dname {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
}


//--- ToLabelIter and ToDname

impl<'a> ToLabelIter<'a> for Dname {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToDname for Dname { }


//--- Deref and AsRef

impl ops::Deref for Dname {
    type Target = Bytes;

    fn deref(&self) -> &Bytes {
        self.as_ref()
    }
}

impl AsRef<Bytes> for Dname {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl AsRef<[u8]> for Dname {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a Dname {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl PartialEq for Dname {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_slice())
    }
}

impl Eq for Dname { }


//--- PartialOrd and Ord

impl PartialOrd for Dname {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl Ord for Dname {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


//--- Hash

impl hash::Hash for Dname {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Display and Debug

impl fmt::Display for Dname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        match iter.next() {
            Some(label) => label.fmt(f)?,
            None => return Ok(())
        }
        while let Some(label) = iter.next() {
            f.write_str(".")?;
            label.fmt(f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Dname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dname({})", self)
    }
}


//------------ DnameError ----------------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnameError {
    /// A bad domain name was encountered.
    BadDname(RelativeDnameError),

    /// The name didn’t end with the root label.
    RelativeDname,
}

impl From<RelativeDnameError> for DnameError {
    fn from(err: RelativeDnameError) -> Self {
        DnameError::BadDname(err)
    }
}

impl From<SplitLabelError> for DnameError {
    fn from(err: SplitLabelError) -> Self {
        DnameError::BadDname(err.into())
    }
}

impl error::Error for DnameError {
    fn description(&self) -> &str {
        use self::DnameError::*;

        match *self {
            BadDname(ref err) => err.description(),
            RelativeDname => "relative domain name",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::DnameError::*;

        match *self {
            BadDname(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for DnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ ParseDnameError -----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseDnameError {
    BadDname(RelativeDnameError),
    ShortParser,
}

impl From<RelativeDnameError> for ParseDnameError {
    fn from(err: RelativeDnameError) -> ParseDnameError {
        ParseDnameError::BadDname(err)
    }
}

impl From<SplitLabelError> for ParseDnameError {
    fn from(err: SplitLabelError) -> ParseDnameError {
        ParseDnameError::BadDname(err.into())
    }
}

impl From<ShortParser> for ParseDnameError {
    fn from(_: ShortParser) -> ParseDnameError {
        ParseDnameError::ShortParser
    }
}

impl error::Error for ParseDnameError {
    fn description(&self) -> &str {
        match *self {
            ParseDnameError::BadDname(ref err) => err.description(),
            ParseDnameError::ShortParser => ShortParser.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ParseDnameError::BadDname(ref err) => Some(err),
            ParseDnameError::ShortParser => Some(&ShortParser),
        }
    }
}

impl fmt::Display for ParseDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}

