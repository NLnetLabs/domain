
use std::{cmp, error, fmt, hash, ops};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::parse::{Parseable, Parser, ShortParser};
use super::label::{Label, SplitLabelError};
use super::relname::{IndexError, RelativeDname, RelativeDnameError,
                     DnameIter};
use super::traits::{ToLabelIter, ToDname, ToRelativeDname};


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
    
    pub fn into_relative(mut self) -> RelativeDname {
        let len = self.bytes.len() - 1;
        self.bytes.truncate(len);
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes) }
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

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<N: ToRelativeDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns a part of the name indicated by start and end positions.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. Both positions must point to the begining of a label
    /// or an error will be returned.
    ///
    /// Because the returned domain is a relative name, the method will also
    /// return an error if the end equal to the length of the name. If you
    /// want to slice the entire end of the name including the final root
    /// label, you can use [`slice_from()`] instead.
    ///
    /// # Panics
    ///
    /// The method panics if either position points beyond the end of the
    /// name.
    ///
    /// [`slice_from()`]: #method.slice_from
    pub fn slice(&self, begin: usize, end: usize)
                 -> Result<RelativeDname, IndexError> {
        IndexError::check(&self.bytes, begin)?;
        IndexError::check(&self.bytes, end)?;
        if end == self.len() {
            return Err(IndexError)
        }
        Ok(unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.slice(begin, end))
        })
    }

    /// Returns the part of the name starting at the given position.
    ///
    /// This will fail if the position isn’t the start of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position points beyond the end of the
    /// name.
    pub fn slice_from(&self, begin: usize) -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, begin)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_from(begin))
        })
    }

    /// Returns the part of the name ending at the given position.
    ///
    /// This will fail if the position isn’t the start of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position points beyond the end of the
    /// name.
    pub fn slice_to(&self, end: usize) -> Result<RelativeDname, IndexError> {
        IndexError::check(&self.bytes, end)?;
        if end == self.len() {
            return Err(IndexError)
        }
        Ok(unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.slice_to(end))
        })
    }

    // XXX No `split_off()` since that would require `self` to mysteriously
    //     change into a `RelativeDname`. Would could make this move `self`,
    //     but then you would loose it upon an error which is not nice,
    //     either.

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name starting at the position
    /// while the name ending right before it will be returned. The method
    /// will fail if `mid` is not the start of a new label.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is greater than the name’s length.
    pub fn split_to(&mut self, mid: usize)
                    -> Result<RelativeDname, IndexError> {
        IndexError::check(&self.bytes, mid)?;
        Ok(unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.split_to(mid))
        })
    }

    // XXX No `truncate()` either.

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns an error and does nothing.
    pub fn split_first(&mut self) -> Result<RelativeDname, RootNameError> {
        if self.len() == 1 {
            return Err(RootNameError)
        }
        let end = self.iter().next().unwrap().len() + 1;
        Ok(unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.split_to(end))
        })
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// This will fail if the name consists of the root label only.
    pub fn parent(&mut self) -> Result<(), RootNameError> {
        self.split_first().map(|_| ())
    }

    // XXX And no `strip_suffix()`.
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


//------------ RootNameError -------------------------------------------------

/// An attempt was made to remove labels from a name that is only the root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootNameError;

impl error::Error for RootNameError {
    fn description(&self) -> &str {
        "operation not allowed on root name"
    }
}

impl fmt::Display for RootNameError {
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

