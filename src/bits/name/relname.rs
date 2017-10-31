
use std::{cmp, error, fmt, hash, ops};
use std::ascii::AsciiExt;
use std::str::FromStr;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use super::chain::Chain;
use super::from_str::{from_str, from_chars, FromStrError};
use super::label::{Label, SplitLabelError};
use super::traits::{ToLabelIter, ToRelativeDname};


//------------ RelativeDname -------------------------------------------------

#[derive(Clone)]
pub struct RelativeDname {
    bytes: Bytes,
}

/// # Creation and Conversion
///
impl RelativeDname {
    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        RelativeDname { bytes }
    }

    pub fn empty() -> Self {
        unsafe {
            RelativeDname::from_bytes_unchecked(Bytes::from_static(b""))
        }
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, RelativeDnameError> {
        if bytes.len() > 255 {
            return Err(RelativeDnameError::TooLong)
        }
        {
            let mut tmp = bytes.as_ref();
            while !tmp.is_empty() {
                let (label, tail) = Label::split_from(tmp)?;
                if label.is_root() {
                    return Err(RelativeDnameError::AbsoluteName);
                }
                tmp = tail;
            }
        }
        Ok( unsafe { RelativeDname::from_bytes_unchecked(bytes) })
    }

    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        from_chars(chars)
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

    pub fn chain<N: ToRelativeDname>(self, other: N) -> Chain<Self, N> {
        Chain::new(self, other)
    }
}

/// # Working with Labels
///
impl RelativeDname {
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

    /// Returns the number of dots in the string representation of the name.
    ///
    /// Specifically, returns a value equal to the number of labels minus one,
    /// except for an empty name where it returns a zero, also.
    pub fn ndots(&self) -> usize {
        if self.is_empty() { 0 }
        else {
            self.label_count() - 1
        }
    }

    pub fn starts_with(&self, base: &Self) -> bool {
        if base.len() > self.len() {
            return false
        }
        let start = &self.bytes.as_ref()[..base.len()];
        base.bytes.as_ref().eq_ignore_ascii_case(start)
    }

    pub fn ends_with(&self, base: &Self) -> bool {
        if base.len() > self.len() {
            return false
        }
        let (_, right) = match self.split_at(self.len() - base.len()) {
            Ok(res) => res,
            Err(_) => return false,
        };
        right.bytes.as_ref().eq_ignore_ascii_case(base.bytes.as_ref())
    }

    pub fn split_at(&self, mid: usize)
                    -> Result<(Self, Self), RelativeDnameError> {
        assert!(mid <= self.len());
        let left = Self::from_bytes(self.bytes.slice_to(mid))?;
        let right = unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_from(mid))
        };
        Ok((left, right))
    }

    pub fn split_first(&self) -> Option<(Self, Self)> {
        let first_end = match self.iter().next() {
            Some(label) => label.len() + 1,
            None => return None
        };
        if first_end == self.len() {
            Some((self.clone(), Self::empty()))
        }
        else {
            Some(unsafe {(
                Self::from_bytes_unchecked(self.bytes.slice_to(first_end)),
                Self::from_bytes_unchecked(self.bytes.slice_from(first_end))
            )})
        }
    }

    pub fn parent(&self) -> Option<Self> {
        self.split_first().map(|res| res.1)
    }

    pub fn strip_suffix(&mut self, base: &Self)
                        -> Result<(), StripSuffixError> {
        if self.ends_with(base) {
            self.bytes.split_off(base.len());
            Ok(())
        }
        else {
            Err(StripSuffixError)
        }
    }
}


//--- Composable

impl Composable for RelativeDname {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
}

//--- ToLabelIter and ToRelativeDname

impl<'a> ToLabelIter<'a> for RelativeDname {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToRelativeDname for RelativeDname {
}


//--- Deref and AsRef

impl ops::Deref for RelativeDname {
    type Target = Bytes;

    fn deref(&self) -> &Bytes {
        self.as_ref()
    }
}

impl AsRef<Bytes> for RelativeDname {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl AsRef<[u8]> for RelativeDname {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


//--- FromStr

impl FromStr for RelativeDname {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_str(s)
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a RelativeDname {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl PartialEq for RelativeDname {
    fn eq(&self, other: &Self) -> bool {
        // Comparing the whole slice while ignoring ASCII case is fine since
        // the length octets of the labels are in range 0...63 which aren’t
        // ASCII letters and compare uniquely.
        self.as_slice().eq_ignore_ascii_case(other.as_slice())
    }
}

impl Eq for RelativeDname { }


//--- PartialOrd and Ord

impl PartialOrd for RelativeDname {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl Ord for RelativeDname {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


//--- Hash

impl hash::Hash for RelativeDname {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Display and Debug

impl fmt::Display for RelativeDname {
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

impl fmt::Debug for RelativeDname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RelativeDname({})", self)
    }
}


//------------ DnameIter -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct DnameIter<'a> {
    slice: &'a [u8],
}

impl<'a> DnameIter<'a> {
    pub(super) fn new(slice: &'a [u8]) -> Self {
        DnameIter { slice }
    }
}

impl<'a> Iterator for DnameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        let (label, tail) = match Label::split_from(self.slice) {
            Ok(res) => res,
            Err(_) => return None,
        };
        self.slice = tail;
        Some(label)
    }
}

impl<'a> DoubleEndedIterator for DnameIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None
        }
        let mut tmp = self.slice;
        loop {
            let (label, tail) = Label::split_from(tmp).unwrap();
            if tail.is_empty() {
                let end = self.slice.len() - (label.len() + 1);
                self.slice = &self.slice[end..];
                return Some(label)
            }
            else {
                tmp = tail
            }
        }
    }
}


//------------ RelativeDnameError --------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativeDnameError {
    /// A bad label was encountered.
    BadLabel(SplitLabelError),

    /// The domain name was longer than 255 octets.
    TooLong,

    /// There were trailing octets.
    ///
    /// This happens when the root label is encountered in the middle of
    /// the octets.
    TrailingData,

    /// The root label was encountered.
    AbsoluteName,
}

impl From<SplitLabelError> for RelativeDnameError {
    fn from(err: SplitLabelError) -> Self {
        RelativeDnameError::BadLabel(err)
    }
}

impl error::Error for RelativeDnameError {
    fn description(&self) -> &str {
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => ::std::error::Error::description(err),
            TooLong => "name with more than 255 octets",
            TrailingData => "trailing data",
            AbsoluteName => "the name includes the root label",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for RelativeDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        use self::RelativeDnameError::*;

        match *self {
            BadLabel(ref err) => err.fmt(f),
            _ => f.write_str(self.description())
        }
    }
}


//------------ StripSuffixError ----------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StripSuffixError;

impl error::Error for StripSuffixError {
    fn description(&self) -> &str {
        "suffix not found"
    }
}

impl fmt::Debug for StripSuffixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "StripSuffixError".fmt(f)
    }
}

impl fmt::Display for StripSuffixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "suffix not found".fmt(f)
    }
}

