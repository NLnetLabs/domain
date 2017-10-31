
use std::{cmp, error, fmt, hash, ops};
use std::ascii::AsciiExt;
use std::str::FromStr;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use super::chain::Chain;
use super::fqdn::{Fqdn, RelativeDname};
use super::from_str::{from_str, from_chars, FromStrError};
use super::label::{Label, SplitLabelError};
use super::traits::{ToLabelIter, ToDname};


//------------ Dname ---------------------------------------------------------

#[derive(Clone)]
pub struct Dname {
    bytes: Bytes,
    is_absolute: bool,
}


/// # Creation and Conversion
///
impl Dname {
    pub fn root() -> Self {
        Dname {
            bytes: Bytes::from_static(b"\0"),
            is_absolute: true,
        }
    }

    pub fn empty() -> Self {
        Dname {
            bytes: Bytes::from_static(b""),
            is_absolute: false,
        }
    }

    pub(super) unsafe fn new_unchecked(bytes: Bytes, is_absolute: bool)
                                       -> Self {
        Dname { bytes, is_absolute }
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, DnameError> {
        if bytes.len() > 255 {
            return Err(DnameError::TooLong)
        }
        let is_absolute = {
            let mut tmp = bytes.as_ref();
            loop {
                if tmp.is_empty() {
                    break false
                }
                let (label, tail) = Label::split_from(tmp)?;
                if label.is_root() {
                    if tail.is_empty() {
                        break true;
                    }
                    else {
                        return Err(DnameError::TrailingData)
                    }
                }
                tmp = tail;
            }
        };
        Ok(Dname { bytes, is_absolute })
    }

    pub fn from_fqdn(name: Fqdn) -> Dname {
        Dname { bytes: name.into_bytes(), is_absolute: true }
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

    pub fn into_fqdn(self) -> Result<Fqdn, RelativeDname> {
        Fqdn::from_dname(self)
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub fn chain<N: ToDname>(self, other: N) -> Chain<Self, N> {
        Chain::new(self, other)
    }
}

/// # Properties
///
impl Dname {
    pub fn is_absolute(&self) -> bool {
        self.is_absolute
    }

    pub fn is_relative(&self) -> bool {
        !self.is_absolute
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

    /// Returns the number of dots in the string representation of the name.
    ///
    /// The method returns a value only for relative domain names. In this
    /// case, it returns a value equal to the number of labels minus one,
    /// except for an empty name where it returns a zero, also.
    pub fn ndots(&self) -> Option<usize> {
        if self.is_absolute { None }
        else if self.is_empty() { Some(0) }
        else {
            Some(self.label_count() - 1)
        }
    }

    pub fn starts_with(&self, base: &Dname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let start = &self.bytes.as_ref()[..base.len()];
        base.bytes.as_ref().eq_ignore_ascii_case(start)
    }

    pub fn ends_with(&self, base: &Dname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let (_, right) = match self.split_at(self.len() - base.len()) {
            Ok(res) => res,
            Err(_) => return false,
        };
        right.bytes.as_ref().eq_ignore_ascii_case(base.bytes.as_ref())
    }

    pub fn split_at(&self, mid: usize) -> Result<(Dname, Dname), DnameError> {
        assert!(mid <= self.len());
        let left = Dname::from_bytes(self.bytes.slice_to(mid))?;
        let right = Dname { 
            bytes: self.bytes.slice_from(mid),
            is_absolute: self.is_absolute
        };
        Ok((left, right))
    }

    pub fn split_first(&self) -> Option<(Dname, Dname)> {
        let first_end = match self.iter().next() {
            Some(label) => label.len() + 1,
            None => return None
        };
        if first_end == self.len() {
            Some((self.clone(), Dname::empty()))
        }
        else {
            Some((
                Dname {
                    bytes: self.bytes.slice_to(first_end),
                    is_absolute: false,
                },
                Dname {
                    bytes: self.bytes.slice_from(first_end),
                    is_absolute: self.is_absolute
                }
            ))
        }
    }

    pub fn parent(&self) -> Option<Dname> {
        self.split_first().map(|res| res.1)
    }

    pub fn strip_suffix(&mut self, base: &Dname)
                        -> Result<(), StripSuffixError> {
        if self.ends_with(base) {
            self.bytes.split_off(base.len());
            self.is_absolute = false;
            Ok(())
        }
        else {
            Err(StripSuffixError)
        }
    }
}


//--- Composable

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

impl ToDname for Dname {
    fn is_absolute(&self) -> bool {
        self.is_absolute
    }
}


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


//--- From and FromStr

impl From<Fqdn> for Dname {
    fn from(fqdn: Fqdn) -> Self {
        Self::from_fqdn(fqdn)
    }
}

impl FromStr for Dname {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        from_str(s)
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
        // Comparing the whole slice while ignoring ASCII case is fine since
        // the length octets of the labels are in range 0...63 which aren’t
        // ASCII letters and compare uniquely.
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


//------------ DnameError ----------------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnameError {
    /// A bad label was encountered.
    BadLabel(SplitLabelError),

    /// The domain name was longer than 255 octets.
    TooLong,

    /// There were trailing octets.
    ///
    /// This happens when the root label is encountered in the middle of
    /// the octets.
    TrailingData,
}

impl From<SplitLabelError> for DnameError {
    fn from(err: SplitLabelError) -> Self {
        DnameError::BadLabel(err)
    }
}

impl error::Error for DnameError {
    fn description(&self) -> &str {
        use self::DnameError::*;

        match *self {
            BadLabel(ref err) => ::std::error::Error::description(err),
            TooLong => "name with more than 255 octets",
            TrailingData => "trailing data",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::DnameError::*;

        match *self {
            BadLabel(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for DnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        use self::DnameError::*;

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

