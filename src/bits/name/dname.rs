/// Uncompressed, absolute domain names.

use std::{cmp, fmt, hash, ops};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::parse::{Parseable, Parser};
use super::error::{DnameError, IndexError, RootNameError};
use super::label::Label;
use super::relative::{RelativeDname, DnameIter};
use super::traits::{ToLabelIter, ToDname, ToRelativeDname};


//------------ Dname ---------------------------------------------------------

/// An uncompressed, absolute domain name.
///
/// The type wraps a [`Bytes`] value and guarantees that it always contains
/// a correctly encoded, absolute domain name. It derefs to [`Bytes`] and
/// therefore to `[u8]` allowing you direct access to the underlying byte
/// slice. It does overide all applicable methods providing access to parts
/// of the byte slice, though, returning either `Dname` or [`RelativeDname`]s
/// instead.
///
/// You can construct a domain name from a string via the `FromStr` trait or
/// manually via a [`DnameBuilder`]. In addition, you can also parse it from
/// a message. This will, however, require the name to be uncompressed.
///
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`DnameBuilder`]: struct.DnameBuilder.html
#[derive(Clone)]
pub struct Dname {
    bytes: Bytes
}

/// # Creation and Conversion
///
impl Dname {
    /// Creates a domain name from the underlying bytes without any check.
    ///
    /// Since this will allow to actually construct an incorrectly encoded
    /// domain name value, the function is unsafe.
    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Dname { bytes }
    }

    /// Creates a domain name representing the root.
    ///
    /// The resulting domain name will consist of the root label only.
    pub fn root() -> Self {
        unsafe { Self::from_bytes_unchecked(Bytes::from_static(b"\0")) }
    }

    /// Creates a domain name from a bytes value.
    ///
    /// This will only succeed if `bytes` contains a properly encoded
    /// absolute domain name. Because the function checks, this will take
    /// a wee bit of time.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, DnameError> {
        if bytes.len() > 255 {
            return Err(DnameError::LongName);
        }
        {
            let mut tmp = bytes.as_ref();
            loop {
                let (label, tail) = Label::split_from(tmp)?;
                if label.is_root() {
                    if tail.is_empty() {
                        break;
                    }
                    else {
                        return Err(DnameError::TrailingData)
                    }
                }
                if tail.is_empty() {
                    return Err(DnameError::RelativeName)
                }
                tmp = tail;
            }
        }
        Ok(unsafe { Dname::from_bytes_unchecked(bytes) })
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Converts the domain name into its underlying bytes slice.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
 
    /// Converts the name into a relative name by dropping the root label.
    pub fn into_relative(mut self) -> RelativeDname {
        let len = self.bytes.len() - 1;
        self.bytes.truncate(len);
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes) }
    }
}


/// # Working with Labels
///
impl Dname {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.bytes.as_ref())
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
    pub fn last(&self) -> &Label {
        self.iter().next_back().unwrap()
    }

    /// Determines whether `base` is a prefix of `self`.
    /// 
    /// As this methods accepts only relative domain names, it will only
    /// allow checking for a ‘strict’ prefix.
    pub fn starts_with<N: ToRelativeDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns the part of the name indicated by start and end positions.
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
    type Err = DnameError;

    fn parse(parser: &mut Parser) -> Result<Self, DnameError> {
        let len = {
            let mut tmp = parser.peek();
            loop {
                if tmp.is_empty() {
                    return Err(DnameError::ShortData)
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
            return Err(DnameError::LongName);
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

impl ToDname for Dname {
    fn to_name(&self) -> Dname {
        self.clone()
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

