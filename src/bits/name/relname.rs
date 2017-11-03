/// Uncompressed, relative domain names.

use std::{cmp, fmt, hash, ops};
use std::ascii::AsciiExt;
use std::str::FromStr;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use super::builder::DnameBuilder;
use super::chain::Chain;
use super::error::{FromStrError, IndexError, LongNameError,
                   RelativeDnameError, StripSuffixError};
use super::from_str::{from_str, from_chars};
use super::label::Label;
use super::traits::{ToLabelIter, ToRelativeDname};


//------------ RelativeDname -------------------------------------------------

/// An uncompressed, relative domain name.
///
/// A relative domain name is one that doesn’t end with the root label. As the
/// name suggests, it is relative to some other domain name. This type wraps
/// such a relative name similarly to as [`Dname`] wraps an absolute one. It
/// behaves very similarly to [`Dname`] taking into account differences when
/// slicing and dicing names.
///
/// [`Dname`]: struct.Dname.html
#[derive(Clone)]
pub struct RelativeDname {
    bytes: Bytes,
}

/// # Creation and Conversion
///
impl RelativeDname {
    /// Creates a relative domain name from a bytes value without checking.
    ///
    /// Since the content of the bytes value can be anything, really, this is
    /// an unsafe function.
    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        RelativeDname { bytes }
    }

    /// Creates an empty relative domain name.
    ///
    /// Determining what this could possibly be useful for is left as an
    /// excercise to the reader.
    pub fn empty() -> Self {
        unsafe {
            RelativeDname::from_bytes_unchecked(Bytes::from_static(b""))
        }
    }

    /// Creates a relative domain name representing the wildcard label.
    ///
    /// The wildcard label is intended to match any label. There are special
    /// rules for names with wildcard labels. Note that the comparison traits
    /// implemented for domain names do *not* consider wildcards and treat
    /// them as regular labels.
    pub fn wildcard() -> Self {
        unsafe {
            RelativeDname::from_bytes_unchecked(Bytes::from_static(b"\x01*"))
        }
    }

    /// Creates a relative domain name from a bytes value.
    ///
    /// This checks if `bytes` contains a properly encoded relative domain
    /// name and fails if it doesn’t.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, RelativeDnameError> {
        if bytes.len() > 255 {
            return Err(RelativeDnameError::LongName)
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

    /// Creates a relative domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// Since the resulting name is a relative name, the last character
    /// should not be a dot.
    ///
    /// If you have a string, you can also use the `FromStr` trait, which
    /// really does the same thing.
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        from_chars(chars)
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Converts the name into the underlying bytes value.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    /// Converts the name into a domain name builder for appending data.
    ///
    /// If the underlying bytes value can be converted into a [`BytesMut`]
    /// (via its [`try_mut`] method), the builder will use that direclty.
    /// Otherwise, it will create an all new [`BytesMut`] from the name’s
    /// content.
    ///
    /// [`BytesMut`]: ../../../bytes/struct.BytesMut.html
    /// [`try_mut`]: ../../../bytes/struct.BytesMut.html#method.try_mut
    pub fn into_builder(self) -> DnameBuilder {
        let bytes = match self.bytes.try_mut() {
            Ok(bytes) => bytes,
            Err(bytes) => bytes.as_ref().into()
        };
        unsafe { DnameBuilder::from_bytes(bytes) }
    }

    /// Creates a domain name by combining `self` with `other`.
    ///
    /// Depending on whether other is an absolute or relative domain name,
    /// the resulting name will behave like an absolute or relative name.
    /// 
    /// The method will fail if the combined length of the two names is
    /// greater than the size limit of 255. Note that in this case you will
    /// loose both `self` and `other`, so it might be worthwhile to check
    /// first.
    pub fn chain<N: Composable>(self, other: N)
                                -> Result<Chain<Self, N>, LongNameError> {
        Chain::new(self, other)
    }
}

/// # Working with Labels
///
impl RelativeDname {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.bytes.as_ref())
    }

    /// Returns the number of labels in the name.
    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    /// Returns a reference to the first label if the name isn’t empty.
    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    /// Returns a reference to the last label if the name isn’t empty.
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

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<N: ToRelativeDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToRelativeDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns a part of the name indicated by start and end positions.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. This will failed of either of these positions is not
    /// the start of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position points beyond the end of the
    /// name.
    pub fn slice(&self, begin: usize, end: usize)
                 -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, begin)?;
        IndexError::check(&self.bytes, end)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.slice(begin, end))
        })
    }

    /// Returns the part of the name starting at the given position.
    ///
    /// This will fail if the position isn’t the start of a label.
    ///
    /// # Panics
    ///
    /// The method panics if the position is beyond the end of the name.
    pub fn slice_from(&self, begin: usize) -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, begin)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_from(begin))
        })
    }

    /// Returns the part of the name ending before the given position.
    ///
    /// This will fail if the position isn’t the start of a label.
    ///
    /// # Panics
    ///
    /// The method panics if the position is beyond the end of the name.
    pub fn slice_to(&self, end: usize) -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, end)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_to(end))
        })
    }

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name ending at the position
    /// while the name starting at the position will be returned. The method
    /// will fail if `mid` is not the start of a new label.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is greater than the name’s length.
    pub fn split_off(&mut self, mid: usize) -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, mid)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.split_off(mid))
        })
    }

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name starting at the position
    /// while the name ending right before it will be returned. The method
    /// will fail if `mid` is not the start of a new label.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is greater than the name’s length.
    pub fn split_to(&mut self, mid: usize) -> Result<Self, IndexError> {
        IndexError::check(&self.bytes, mid)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(self.bytes.split_to(mid))
        })
    }

    /// Truncates the name to the given length.
    ///
    /// This will only work if the result would be a valid name. If `len` is
    /// greater than the current length, nothing will happen.
    pub fn truncate(&mut self, len: usize) -> Result<(), IndexError> {
        IndexError::check(&self.bytes, len)?;
        self.bytes.truncate(len);
        Ok(())
    }

    /// Splits off the first label.
    ///
    /// If there is at least one label in the name, returns the first label
    /// as a relative domain name with exactly one label and make `self`
    /// contain the domain name starting after that first label.
    pub fn split_first(&mut self) -> Option<Self> {
        if self.is_empty() {
            return None
        }
        let first_end = match self.iter().next() {
            Some(label) => label.len() + 1,
            None => return None
        };
        Some(unsafe {
            Self::from_bytes_unchecked(self.bytes.split_to(first_end))
        })
    }

    /// Reduces the name to its parent.
    ///
    /// Returns whether that actually happened, since if the name is already
    /// empty it can’t.
    pub fn parent(&mut self) -> bool {
        self.split_first().is_some()
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// This will fail if `base` isn’t actually a suffix, i.e., if
    /// [`ends_with`] doesn’t return `true`.
    ///
    /// [`ends_with`]: #method.ends_with
    pub fn strip_suffix<N: ToRelativeDname>(&mut self, base: &N)
                                            -> Result<(), StripSuffixError> {
        if self.ends_with(base) {
            self.bytes.split_off(base.compose_len());
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
    fn to_name(&self) -> RelativeDname {
        self.clone()
    }
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

/// An iterator over the labels in an uncompressed name.
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

