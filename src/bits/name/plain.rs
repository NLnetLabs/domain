//! Uncompressed domain names.

use std::borrow::{self, Cow};
use std::cmp;
use std::error;
use std::fmt;
use std::hash;
use std::mem;
use std::ops::Deref;
use std::ptr;
use std::str;
use ::master::{Scanner, ScanResult};
use super::from_str::from_str;
use super::{DName, Label, NameLabels, NameLabelettes};


//------------ DNameSlice ----------------------------------------------------

/// A slice of a domain name.
///
/// The slice is guaranteed to contain a correctly encoded domain name. The
/// name may be relative or absolute but cannot support name compression.
///
/// Operations are available for iterating over the labels of the name and
/// breaking the name up into parts along the lines of label boundaries.
///
/// This is an unsized type. You will have to use it with some kind of
/// pointer, such as a reference or box. The sibling type owning the name
/// outright is [`DNameBuf`]. The two can be used together through the
/// `AsRef<DNameSlice>` trait or via a `Cow<DNameSlice>`.
///
/// [`DNameBuf`]: struct.DNameBuf.html
pub struct DNameSlice {
    inner: [u8]
}


/// # Creation and Convertion
///
impl DNameSlice {
    /// Creates a domain name slice from a bytes slice without checking.
    ///
    /// This is only safe if the input slice follows the encoding rules for
    /// a domain name and does not contain compressed labels.
    pub unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &DNameSlice {
        mem::transmute(bytes)
    }

    /// Creates a domain name from a bytes slice if it contains a valid name.
    ///
    /// The bytes slice must be exactly one correctly encoded, uncompressed
    /// domain name. If it isn’t or if it contains trailing data, the
    /// function returns `None`.
    ///
    /// As this function traverses the slice to check that it is correctly
    /// encoded, it may take a bit of time.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        let mut tmp = bytes;
        while !tmp.is_empty() {
            let (label, tail) = match Label::split_from(tmp) {
                Some(data) => data,
                None => return None
            };
            if label.is_root() && !tail.is_empty() {
                return None
            }
            tmp = tail;
        }
        Some(unsafe { DNameSlice::from_bytes_unsafe(bytes) })
    }

    /// Creates a domain name slice for the root domain name.
    pub fn root() -> &'static DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(b"\0") }
    }

    /// Creates an empty domain name slice.
    pub fn empty() -> &'static DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(b"") }
    }

    /// Returns a reference to the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Converts the domain name slice to an owned domain name.
    pub fn to_owned(&self) -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(self.inner.to_owned()) }
    }
}

/// Unsafely creates a domain name slice from a bytes slice.
///
/// This function exists to give sibling modules a shot at creating their
/// very own unsafe domain names without opening this path up to world and
/// dog.
pub unsafe fn slice_from_bytes_unsafe(bytes: &[u8]) -> &DNameSlice {
    DNameSlice::from_bytes_unsafe(bytes)
}


/// # Properties
///
impl DNameSlice {
    /// Checks whether the domain name is absolute.
    ///
    /// A domain name is absolute if it ends with an empty normal label
    /// (the root label).
    pub fn is_absolute(&self) -> bool {
        self.last().map_or(false, |l| l.is_root())
    }

    /// Checks whether the domain name is relative, ie., not absolute.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }
}


/// # Iterating over Labels
///
impl DNameSlice {
    /// Produces an iterator over the labels in the name.
    pub fn labels(&self) -> NameLabels {
        NameLabels::from_slice(self)
    }

    /// Produces an iterator over the labelettes in the name.
    pub fn labelettes(&self) -> NameLabelettes {
        NameLabelettes::new(self.labels())
    }

    /// Returns the number of labels in `self`.
    pub fn len(&self) -> usize {
        self.labels().count()
    }

    /// Checks whether the domain name is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the first label or `None` if the name is empty.
    pub fn first(&self) -> Option<&Label> {
        self.labels().next()
    }

    /// Returns the last label or `None` if the name is empty.
    pub fn last(&self) -> Option<&Label> {
        self.labels().last()
    }

    /// Returns the number of dots if this is a relative name.
    ///
    /// Returns `None` if this is an absolute name.
    pub fn ndots(&self) -> Option<usize> {
        let mut res = 0;
        for label in self.labels() {
            if label.is_root() {
                return None
            }
            res += 1;
        }
        Some(res)
    }
}


/// # Working with Parts
///
impl DNameSlice {
    /// Returns the first label and the remaining domain name.
    ///
    /// Returns `None` only if the name is empty (which is different from a
    /// name containing only the root label).
    pub fn split_first(&self) -> Option<(&Label, &Self)> {
        Label::split_from(&self.inner).map(|(label, tail)| {
            (label, unsafe { DNameSlice::from_bytes_unsafe(tail) })
        })
    }

    /// Returns the domain name without its leftmost label.
    ///
    /// Returns `None` for an empty domain name and a domain name consisting
    /// of only the root label. Returns an empty domain name for a single
    /// label relative domain name.
    pub fn parent(&self) -> Option<&DNameSlice> {
        match self.split_first() {
            None => None,
            Some((left, right)) => {
                if left.is_root() { None }
                else { Some(right) }
            }
        }
    }

    /// Returns a domain name slice relative to `base`.
    ///
    /// This fails if `base` isn’t a suffix of `self`.
    pub fn strip_suffix<'a, N: DName>(&'a self, base: &'a N)
                                      -> Result<Cow<'a, Self>,
                                                StripSuffixError> {
        let mut self_iter = self.labelettes();
        let mut base_iter = base.labelettes();
        loop {
            let base_ltte = match base_iter.next_back() {
                Some(ltte) => ltte,
                None => {
                    return Ok(self_iter.to_name())
                }
            };
            let self_ltte = match self_iter.next_back() {
                Some(ltte) => ltte,
                None => {
                    return Err(StripSuffixError)
                }
            };
            if base_ltte != self_ltte {
                return Err(StripSuffixError)
            }
        }
    }

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<N: DName>(&self, base: &N) -> bool {
        let mut self_iter = self.labelettes();
        let mut base_iter = base.labelettes();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (_, None) => return true,
                (None, Some(_)) =>  return false
            }
        }
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: DName>(&self, base: &N) -> bool {
        let mut self_iter = self.labelettes().rev();
        let mut base_iter = base.labelettes().rev();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (_, None) => return true,
                (None, Some(_)) =>  return false
            }
        }
    }

    /// Creates an owned domain name made absolute if necessary.
    ///
    /// If `self` is already an absolute domain name, nothing happens.
    pub fn join<N: DName>(&self, base: &N) -> Result<DNameBuf, PushError> {
        let mut res = self.to_owned();
        try!(res.append(base));
        Ok(res)
    }
}


//--- DName

impl<'a> DName for &'a DNameSlice {
    fn to_cow(&self) -> Cow<DNameSlice> {
        Cow::Borrowed(self)
    }

    fn labels(&self) -> NameLabels {
        DNameSlice::labels(self)
    }
}


//--- From

impl<'a> From<&'a Label> for &'a DNameSlice {
    fn from(label: &'a Label) -> &'a DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(label.as_bytes()) }
    }
}


//--- AsRef

impl AsRef<DNameSlice> for DNameSlice {
    fn as_ref(&self) -> &Self {
        self
    }
}


//--- ToOwned

impl borrow::ToOwned for DNameSlice {
    type Owned = DNameBuf;

    fn to_owned(&self) -> Self::Owned {
        self.to_owned()
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a DNameSlice {
    type Item = &'a Label;
    type IntoIter = NameLabels<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.labels()
    }
}


//--- PartialEq and Eq

impl PartialEq for DNameSlice {
    fn eq(&self, other: &Self) -> bool {
        let self_iter = self.labelettes();
        let other_iter = other.labelettes();
        self_iter.eq(other_iter)
    }
}

impl<N: DName> PartialEq<N> for DNameSlice {
    fn eq(&self, other: &N) -> bool {
        let self_iter = self.labelettes();
        let other_iter = other.labelettes();
        self_iter.eq(other_iter)
    }
}

impl PartialEq<str> for DNameSlice {
    fn eq(&self, other: &str) -> bool {
        use std::str::FromStr;

        let other = match DNameBuf::from_str(other) {
            Ok(other) => other,
            Err(_) => return false
        };
        self.eq(&other)
    }
}

impl Eq for DNameSlice { }


//--- PartialOrd and Ord

impl PartialOrd for DNameSlice {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        let self_iter = self.labelettes().rev();
        let other_iter = other.labelettes().rev();
        self_iter.partial_cmp(other_iter)
    }
}

impl<N: DName> PartialOrd<N> for DNameSlice {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        let self_iter = self.labelettes().rev();
        let other_iter = other.labelettes().rev();
        self_iter.partial_cmp(other_iter)
    }
}

impl Ord for DNameSlice {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let self_iter = self.labelettes().rev();
        let other_iter = other.labelettes().rev();
        self_iter.cmp(other_iter)
    }
}


//--- Hash

impl hash::Hash for DNameSlice {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.labelettes() {
            item.hash(state)
        }
    }
}


//--- std::fmt traits

impl fmt::Display for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{}", label));
        }
        for label in labels {
            try!(write!(f, ".{}", label))
        }
        Ok(())
    }
}

impl fmt::Octal for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:o}", label));
        }
        for label in labels {
            try!(write!(f, ".{:o}", label))
        }
        Ok(())
    }
}

impl fmt::LowerHex for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:x}", label));
        }
        for label in labels {
            try!(write!(f, ".{:x}", label))
        }
        Ok(())
    }
}

impl fmt::UpperHex for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:X}", label));
        }
        for label in labels {
            try!(write!(f, ".{:X}", label))
        }
        Ok(())
    }
}

impl fmt::Binary for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:b}", label));
        }
        for label in labels {
            try!(write!(f, ".{:b}", label))
        }
        Ok(())
    }
}

impl fmt::Debug for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("DNameSlice("));
        try!(fmt::Display::fmt(self, f));
        f.write_str(")")
    }
}


//------------ DNameBuf ------------------------------------------------------

/// An owned complete domain name.
///
/// A value of this type contains a vector with a correctly encoded,
/// uncompressed domain name. It derefs to [`DNameSlice`] in order to make
/// all its methods available for working with domain names.
///
/// In addition, it provides a number of methods to add labels or entire
/// names to its end.
///
/// `DNameBuf` values can be created from string via the `std::str::FromStr`
/// trait. Such strings must be in the usual zonefile encoding.
///
/// [`DNameSlice`]: struct.DNameSlice.html
#[derive(Clone, Default)]
pub struct DNameBuf {
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl DNameBuf {
    /// Creates a new empty domain name.
    pub fn new() -> Self {
        DNameBuf{inner: Vec::new()}
    }

    /// Creates a new empty name with the given amount of space reserved.
    pub fn with_capacity(capacity: usize) -> DNameBuf {
        DNameBuf{inner: Vec::with_capacity(capacity)}
    }

    /// Creates an owned domain name using an existing bytes vector.
    ///
    /// If the content of the bytes vector does not constitute a correctly
    /// encoded uncompressed domain name, the function will fail.
    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if DNameSlice::from_bytes(&vec).is_none() {
            return None
        }
        Some(unsafe { Self::from_vec_unsafe(vec) })
    }

    /// Creates an owned domain name from a bytes vec without checking.
    unsafe fn from_vec_unsafe(vec: Vec<u8>) -> Self {
        DNameBuf { inner: vec }
    }

    /// Creates an owned domain name from the labels of the iterator.
    pub fn try_from_iter<'a, T>(iter: T) -> Result<Self, PushError>
                         where T: IntoIterator<Item=&'a Label> {
        let mut res = DNameBuf::new();
        res.append_iter(iter)?;
        Ok(res)
    }

    /// Creates an owned domain name by reading it from a scanner.
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        scanner.scan_dname(origin)
    }

    /// Returns a new owned domain name consisting only of the root label. 
    pub fn root() -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(vec![0]) }
    }

    /// Returns a reference to a slice of the domain name.
    pub fn as_slice(&self) -> &DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(&self.inner) }
    }

    /// Extracts the underlying vector from the name.
    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

/// Creates an owned domain name from a vector without checking.
///
/// This function is intended for sibling modules and is not exported at all.
pub unsafe fn buf_from_vec_unsafe(vec: Vec<u8>) -> DNameBuf {
    DNameBuf::from_vec_unsafe(vec)
}


/// Manipulations
///
impl DNameBuf {
    /// Extends a relative name with a label.
    ///
    /// If the name is absolute, nothing happens.
    pub fn push(&mut self, label: &Label) -> Result<(), PushError> {
        if self.is_absolute() {
            return Ok(())
        }
        if self.len() + label.len() > 255 {
            return Err(PushError)
        }
        self.inner.extend_from_slice(label.as_bytes());
        Ok(())
    }

    /// Pushes a normal label to the end of a relative name.
    ///
    /// If the name is absolute, nothing happens. If the resulting name would
    /// exceed the maximum allowd length of 255 octets, returns an error.
    ///
    /// # Panics
    ///
    /// The method panics if `content` is longer that 63 bytes.
    pub fn push_normal(&mut self, content: &[u8]) -> Result<(), PushError> {
        if self.is_absolute() {
            return Ok(())
        }
        assert!(content.len() < 64);
        if self.len() + content.len() + 1 > 255 {
            Err(PushError)
        }
        else {
            self.inner.push(content.len() as u8);
            self.inner.extend_from_slice(content);
            Ok(())
        }
    }

    /// Pushes a binary label to the end of a relative name.
    ///
    /// The binary label will be `count` bits long and contain the bits
    /// from `bits`. If `bits` is too short, the label will be filled up
    /// with zero bits. If `bits` is too long, it will be trimmed to the
    /// right length.
    ///
    /// If the name is absolute, nothing happens. If the resulting name would
    /// exceed the maximum allowd length of 255 octets, returns an error.
    ///
    /// # Panics
    ///
    /// The method panics if `count` is larger than 256.
    pub fn push_binary(&mut self, count: usize, bits: &[u8])
                       -> Result<(), PushError> {
        if self.is_absolute() {
            return Ok(())
        }
        assert!(count <= 256);
        let bitlen = (count - 1) / 8 + 1;
        if self.len() + bitlen + 2 > 255 {
            return Err(PushError)
        }
        self.inner.push(0x41);
        self.inner.push(if count == 256 { 0 } else { count as u8 });
        if bits.len() < bitlen {
            self.inner.extend_from_slice(bits);
            let new_len = self.inner.len() + (bitlen - bits.len());
            self.inner.resize(new_len, 0);
        }
        else {
            let bits = &bits[..bitlen];
            self.inner.extend_from_slice(bits);

            // Set the unused bits to zero as required by RFC 2673.
            let mask = 0xFF ^ (0xFF >> (count % 8));
            let idx = self.inner.len() - 1;
            self.inner[idx] &= mask;
        }
        Ok(())
    }

    /// Pushes an empty binary label of the given length to the domain name.
    ///
    /// Upon success the function returns a mutable reference to the bytes
    /// slice of the bits of the binary label.
    ///
    /// If the name is already absolute, returns `Ok(None)`. If the resulting
    /// name would exceed the maximum allowd length of 255 octets, returns an
    /// error.
    ///
    /// # Panics
    ///
    /// The method panics if `count` is larger than 256.
    pub fn push_empty_binary(&mut self, count: usize)
                             -> Result<Option<&mut [u8]>, PushError> {
        if self.is_absolute() {
            return Ok(None)
        }
        assert!(count <= 256);
        let bitlen = (count - 1) / 8 + 1;
        if self.len() + bitlen + 2 > 256 {
            return Err(PushError)
        }
        self.inner.push(0x41);
        self.inner.push(if count == 256 { 0 } else { count as u8 });
        let pos = self.len();
        self.inner.resize(pos + bitlen, 0);
        Ok(Some(&mut self.inner[pos..]))
    }

    /// Extends a relative name with a domain name.
    ///
    /// If the name is already absolute, nothing will be appended and the
    /// name remains unchanged. If by appending the name would exceed the
    /// maximum allowed length of 255 octets, an error will be returned and
    /// the name remains unchanged, too.
    pub fn append<N: DName>(&mut self, name: &N) -> Result<(), PushError> {
        if self.is_absolute() {
            return Ok(())
        }
        let len = self.inner.len();
        for label in name.labels() {
            if let Err(err) = self.push(label.as_ref()) {
                self.inner.truncate(len);
                return Err(err)
            }
        }
        Ok(())
    }

    /// Makes a domain name absolute if it isn’t yet by appending root.
    ///
    /// This may fail if the name is already 255 octets long.
    pub fn append_root(&mut self) -> Result<(), PushError> {
        self.append(&DNameSlice::root())
    }

    /// Appends the content of an iterator to the end of the name.
    pub fn append_iter<'a, T>(&mut self, iter: T) -> Result<(), PushError>
                       where T: IntoIterator<Item=&'a Label> {
        for item in iter {
            self.push(item)?
        }
        Ok(())
    }

    /// Removes the first label.
    ///
    /// After this operation, the content of `self` is `self.parent()`.
    ///
    /// # Panics
    ///
    /// Panics if the name is empty.
    pub fn remove_first(&mut self) {
        let offset = self.split_first().expect("remove_first on empty name")
                         .0.len() as isize;
        let len = self.inner.len();
        unsafe {
            let ptr = self.inner.as_mut_ptr();
            ptr::copy(ptr.offset(offset), ptr, len);
        }
    }
}


//--- DName

impl DName for DNameBuf {
    fn to_cow(&self) -> Cow<DNameSlice> {
        Cow::Borrowed(self)
    }

    fn labels(&self) -> NameLabels {
        DNameSlice::labels(self)
    }
}

impl<'a> DName for &'a DNameBuf {
    fn to_cow(&self) -> Cow<DNameSlice> {
        Cow::Borrowed(self)
    }

    fn labels(&self) -> NameLabels {
        DNameSlice::labels(self)
    }
}


//--- From, FromStr, FromIterator

impl<'a> From<&'a DNameSlice> for DNameBuf {
    fn from(name: &'a DNameSlice) -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(Vec::from(&name.inner)) }
    }
}

impl<'a> From<&'a Label> for DNameBuf {
    fn from(label: &'a Label) -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(Vec::from(label.as_bytes())) }
    }
}


impl str::FromStr for DNameBuf {
    type Err = FromStrError;

    /// Creates a new domain name from a string.
    ///
    /// The string must follow zone file conventions. It must only contain
    /// printable ASCII characters and no whitespace. Invidual labels are
    /// separated by a dot. A backslash escapes the next character unless
    /// that is a `0`, `1`, or `2`, in which case the next three characters
    /// are the byte value in decimal representation.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "." {
            return Ok(DNameBuf::root())
        }
        from_str(s).map(|vec| unsafe { DNameBuf::from_vec_unsafe(vec) })
    }
}


//--- Deref, Borrow, and AsRef

impl Deref for DNameBuf {
    type Target = DNameSlice;

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl borrow::Borrow<DNameSlice> for DNameBuf {
    fn borrow(&self) -> &DNameSlice {
        self
    }
}

impl AsRef<DNameSlice> for DNameBuf {
    fn as_ref(&self) -> &DNameSlice {
        self
    }
}


//--- PartialEq and Eq

impl<N: DName> PartialEq<N> for DNameBuf {
    fn eq(&self, other: &N) -> bool {
        self.deref().eq(other)
    }
}

impl PartialEq<str> for DNameBuf {
    fn eq(&self, other: &str) -> bool {
        self.deref().eq(other)
    }
}

impl Eq for DNameBuf { }


//--- PartialOrd and Ord

impl<N: DName> PartialOrd<N> for DNameBuf {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other)
    }
}

impl Ord for DNameBuf {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl hash::Hash for DNameBuf {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- std::fmt traits

impl fmt::Display for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.deref(), f)
    }
}

impl fmt::Octal for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Octal::fmt(self.deref(), f)
    }
}

impl fmt::LowerHex for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.deref(), f)
    }
}

impl fmt::UpperHex for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(self.deref(), f)
    }
}

impl fmt::Binary for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(self.deref(), f)
    }
}

impl fmt::Debug for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("DNameBuf("));
        try!(fmt::Display::fmt(self.deref(), f));
        f.write_str(")")
    }
}


//------------ FromStrError --------------------------------------------

#[derive(Clone, Debug)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// An empty label was encountered.
    EmptyLabel,

    /// A domain name label has more than 63 octets.
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter,

    /// An illegal binary label sequence was encountered.
    IllegalBinary,

    /// A relative name was encountered.
    RelativeName,

    /// The name has more than 255 characters.
    LongName,
}

impl error::Error for FromStrError {
    fn description(&self) -> &str {
        use self::FromStrError::*;

        match *self {
            UnexpectedEnd => "unexpected end of input",
            EmptyLabel => "an empty label was encountered",
            LongLabel => "domain name label with more than 63 octets",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
            IllegalBinary => "illegal binary label",
            RelativeName => "relative name",
            LongName => "domain name with more than 255 octets",
        }
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to append content to an owned domain name.
///
/// The only error that can happen is that by appending something the name
/// would exceed the size limit of 255 octets.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PushError;

impl error::Error for PushError {
    fn description(&self) -> &str {
        "adding a label would exceed the size limit"
    }
}

impl fmt::Debug for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "PushError".fmt(f)
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "adding a label would exceed the size limit".fmt(f)
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


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use super::*;


    //--- DNameSlice

    fn slice(slice: &[u8]) -> &DNameSlice {
        DNameSlice::from_bytes(slice).unwrap()
    }

    #[test]
    fn slice_from_bytes() {
        assert!(slice(b"\x03foo\x03bar\x00").is_absolute());
        assert!(slice(b"\x00").is_absolute());
        assert!(slice(b"\x03foo\x03bar").is_relative());
        assert!(slice(b"").is_relative());
        assert!(DNameSlice::from_bytes(b"\x03foo\x03ba").is_none());
        assert!(DNameSlice::from_bytes(b"\x03foo\x03ba").is_none());
        assert!(DNameSlice::from_bytes(b"\x03foo\x03bar\x00\x03foo").is_none());
    }

    #[test]
    fn slice_display() {
        assert_eq!(format!("{}", slice(b"\x03foo")), "foo");
        assert_eq!(format!("{}", slice(b"\x03foo\x00")), "foo.");
        assert_eq!(format!("{}", slice(b"\x03foo\x03bar")), "foo.bar");
        assert_eq!(format!("{}", slice(b"\x03foo\x03bar\x00")), "foo.bar.");
        assert_eq!(format!("{}", slice(b"\x03f\xf0o")), "f\\240o");
        assert_eq!(format!("{}", slice(b"\x03f\x0Ao")), "f\\010o");
        assert_eq!(format!("{}", slice(b"\x03f.o")), "f\\.o");
        assert_eq!(format!("{}", slice(b"\x03f\\o")), "f\\\\o");

        assert_eq!(format!("{}", slice(b"\x41\x08\x22")), "\\[34.0.0.0/8]");
        assert_eq!(format!("{:o}", slice(b"\x41\x08\x22\x00")),
                   "\\[o42/8].");
        assert_eq!(format!("{:x}", slice(b"\x41\x08\x22")), "\\[x22/8]");
    }

    #[test]
    fn slice_methods() {
        let empty = slice(b"");
        let dot = slice(b"\x00");
        let foo = slice(b"\x03foo");
        let bar = slice(b"\x03bar");
        let foodot = slice(b"\x03foo\x00");
        let bardot = slice(b"\x03bar\x00");
        let foobar = slice(b"\x03foo\x03bar");
        let foobardot = slice(b"\x03foo\x03bar\x00");

        assert!(!empty.is_absolute()); assert!(empty.is_relative());
        assert!(!foo.is_absolute()); assert!(foo.is_relative());
        assert!(!foobar.is_absolute()); assert!(foobar.is_relative());
        assert!(dot.is_absolute()); assert!(!dot.is_relative());
        assert!(foodot.is_absolute()); assert!(!foodot.is_relative());
        assert!(foobardot.is_absolute()); assert!(!foobardot.is_relative());

        assert_eq!(empty.len(), 0); assert_eq!(dot.len(), 1);
        assert_eq!(foo.len(), 1); assert_eq!(foodot.len(), 2);
        assert_eq!(foobar.len(), 2); assert_eq!(foobardot.len(), 3);

        assert!(empty.is_empty()); assert!(!dot.is_empty());
        assert!(!foo.is_empty());

        assert_eq!(empty.first(), None);
        assert_eq!(dot.first().unwrap().as_str().unwrap(), "");
        assert_eq!(foo.first().unwrap().as_str().unwrap(), "foo");
        assert_eq!(foodot.first().unwrap().as_str().unwrap(), "foo");
        assert_eq!(foobar.first().unwrap().as_str().unwrap(), "foo");
        assert_eq!(foobardot.first().unwrap().as_str().unwrap(), "foo");

        assert_eq!(empty.last(), None);
        assert_eq!(dot.last().unwrap().as_str().unwrap(), "");
        assert_eq!(foo.last().unwrap().as_str().unwrap(), "foo");
        assert_eq!(foodot.last().unwrap().as_str().unwrap(), "");
        assert_eq!(foobar.last().unwrap().as_str().unwrap(), "bar");
        assert_eq!(foobardot.last().unwrap().as_str().unwrap(), "");

        assert_eq!(empty.split_first(), None);
        assert_eq!(dot.split_first().unwrap().0.as_str().unwrap(), "");
        assert_eq!(dot.split_first().unwrap().1.as_bytes(), b"");
        assert_eq!(foo.split_first().unwrap().0.as_str().unwrap(), "foo");
        assert_eq!(foo.split_first().unwrap().1.as_bytes(), b"");
        assert_eq!(foodot.split_first().unwrap().0.as_str().unwrap(), "foo");
        assert_eq!(foodot.split_first().unwrap().1.as_bytes(), b"\x00");
        assert_eq!(foobar.split_first().unwrap().0.as_str().unwrap(), "foo");
        assert_eq!(foobar.split_first().unwrap().1.as_bytes(), b"\x03bar");
        assert_eq!(foobardot.split_first().unwrap().0.as_str().unwrap(),
                   "foo");
        assert_eq!(foobardot.split_first().unwrap().1.as_bytes(),
                   b"\x03bar\x00");

        assert_eq!(empty.parent(), None);
        assert_eq!(dot.parent(), None);
        assert_eq!(foo.parent().unwrap().as_bytes(), b"");
        assert_eq!(foodot.parent().unwrap().as_bytes(), b"\x00");
        assert_eq!(foobar.parent().unwrap().as_bytes(), b"\x03bar");
        assert_eq!(foobardot.parent().unwrap().as_bytes(), b"\x03bar\x00");

        assert!(empty.starts_with(&empty)); assert!(!empty.starts_with(&dot));
        assert!(dot.starts_with(&empty)); assert!(dot.starts_with(&dot));
            assert!(!dot.starts_with(&foo));
        assert!(foo.starts_with(&empty)); assert!(foo.starts_with(&foo));
            assert!(!foo.starts_with(&dot)); assert!(!foo.starts_with(&bar));
            assert!(!foo.starts_with(&foodot));
        assert!(foobar.starts_with(&empty));
            assert!(foobar.starts_with(&foo));
            assert!(foobar.starts_with(&foobar));
            assert!(!foobar.starts_with(&foobardot));
            assert!(!foobar.starts_with(&dot));
            assert!(!foobar.starts_with(&bar));
        assert!(foobardot.starts_with(&empty));
            assert!(foobardot.starts_with(&foo));
            assert!(foobardot.starts_with(&foobar));
            assert!(foobardot.starts_with(&foobardot));
            assert!(!foobardot.starts_with(&dot));
            assert!(!foobardot.starts_with(&bar));

        assert!(empty.ends_with(&empty)); assert!(!empty.ends_with(&dot));
            assert!(!empty.ends_with(&foo));
        assert!(dot.ends_with(&empty)); assert!(dot.ends_with(&dot));
            assert!(!empty.ends_with(&foo));
        assert!(foo.ends_with(&empty)); assert!(dot.ends_with(&dot));
            assert!(foo.ends_with(&foo)); assert!(!foo.ends_with(&bar));
            assert!(!foo.ends_with(&foodot));
        assert!(foodot.ends_with(&empty)); assert!(foodot.ends_with(&dot));
            assert!(!foodot.ends_with(&foo)); assert!(!foodot.ends_with(&bar));
            assert!(foodot.ends_with(&foodot));
        assert!(foobar.ends_with(&empty)); assert!(!foobar.ends_with(&dot));
            assert!(!foobar.ends_with(&foo)); assert!(foobar.ends_with(&bar));
        assert!(foobardot.ends_with(&empty));
            assert!(foobardot.ends_with(&dot));
            assert!(!foobardot.ends_with(&foo));
            assert!(foobardot.ends_with(&bardot));
            assert!(foobardot.ends_with(&foobardot));

        assert_eq!(empty.join(&empty).unwrap(), empty);
        assert_eq!(empty.join(&dot).unwrap(), dot);
        assert_eq!(empty.join(&foo).unwrap(), foo);
        assert_eq!(empty.join(&foodot).unwrap(), foodot);
        assert_eq!(dot.join(&empty).unwrap(), dot);
        assert_eq!(dot.join(&dot).unwrap(), dot);
        assert_eq!(dot.join(&foo).unwrap(), dot);
        assert_eq!(dot.join(&foodot).unwrap(), dot);
        assert_eq!(foo.join(&empty).unwrap(), foo);
        assert_eq!(foo.join(&dot).unwrap(), foodot);
        assert_eq!(foo.join(&bar).unwrap(), foobar);
        assert_eq!(foo.join(&bardot).unwrap(), foobardot);
        assert_eq!(foodot.join(&empty).unwrap(), foodot);
        assert_eq!(foodot.join(&dot).unwrap(), foodot);
        assert_eq!(foodot.join(&foo).unwrap(), foodot);
        assert_eq!(foodot.join(&foodot).unwrap(), foodot);
    }

    //--- DNameBuf
    fn buf(bytes: &[u8]) -> DNameBuf {
        DNameBuf::from_vec(Vec::from(bytes)).unwrap()
    }

    #[test]
    fn buf_from_vec() {
        assert_eq!(buf(b"\x03foo\x03bar\x00").as_bytes(),
                   b"\x03foo\x03bar\x00");
        assert_eq!(buf(b"\x00").as_bytes(), b"\x00");
        assert_eq!(buf(b"\x03foo\x03bar").as_bytes(), b"\x03foo\x03bar");
        assert_eq!(buf(b"").as_bytes(), b"");
        assert!(DNameBuf::from_vec(Vec::from(&b"\x03foo\x03ba"[..])).is_none());
        assert!(DNameBuf::from_vec(Vec::from(&b"\x03foo\x03ba"[..])).is_none());
        assert!(DNameBuf::from_vec(Vec::from(&b"\x03foo\x03bar\x00\x03foo"[..]))
                         .is_none());
    }

    #[test]
    fn buf_push() {
        let suffix_buf = DNameBuf::from_str("bazz").unwrap();
        let suffix = suffix_buf.first().unwrap();
        
        let mut name = DNameBuf::from_str("foo.bar").unwrap();
        name.push(&suffix).unwrap();
        assert_eq!(name.to_string(), "foo.bar.bazz");
        let mut name = DNameBuf::from_str("foo.bar.").unwrap();
        name.push(&suffix).unwrap();
        assert_eq!(name.to_string(), "foo.bar.");
    }

    #[test]
    fn buf_append() {
        let suffix = DNameBuf::from_str("wobble.wibble.").unwrap();

        let mut name = DNameBuf::from_str("foo.bar").unwrap();
        name.append(&suffix).unwrap();
        assert_eq!(name.to_string(), "foo.bar.wobble.wibble.");
        let mut name = DNameBuf::from_str("foo.bar.").unwrap();
        name.append(&suffix).unwrap();
        assert_eq!(name.to_string(), "foo.bar.");
    }
}
