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
use super::{DName, Label, NameIter, RevNameIter};


//------------ DNameSlice ----------------------------------------------------

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
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &DNameSlice {
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
    ///
    pub fn is_absolute(&self) -> bool {
        self.last().map_or(false, |l| l.is_root())
    }

    /// Checks whether the domain name is relative, ie., not absolute.
    ///
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }
}


/// # Iterating over Labels
///
impl DNameSlice {
    /// Produces an iterator over the labels in the name.
    pub fn iter(&self) -> NameIter {
        NameIter::from_slice(self)
    }

    /// Produces an iterator over the labels in reverse order.
    pub fn rev_iter(&self) -> RevNameIter {
        RevNameIter::new(self.iter())
    }

    /// Returns the number of labels in `self`.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Checks whether the domain name is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the first label or `None` if the name is empty.
    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    /// Returns the last label or `None` if the name is empty.
    pub fn last(&self) -> Option<&Label> {
        self.iter().last()
    }

    /// Returns the number of dots if this is a relative name.
    pub fn ndots(&self) -> Option<usize> {
        let mut res = 0;
        for label in self.iter() {
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

    /// Determines whether `base` is a prefix of `self`.
    pub fn start_with<N: DName>(&self, base: &N) -> bool {
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
        let mut self_iter = self.rev_labelettes();
        let mut base_iter = base.rev_labelettes();
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

    /// Creates an owned domain name with `base` adjoined to `self`.
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

    fn labels(&self) -> NameIter {
        DNameSlice::iter(self)
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
    type IntoIter = NameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
        let self_iter = self.rev_labelettes();
        let other_iter = other.rev_labelettes();
        self_iter.partial_cmp(other_iter)
    }
}

impl<N: DName> PartialOrd<N> for DNameSlice {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        let self_iter = self.rev_labelettes();
        let other_iter = other.rev_labelettes();
        self_iter.partial_cmp(other_iter)
    }
}

impl Ord for DNameSlice {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let self_iter = self.rev_labelettes();
        let other_iter = other.rev_labelettes();
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
        let mut labels = self.iter();
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
        let mut labels = self.iter();
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
        let mut labels = self.iter();
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
        let mut labels = self.iter();
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
        let mut labels = self.iter();
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

#[derive(Clone, Default)]
pub struct DNameBuf {
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl DNameBuf {
    pub fn new() -> Self {
        DNameBuf{inner: Vec::new()}
    }

    pub fn with_capactity(capacity: usize) -> DNameBuf {
        DNameBuf{inner: Vec::with_capacity(capacity)}
    }

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

    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        scanner.scan_dname(origin)
    }

    pub fn root() -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(vec![0]) }
    }

    pub fn as_slice(&self) -> &DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(&self.inner) }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}

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
        if self.is_relative() {
            if self.len() + label.len() > 255 {
                return Err(PushError)
            }
            self.inner.extend_from_slice(label.as_bytes())
        }
        Ok(())
    }

    /// Pushes a new normal label to the end of the name.
    ///
    /// # Panics
    ///
    /// The method panics if `content` is longer that 63 bytes or if the
    /// resulting name would be longer that 255 bytes.
    pub fn push_normal(&mut self, content: &[u8]) {
        assert!(content.len() < 64 && self.len() + content.len()  + 1 < 256);
        self.inner.push(content.len() as u8);
        self.inner.extend_from_slice(content);
    }

    /// Pushes a binary label to the end of the name.
    ///
    /// The binary label will be `count` bits long and contain the bits
    /// from `bits`. If `bits` is too short, the label will be filled up
    /// with zero bits. If `bits` is too long, it will be trimmed to the
    /// right length.
    ///
    /// # Panics
    ///
    /// The method panics if `count` is larger than 256.
    pub fn push_binary(&mut self, count: usize, bits: &[u8]) {
        assert!(count <= 256);
        let bitlen = (count - 1) / 8 + 1;
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
    }

    /// Extends a relative name with a domain name.
    pub fn append<N: DName>(&mut self, name: &N) -> Result<(), PushError> {
        if self.is_relative() {
            for label in name.labels() {
                try!(self.push(label.as_ref()))
            }
        }
        Ok(())
    }

    /// Makes a domain name absolute if it isn’t yet by appending root.
    pub fn append_root(&mut self) -> Result<(), PushError> {
        self.append(&DNameSlice::root())
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
        Cow::Borrowed(&self)
    }

    fn labels(&self) -> NameIter {
        DNameSlice::iter(self)
    }
}

impl<'a> DName for &'a DNameBuf {
    fn to_cow(&self) -> Cow<DNameSlice> {
        Cow::Borrowed(self)
    }

    fn labels(&self) -> NameIter {
        DNameSlice::iter(self)
    }
}

//--- From and FromStr

impl<'a> From<&'a DNameSlice> for DNameBuf {
    fn from(name: &'a DNameSlice) -> DNameBuf {
        unsafe { DNameBuf::from_vec_unsafe(Vec::from(&name.inner)) }
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
        self.deref()
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

#[derive(Clone, Copy)]
pub struct PushError;

impl error::Error for PushError {
    fn description(&self) -> &str {
        "adding a label would exceed the size limit"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
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

