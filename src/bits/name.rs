//! Domain names.

use std::ascii::AsciiExt;
use std::borrow::{Borrow, Cow};
use std::cmp;
use std::fmt;
use std::hash;
use std::mem;
use std::ops::Deref;
use std::str;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, FromStrError, FromStrResult, ParseError,
                   ParseResult};
use super::parse::{ParseBytes, ParseLazy};
use super::u8::{BytesExt, BytesVecExt};


//------------ DName --------------------------------------------------------

/// A trait common to all domain name types.
///
/// This trait makes it possible to define types that are generic over all
/// three types of domain names.
pub trait DName: fmt::Display + Sized + PartialEq {
    /// Return a cow to a domain name slice.
    fn to_cow(&self) -> ParseResult<Cow<DNameSlice>>;

    /// Return an owned domain name.
    fn to_owned(&self) -> ParseResult<OwnedDName> {
        Ok(try!(self.to_cow()).into_owned())
    }
}


//------------ DNameSlice ---------------------------------------------------

/// Unsized type for a complete domain name.
///
/// This type implements functionality common to `DNameRef` and `OwnedDName`
/// both of which deref to it.
///
/// A domain name slice is a bytes slice encoded following the domain name
/// encoding rules with only normal and binary labels.
#[derive(Debug)]
pub struct DNameSlice {
    slice: [u8]
}

/// # Creation and Conversion
///
impl DNameSlice {
    /// Creates a domain name slice form a bytes slice.
    ///
    /// This is only safe if the input slice follows the encoding rules for
    /// a domain name and does not contain compressed labels.
    unsafe fn from_bytes(slice: &[u8]) -> &DNameSlice {
        mem::transmute(slice)
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.slice
    }

    /// Converts `self` into an owned domain name.
    pub fn to_owned(&self) -> OwnedDName {
        OwnedDName::from(self)
    }

    /// Converts `self` to a string.
    ///
    /// The resulting string will follow the zonefile representation.
    ///
    /// Normal labels will be interpreted as ASCII text with non-printable
    /// ASCII characters and non-ASCII bytes escaped as a backslash followed
    /// by three decimal digits with the decimal value of the byte and
    /// periods within a label and backslashes escaped with a leading
    /// backslash.
    /// 
    /// Binary labels are encoded starting with `"[x"`, then the hexadecimal
    /// representation of the bitfield, then a slash, then a decimal
    /// representation of the bit count, and finally a closing `']'`.
    ///
    pub fn to_string(&self) -> String {
        // With normal ASCII labels only, the resulting string is exactly
        // as long as the domain name slice.
        let mut res = String::with_capacity(self.slice.len());
        for label in self.iter() {
            if !res.is_empty() { res.push('.') }
            label.push_string(&mut res)
        }
        res
    }
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


/// # Iteration over Labels
///
impl DNameSlice {
    /// Produces an iterator over the labels in the name.
    pub fn iter<'a> (&'a self) -> SliceIter<'a> {
        SliceIter::new(self)
    }

    /// Returns the number of labels in `self`.
    ///
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Checks whether the domain name is empty.
    ///
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    /// Returns the first label or `None` if the name is empty.
    ///
    pub fn first(&self) -> Option<Label> {
        self.iter().next()
    }

    /// Returns the last label or `None` if the name is empty.
    ///
    pub fn last(&self) -> Option<Label> {
        self.iter().last()
    }
}


/// # Working with Parts
///
impl DNameSlice {
    /// Returns the first label and the rest of the name.
    ///
    /// Returns `None` if the name is empty.
    pub fn split_first(&self) -> Option<(Label, &DNameSlice)> {
        let mut iter = self.iter();
        iter.next().map(|l| (l, iter.as_name()))
    }

    /// Returns the domain name without its leftmost label.
    ///
    /// Returns `None` for an empty domain name. Returns an empty domain
    /// name for a single label domain name.
    pub fn parent(&self) -> Option<&DNameSlice> {
        self.split_first().map(|(_, tail)| tail)
    }

    /// Determines whether `base` is a prefix of `self`.
    ///
    /// The method only considers whole labels and compares them
    /// case-insensitively.
    ///
    /// The current implementation does not compare a sequence of binary
    /// labels correctly.
    pub fn starts_with<N: AsRef<Self>>(&self, base: N) -> bool {
        self._starts_with(base.as_ref())
    }

    fn _starts_with(&self, base: &Self) -> bool {
        let mut self_iter = self.iter();
        let mut base_iter = base.iter();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (Some(_), None) => return true,
                (None, None) => return true,
                (None, Some(_)) => return false,
            }
        }
    }

    /// Determines whether `base` is a suffix of `self`.
    ///
    /// The method only considers whole labels and compares them
    /// case-insensitively.
    ///
    /// The current implementation does not compare a sequence of binary
    /// labels correctly.
    pub fn ends_with<N: AsRef<Self>>(&self, base: N) -> bool {
        self._ends_with(base.as_ref())
    }

    fn _ends_with(&self, base: &Self) -> bool {
        let mut self_iter = self.iter();

        loop {
            let mut base_iter = base.iter();
            let base_first = match base_iter.next() {
                Some(l) => l,
                None => return false
            };
            if self_iter.find(|l| *l == base_first).is_none() {
                return false
            }
            let mut self_test = self_iter.clone();
            loop {
                match (self_test.next(), base_iter.next()) {
                    (Some(sl), Some(bl)) => {
                        if sl != bl { break }
                    }
                    (Some(_), None) => break,
                    (None, None) => return true,
                    (None, Some(_)) => break
                }
            }
        }
    }

    /// Creates an owned domain name with `base` adjoined to `self`.
    pub fn join<N: AsRef<Self>>(&self, base: N) -> OwnedDName {
        self._join(base.as_ref())
    }

    fn _join(&self, base: &Self) -> OwnedDName {
        let mut res = self.to_owned();
        res.append(base);
        res
    }
}


//--- DName

impl<'a> DName for &'a DNameSlice {
    fn to_cow(&self) -> ParseResult<Cow<DNameSlice>> {
        Ok(Cow::Borrowed(self))
    }
}


//--- AsRef

impl AsRef<DNameSlice> for DNameSlice {
    fn as_ref(&self) -> &DNameSlice { self }
}


//--- ToOwned

impl ToOwned for DNameSlice {
    type Owned = OwnedDName;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}


//--- PartialEq and Eq

impl<T: AsRef<DNameSlice> + ?Sized> PartialEq<T> for DNameSlice {
    fn eq(&self, other: &T) -> bool {
        self.iter().eq(other.as_ref().iter())
    }
}

impl<'a> PartialEq<LazyDName<'a>> for DNameSlice {
    /// Test whether `self` and `other` are equal.
    ///
    /// An unparsable `other` always compares false.
    fn eq(&self, other: &LazyDName<'a>) -> bool {
        self.iter().eq(other.iter())
    }
}

impl PartialEq<str> for DNameSlice {
    fn eq(&self, other: &str) -> bool {
        if !other.is_ascii() { return false }
        let mut other = other.as_bytes();
        let mut name = unsafe { DNameSlice::from_bytes(&self.slice) };
        loop {
            let (label, tail) = match name.split_first() {
                Some(x) => x,
                None => return other.is_empty()
            };
            match label.eq_zonefile(other) {
                Ok(v) => return v,
                Err(tail) => other = tail
            };
            if tail.is_empty() {
                return other.is_empty()
            }
            name = tail
        }
    }
}

impl cmp::Eq for DNameSlice { }


//--- PartialOrd and Ord

impl<T: AsRef<DNameSlice> + ?Sized> PartialOrd<T> for DNameSlice {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.as_ref().iter())
    }
}

impl<'a> PartialOrd<LazyDName<'a>> for DNameSlice {
    fn partial_cmp(&self, other: &LazyDName) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl Ord for DNameSlice {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


//--- Hash

impl hash::Hash for DNameSlice {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        use std::hash::Hash;

        for label in self.iter() {
            label.hash(state)
        }
    }
}


//--- Display

impl fmt::Display for DNameSlice {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}


//------------ DNameRef -----------------------------------------------------

/// A reference to a complete domain name.
///
/// This is nothing more than a wrapper around a `&DNameSlice` to provide a
/// drop-in type with the same semantics as the other two domain name types.
/// It derefs to a `DNameSlice`, thus providing all the methods that type
/// provides.
#[derive(Clone, Debug)]
pub struct DNameRef<'a> {
    inner: &'a DNameSlice
}

impl<'a> DNameRef<'a> {
    unsafe fn from_bytes(bytes: &'a [u8]) -> Self {
        DNameRef::from_slice(DNameSlice::from_bytes(bytes))
    }

    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        DNameRef { inner: slice }
    }

    pub fn as_slice(&self) -> &DNameSlice {
        self
    }

    pub fn to_owned(&self) -> OwnedDName {
        self.inner.to_owned()
    }

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let mut sub = parser.sub();
        loop {
            let label = try!(Label::parse_complete(&mut sub));
            if label.is_root() {
                let bytes = try!(parser.parse_bytes(sub.seen()));
                return Ok(unsafe { DNameRef::from_bytes(bytes) })
            }
        }
    }
}


//--- DName

impl<'a> DName for DNameRef<'a> {
    fn to_cow(&self) -> ParseResult<Cow<DNameSlice>> {
        Ok(Cow::Borrowed(self.inner))
    }
}


//--- From

impl<'a> From<&'a DNameSlice> for DNameRef<'a> {
    fn from(slice: &'a DNameSlice) -> Self {
        Self::from_slice(slice)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for DNameRef<'a> {
    type Target = DNameSlice;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a> Borrow<DNameSlice> for DNameRef<'a> {
    fn borrow(&self) -> &DNameSlice {
        self.deref()
    }
}

impl<'a> AsRef<DNameSlice> for DNameRef<'a> {
    fn as_ref(&self) -> &DNameSlice {
        self.deref()
    }
}


//--- PartialEq, Eq

impl<'a, T: AsRef<DNameSlice>> PartialEq<T> for DNameRef<'a> {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl<'a> Eq for DNameRef<'a> { }


//--- PartialOrd, Ord

impl<'a, T: AsRef<DNameSlice>> PartialOrd<T> for DNameRef<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl<'a> Ord for DNameRef<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl<'a> hash::Hash for DNameRef<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl<'a> fmt::Display for DNameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}


//------------ OwnedDName ---------------------------------------------------

/// An owned complete domain name.
///
/// This type derefs to `DNameSlice` and therefore provides all its
/// methods.
#[derive(Clone, Debug)]
pub struct OwnedDName {
    inner: Vec<u8>
}

/// # Creation and Conversion
///
impl OwnedDName {
    /// Creates an owned domain name from a bytes slice.
    ///
    /// This is only safe if the slice followes the domain name encoding
    /// rules and does not contain a compressed label.
    unsafe fn from_bytes(slice: &[u8]) -> Self {
        OwnedDName { inner: Vec::from(slice) }
    }

    /// Creates a new empty domain name.
    pub fn new() -> OwnedDName {
        OwnedDName { inner: Vec::new() }
    }

    /// Creates a new domain name with only the root label.
    pub fn root() -> OwnedDName {
        let mut res = OwnedDName::new();
        res.push(&Label::root());
        res
    }

    /// Creates a new domain name from a string.
    ///
    /// The string must followed zone file conventions. It must only contain
    /// of printable ASCII characters and no whitespace. Invidual labels are
    /// separated by a dot. A backslash escapes the next character unless
    /// that is a `0`, `1`, or `2`, in which case the next three characters
    /// are the byte value in decimal representation.
    pub fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = OwnedDName::new();
        let mut label = Vec::new();
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '.' => {
                            if label.len() > 63 {
                                return Err(FromStrError::LongLabel)
                            }
                            res.inner.push(label.len() as u8);
                            res.inner.extend(&label);
                            label.clear();
                        }
                        '\\' => label.push(try!(parse_escape(&mut chars))),
                        ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                            label.push(c as u8);
                        }
                        _ => return Err(FromStrError::IllegalCharacter)
                    }
                }
                None => break
            }
        }
        res.inner.push(label.len() as u8);
        res.inner.extend(&label);
        Ok(res)
    }

    pub fn parse_complete<'a, P: ParseBytes<'a>>(parser: &mut P)
                                                 -> ParseResult<Self> {
        Ok(try!(DNameRef::parse(parser)).to_owned())
    }

    pub fn parse_compressed<'a, P: ParseLazy<'a>>(parser: &mut P)
                                                  -> ParseResult<Self> {
        Ok(try!(try!(LazyDName::parse(parser)).to_owned()))
    }

    pub fn as_slice(&self) -> &DNameSlice {
        self
    }
}


/// # Manipulation
///
impl OwnedDName {
    /// Extends the name with a label.
    pub fn push(&mut self, label: &Label) {
        label.push_vec(&mut self.inner);
    }

    /// Extends the name with a domain name.
    ///
    /// This will always add `name`, even if `self` is already absolute.
    /// While this may formally result in an illegal name, writing the name
    /// to a message (or otherwise using it) will always assume the name to
    /// end with the root label. Thus, this operation is safe. What’s more,
    /// just appending the name is a lot quicker than first checking whether
    /// the name is absolute already which involves walking the name.
    pub fn append<N: AsRef<DNameSlice>>(&mut self, name: N) {
        self._append(name.as_ref())
    }

    fn _append(&mut self, name: &DNameSlice) {
        self.inner.extend(&name.slice)
    }
}


//--- DName

impl DName for OwnedDName {
    fn to_cow(&self) -> ParseResult<Cow<DNameSlice>> {
        Ok(Cow::Borrowed(self))
    }
}


//--- From and FromStr

impl<'a> From<&'a DNameSlice> for OwnedDName {
    fn from(name: &'a DNameSlice) -> OwnedDName {
        unsafe { OwnedDName::from_bytes(&name.slice) }
    }
}

impl str::FromStr for OwnedDName {
    type Err = FromStrError;

    fn from_str(s: &str) -> FromStrResult<Self> {
        OwnedDName::from_str(s)
    }
}


//--- Deref, Borrow, and AsRef

impl Deref for OwnedDName {
    type Target = DNameSlice;

    fn deref(&self) -> &Self::Target {
        unsafe { DNameSlice::from_bytes(&self.inner) }
    }
}

impl Borrow<DNameSlice> for OwnedDName {
    fn borrow(&self) -> &DNameSlice {
        self.deref()
    }
}

impl AsRef<DNameSlice> for OwnedDName {
    fn as_ref(&self) -> &DNameSlice {
        self
    }
}


//--- PartialEq and Eq

impl<T: AsRef<DNameSlice>> PartialEq<T> for OwnedDName {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl Eq for OwnedDName { }


//--- PartialOrd and Ord

impl<T: AsRef<DNameSlice>> PartialOrd<T> for OwnedDName {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl Ord for OwnedDName {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl hash::Hash for OwnedDName {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl fmt::Display for OwnedDName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}


//------------ LazyDName ----------------------------------------------------

/// A possibly compressed domain name.
///
/// In order to avoid allocations, compression is only resolved when needed.
/// The consequence of this is that a lazy domain name needs to have a
/// reference to the original message handy. To avoid too many type
/// parameters, this reference, called context, is always to a bytes slice.
/// Another consequence is that format errors may only surface when
/// using the name. Thus, there is `ParseResult<T>` return types all over
/// the place.
#[derive(Clone, Debug)]
pub struct LazyDName<'a> {
    slice: &'a [u8],
    context: &'a [u8]
}


/// # Creation and Conversion
///
impl<'a> LazyDName<'a> {
    /// Creates a lazy domain name from its components.
    pub fn new(slice: &'a[u8], context: &'a[u8]) -> Self {
        LazyDName { slice: slice, context: context }
    }

    /// Splits a lazy domain name from the beginning of a bytes slice.
    pub fn split_from(slice: &'a [u8], context: &'a [u8])
                      -> ParseResult<(Self, &'a[u8])> {
        Self::steal_from(slice, context).map(|(res, len)| (res, &slice[len..]))
    }

    /// Steal a lazy domain name from the beginning of a byte slice.
    ///
    /// This returns the name and the octet length of name.
    pub fn steal_from(slice: &'a[u8], context: &'a [u8])
                      -> ParseResult<(Self, usize)> {
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(slice, pos));
            if head.is_final() {
                return Ok((LazyDName::new(&slice[..end], context), end))
            }
            pos = end;
        }
    }

    pub fn parse<P: ParseLazy<'a>>(parser: &mut P) -> ParseResult<Self> {
        let mut sub = parser.sub();
        loop {
            if try!(Label::skip(&mut sub)) {
                let bytes = try!(parser.parse_bytes(sub.seen()));
                return Ok(LazyDName::new(bytes, parser.context()))
            }
        }
    }

    /// Converts the lazy domain name into an owned complete domain name.
    pub fn to_owned(&self) -> ParseResult<OwnedDName> {
        Ok(try!(self.decompress()).into_owned())
    }

    /// Decompress the lazy domain name,
    ///
    /// If `self` does not contain any compressed labels, it will be
    /// coerced into a regular domain name slice. If it does, it will be
    /// converted into an owned domain name.
    pub fn decompress(&self) -> ParseResult<Cow<'a, DNameSlice>> {
        // Walk over the name and return it if it ends without compression.
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(self.slice, pos));
            match head {
                LabelHead::Normal(0) => {
                    let name = unsafe { 
                        DNameSlice::from_bytes(&self.slice[..end])
                    };
                    return Ok(Cow::Borrowed(name));
                }
                LabelHead::Compressed(..) => {
                    break;
                }
                _ => { pos = end }
            }
        }
        // We have compression. Copy all until the compressed label, then
        // iterate over the rest and append each label.
        let (bytes, slice) = try!(self.slice.split_bytes(pos));
        let mut res = unsafe { OwnedDName::from_bytes(bytes) };
        for label in LazyIter::new(slice, self.context) {
            let label = try!(label);
            res.push(&label)
        }
        Ok(Cow::Owned(res))
    }

    /// Converts the lazy domain name into a string.
    pub fn to_string(&self) -> ParseResult<String> {
        // Assuming a properly parsed out slice, the resulting string is
        // at least its size.
        let mut res = String::with_capacity(self.slice.len());
        for label in self.iter() {
            let label = try!(label);
            if !res.is_empty() { res.push('.') }
            label.push_string(&mut res)
        }
        Ok(res)
    }
}


/// # Iteration over Labels
///
impl<'a> LazyDName<'a> {
    /// Returns an iterator over the labels.
    pub fn iter(&self) -> LazyIter<'a> {
        LazyIter::from_name(self)
    }
}


//--- DName

impl<'a> DName for LazyDName<'a> {
    fn to_cow(&self) -> ParseResult<Cow<DNameSlice>> {
        self.decompress()
    }
}


//--- PartialEq

impl<'a, 'b> PartialEq<LazyDName<'b>> for LazyDName<'a> {
    /// Check for equality.
    ///
    /// Lazy domain names that result in a parse error always compare
    /// unequal. Which is also why `LazyDName` does not implement `Eq`
    /// or `Ord`. (Hey, it ain’t called lazy for no reason!)
    fn eq(&self, other: &LazyDName<'b>) -> bool {
        // The orphan rule prohibits us using Iterator::eq() here.
        let mut self_iter = self.iter();
        let mut other_iter = other.iter();

        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(Ok(x)), Some(Ok(y))) => if x != y { return false },
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

impl<'a, T: AsRef<DNameSlice>> PartialEq<T> for LazyDName<'a> {
    fn eq(&self, other: &T) -> bool {
        self.iter().eq(other.as_ref().iter())
    }
}


//--- PartialOrd

impl<'a, 'b> PartialOrd<LazyDName<'b>> for LazyDName<'a> {
    /// Compare.
    ///
    /// This will return `None` if either the names is broken.
    fn partial_cmp(&self, other: &LazyDName<'b>) -> Option<cmp::Ordering> {
        // Orphan rule strikes again.
        use std::cmp::Ordering::*;

        let mut self_iter = self.iter();
        let mut other_iter = other.iter();

        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(Ok(x)), Some(Ok(y))) => match x.partial_cmp(&y) {
                    Some(Equal) => (),
                    non_eq => return non_eq
                },
                (Some(Err(..)), _) => return None,
                (_, Some(Err(..))) => return None,
                (None, None) => return Some(Equal),
                (None, _) => return Some(Less),
                (_, None) => return Some(Greater)
            }
        }
    }
}

impl<'a, T: AsRef<DNameSlice>> PartialOrd<T> for LazyDName<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.as_ref().iter())
    }
}


//--- Display

impl<'a> fmt::Display for LazyDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut empty = true;
        for label in self.iter() {
            match label {
                Err(..) => { try!("<PARSEERR>".fmt(f)); break }
                Ok(label) => {
                    if !empty { try!('.'.fmt(f)) }
                    else {
                        if label.is_root() { try!('.'.fmt(f)) }
                        empty = false;
                    }
                    try!(label.fmt(f))
                }
            }
        }
        Ok(())
    }
}


//------------ SliceIter ----------------------------------------------------

/// An iterator over the labels of a domain name slice.
///
/// This iterator stops either at the end of the domain name or when it
/// encounters the first root label, thus quietly turning every name into
/// a valid name.
#[derive(Clone, Debug)]
pub struct SliceIter<'a> {
    slice: &'a[u8]
}

impl<'a> SliceIter<'a> {
    /// Creates a new iterator from a domain name slice.
    fn new(name: &'a DNameSlice) -> Self {
        SliceIter { slice: &name.slice }
    }

    /// Returns th domain name of the remaining portion.
    pub fn as_name(&self) -> &'a DNameSlice {
        unsafe { DNameSlice::from_bytes(self.slice) }
    }
}

impl<'a> Iterator for SliceIter<'a> {
    type Item = Label<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (label, slice) = match Label::split_from(self.slice) {
            Err(..) => return None,
            Ok(res) => res
        };
        self.slice = if label.is_root() { b"" }
                     else { slice };
        Some(label)
    }
}


//------------ LazyIter -----------------------------------------------------

/// An iterator over the labels of a lazy domain name.
#[derive(Clone, Debug)]
pub struct LazyIter<'a> {
    slice: &'a[u8],
    context: &'a[u8]
}

impl<'a> LazyIter<'a> {
    fn new(slice: &'a[u8], context: &'a[u8]) -> Self {
        LazyIter { slice: slice, context: context }
    }

    fn from_name(name: &LazyDName<'a>) -> Self {
        LazyIter::new(name.slice, name.context)
    }

    pub fn as_name(&self) -> ParseResult<Cow<'a, DNameSlice>> {
        LazyDName::new(self.slice, self.context).decompress()
    }
}

impl<'a> Iterator for LazyIter<'a> {
    type Item = ParseResult<Label<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() { return None }
        match Label::split_compressed(self.slice, self.context) {
            Err(e) => Some(Err(e)),
            Ok((label, slice)) => {
                self.slice = if label.is_root() { b"" }
                             else { slice };
                Some(Ok(label))
            }
        }
    }
}


//------------ Label --------------------------------------------------------

/// The content of a domain name label.
///
/// This type only represents labels with an actual content, ie., normal
/// and binary labels. Compressed labels are being resolved into their
/// actual content by the domain name types on the fly.
///
#[derive(Clone, Debug)]
pub struct Label<'a>(LabelContent<'a>);


/// The actual content of a label.
///
/// This type is private so that it is impossible to gate label creation
/// making public label handling error-free.
#[derive(Clone, Debug)]
enum LabelContent<'a> {
    /// A normal label containing up to 63 octets.
    Normal(&'a [u8]),

    /// A binary label.
    ///
    /// The first element is the number of bits in the label with zero
    /// indicating 256 bits. The second element is the byte slice
    /// representing the bit field padded to full octets.
    ///
    /// This variant is historic and annoying and shouldn't really be
    /// encountered.
    Binary(u8, &'a[u8]),
}


impl<'a> Label<'a> {
    pub fn root() -> Self {
        Label(LabelContent::Normal(b""))
    }

    fn parse_complete<P: ParseBytes<'a>>(parser: &mut P)
                                         -> ParseResult<Self> {
        match try!(LabelHead::parse(parser)) {
            LabelHead::Normal(len) => {
                let bytes = try!(parser.parse_bytes(len as usize));
                Ok(Label(LabelContent::Normal(bytes)))
            }
            LabelHead::Binary => {
                let count = try!(parser.parse_u8());
                let len = Label::binary_len(count);
                let bytes = try!(parser.parse_bytes(len as usize));
                Ok(Label(LabelContent::Binary(count, bytes)))
            }
            LabelHead::Compressed(_) => {
                Err(ParseError::CompressedLabel)
            }
        }
    }

    /// Skips over a label and returns whether it was the final label.
    fn skip<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<bool> {
        match try!(LabelHead::parse(parser)) {
            LabelHead::Normal(len) => {
                try!(parser.skip(len as usize));
                Ok(len == 0)
            }
            LabelHead::Binary => {
                let len = Label::binary_len(try!(parser.parse_u8()));
                try!(parser.skip(len));
                Ok(false)
            }
            LabelHead::Compressed(_) => {
                try!(parser.skip(1));
                Ok(true)
            }
        }
    }

    /// Splits a label from the beginning of a bytes slice.
    ///
    /// Returns the label and the remainder of the slice.
    fn split_from(slice: &'a[u8]) -> ParseResult<(Label<'a>, &'a[u8])> {
        let (head, slice) = try!(LabelHead::split_from(slice));
        match head {
            LabelHead::Normal(len) => {
                let (bytes, slice) = try!(slice.split_bytes(len as usize));
                Ok((Label(LabelContent::Normal(bytes)), slice))
            }
            LabelHead::Binary => {
                let (count, slice) = try!(slice.split_u8());
                let len = Label::binary_len(count);
                let (bytes, slice) = try!(slice.split_bytes(len));
                Ok((Label(LabelContent::Binary(count, bytes)), slice))
            }
            LabelHead::Compressed(_) => {
                Err(ParseError::CompressedLabel)
            }
        }
    }

    /// Split a possibly compressed label from the beginning of a slice.
    ///
    /// Returns the label, whether this was a compressed label, and the
    /// slice to keep parsing the next labels from.
    fn split_compressed(slice: &'a[u8], context: &'a[u8])
                        -> ParseResult<(Label<'a>, &'a[u8])> {
        let (head, slice) = try!(LabelHead::split_from(slice));
        match head {
            LabelHead::Normal(len) => {
                let (bytes, slice) = try!(slice.split_bytes(len as usize));
                Ok((Label(LabelContent::Normal(bytes)), slice))
            }
            LabelHead::Binary => {
                let (count, slice) = try!(slice.split_u8());
                let len = Label::binary_len(count);
                let (bytes, slice) = try!(slice.split_bytes(len));
                Ok((Label(LabelContent::Binary(count, bytes)), slice))
            }
            LabelHead::Compressed(upper) => {
                let (lower, _) = try!(slice.split_u8());
                let ptr = ((upper as usize) << 8) | (lower as usize);
                Label::split_compressed(try!(context.tail(ptr)), context)
            }
        }
    }

    /// Peeks at a label starting at `pos` in `slice`.
    ///
    /// Returns the end index of the label (ie., the index of the following
    /// octet) and the label head.
    ///
    fn peek(slice: &[u8], pos: usize) -> ParseResult<(usize, LabelHead)> {
        try!(slice.check_len(pos + 1));
        let head = try!(LabelHead::from_byte(slice[pos]));
        let end = match head {
            LabelHead::Normal(len) => {
                pos + 1 + (len as usize)
            }
            LabelHead::Binary => {
                try!(slice.check_len(pos + 1));
                let count = slice[pos + 1];
                pos + 2 + Label::binary_len(count)
            }
            LabelHead::Compressed(_) => {
                pos + 2
            }
        };
        try!(slice.check_len(end));
        Ok((end, head))
    }

    /// Returns a string slice if this is normal label and purely ASCII.
    pub fn as_str(&self) -> Option<&str> {
        match self.0 {
            LabelContent::Normal(s) => str::from_utf8(s).ok(),
            _ => None
        }
    }

    /// Returns the length of the label’s wire representation in octets.
    pub fn len(&self) -> usize {
        match self.0 {
            LabelContent::Normal(s) => s.len() + 1,
            LabelContent::Binary(count, _) => Self::binary_len(count) + 2,
        }
    }

    /// Returns whether this is the root label
    pub fn is_root(&self) -> bool {
        match self.0 {
            LabelContent::Normal(b"") => true,
            _ => false,
        }
    }

    /// Push the label to the end of an octet buffer.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        match self.0 {
            LabelContent::Normal(slice) => {
                assert!(slice.len() <= 63);
                try!(target.push_u8(slice.len() as u8));
                target.push_bytes(slice)
            }
            LabelContent::Binary(count, slice) => {
                assert!(slice.len() == Self::binary_len(count));
                try!(LabelHead::Binary.compose(target));
                try!(target.push_u8(count));
                target.push_bytes(slice)
            }
        }
    }

    pub fn compose_compressed<C: ComposeBytes>(target: &mut C, pos: u16)
                                               -> ComposeResult<()> {
        try!(LabelHead::Compressed(((pos & 0xFF00) >> 8) as u8)
                       .compose(target));
        target.push_u8((pos & 0xFF) as u8)
    }

    fn push_vec(&self, vec: &mut Vec<u8>) {
        match self.0 {
            LabelContent::Normal(slice) => {
                assert!(slice.len() <= 63);
                vec.push_u8(slice.len() as u8);
                vec.push_bytes(slice);
            }
            LabelContent::Binary(count, slice) => {
                assert!(slice.len() == Self::binary_len(count));
                LabelHead::Binary.push_vec(vec);
                vec.push_u8(count);
                vec.push_bytes(slice);
            }
        }
    }

    /// Returns the bit label length for a binary label with `count` bits.
    fn binary_len(count: u8) -> usize {
        if count == 0 { 32 }
        else if count % 8 == 0 { (count / 8) as usize }
        else { (count / 8 + 1) as usize }
    }

    /// Push the string representation to the end of a string.
    fn push_string(&self, res: &mut String) {
        use std::char::from_digit;

        match self.0 {
            LabelContent::Normal(slice) => {
                for &ch in slice {
                    if ch == b' ' || ch == b'.' || ch == b'\\' {
                        res.push('\\');
                        res.push(ch as char);
                    }
                    else if ch < b' '  || ch >= 0x7F {
                        res.push('\\');
                        res.push(((ch / 100) % 10 + b'0') as char);
                        res.push(((ch / 10) % 10 + b'0') as char);
                        res.push((ch % 10 + b'0') as char);
                    }
                    else {
                        res.push(ch as char);
                    }
                }
            }
            LabelContent::Binary(count, slice) => {
                res.push_str("[x");
                for &ch in slice {
                    res.push(from_digit(((ch & 0xF0) >> 4) as u32,
                                        16).unwrap());
                    res.push(from_digit((ch & 0x0F) as u32, 16).unwrap());
                    
                }
                res.push('/');
                res.push(from_digit(((count / 100) % 10) as u32, 10).unwrap());
                res.push(from_digit(((count / 10) % 10) as u32, 10).unwrap());
                res.push(from_digit((count % 10) as u32, 10).unwrap());
                res.push(']');
            }
        }
    }

    /// Equality compares the label with a zonefile representation.
    ///
    /// Returns either the result or the remainder of the slice to
    /// use for continuing comparison.
    fn eq_zonefile<'b>(&self, mut s: &'b[u8]) -> Result<bool, &'b[u8]> {
        match self.0 {
            LabelContent::Normal(l) => {
                for lch in l.iter() {
                    if s.is_empty() { return Ok(false) }
                    let (sch, rest) = match split_zonefile_char(s) {
                        Some(x) => x, None => return Ok(false)
                    };
                    if *lch != sch { return Ok(false) }
                    s = rest;
                }
                Err(s)
            }
            LabelContent::Binary(count, l) => {
                // XXX TODO
                let _ = (count, l);
                unimplemented!()
            }
        }
    }
}


//--- PartialEq and Eq

impl<'a> PartialEq for Label<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (&LabelContent::Normal(l), &LabelContent::Normal(r)) => {
                l.eq_ignore_ascii_case(r)
            }
            (&LabelContent::Binary(lc, ls), &LabelContent::Binary(rc, rs)) => {
                if lc != rc { false }
                else {
                    // This assumes that both labels are well-formed,
                    // or at least no empty.
                    let (ll, ls) = ls.split_last().unwrap();
                    let (rl, rs) = rs.split_last().unwrap();
                    if ls != rs { false }
                    else {
                        match lc & 0x7 {
                            0 => ll == rl,
                            c @ _ => {
                                let mask = (1 << c) - 1;
                                (ll & mask) == (rl & mask)
                            }
                        }
                    }
                }
            }
            _ => false
        }
    }
}

impl<'a> PartialEq<[u8]> for Label<'a> {
    fn eq(&self, other: &[u8]) -> bool {
        match self.0 {
            LabelContent::Normal(slice) => {
                slice.eq_ignore_ascii_case(other)
            }
            _ => false
        }
    }
}

impl<'a, 'b> PartialEq<ParseResult<Label<'b>>> for Label<'a> {
    fn eq(&self, other: &ParseResult<Label<'b>>) -> bool {
        match *other {
            Ok(ref other) => self.eq(other),
            Err(..) => false
        }
    }
}

impl<'a, 'b> PartialEq<Label<'b>> for ParseResult<Label<'a>> {
    fn eq(&self, other: &Label<'b>) -> bool {
        other.eq(self)
    }
}

impl<'a> PartialEq<str> for Label<'a> {
    fn eq(&self, other: &str) -> bool {
        self.eq(other.as_bytes())
    }
}

impl<'a> Eq for Label<'a> { }


//--- PartialOrd and Ord

impl<'a> PartialOrd for Label<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, 'b> PartialOrd<ParseResult<Label<'b>>> for Label<'a> {
    fn partial_cmp(&self, other: &ParseResult<Label<'b>>)
                   -> Option<cmp::Ordering> {
        match *other {
            Ok(ref other) => self.partial_cmp(other),
            Err(..) => None
        }
    }
}

impl<'a, 'b> PartialOrd<Label<'b>> for ParseResult<Label<'a>> {
    fn partial_cmp(&self, other: &Label<'b>) -> Option<cmp::Ordering> {
        other.partial_cmp(self).map(|ord| ord.reverse())
    }
}

impl<'a> Ord for Label<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (&self.0, &other.0) {
            (&LabelContent::Normal(l), &LabelContent::Normal(r)) => {
                l.iter().map(u8::to_ascii_lowercase).cmp(
                    r.iter().map(u8::to_ascii_lowercase))
            }
            (&LabelContent::Binary(_, ls), &LabelContent::Binary(_, rs)) => {
                // XXX This considers the padding bits and thus might
                //     be wrong.
                ls.cmp(rs)
            }
            (&LabelContent::Normal(..), &LabelContent::Binary(..))
                => cmp::Ordering::Greater,
            (&LabelContent::Binary(..), &LabelContent::Normal(..))
                => cmp::Ordering::Less,
        }
    }
}


//--- Hash

impl<'a> hash::Hash for Label<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match &self.0 {
            &LabelContent::Normal(slice) => {
                state.write_u8(0);
                for ch in slice {
                    state.write_u8(ch.to_ascii_lowercase())
                }
            }
            &LabelContent::Binary(count, slice) => {
                state.write_u8(1);
                state.write_u8(count);
                let (last, slice) = slice.split_last().unwrap();
                state.write(slice);
                let count = count & 0x7;
                let mask = if count == 0 { 0xFF }
                           else { (1 << count) - 1 };
                state.write_u8(last & mask);
            }
        }
    }
}


//--- Display

impl<'a> fmt::Display for Label<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut res = String::new();
        self.push_string(&mut res);
        res.fmt(f)
    }
}


//------------ LabelHead ----------------------------------------------------

/// The first octet of a domain name.
///
/// This is an internal type used for parsing labels. We only have variants
/// for the defined label types. Illegal or unknown types will result in
/// errors.
///
#[derive(Clone, Copy, Debug)]
enum LabelHead {
    /// A normal label with the length in octets.
    Normal(u8),

    /// A compressed label with the upper six bits of the pointer.
    Compressed(u8),

    /// A binary label.
    ///
    /// Since this is an extended type, the first octet really only is the
    /// type.
    Binary,
}

impl LabelHead {
    fn from_byte(octet: u8) -> ParseResult<Self> {
        match octet {
            0 ... 0x3F => Ok(LabelHead::Normal(octet)),
            0xC0 ... 0xFF => Ok(LabelHead::Compressed(octet & 0x3F)),
            0x41 => Ok(LabelHead::Binary),
            _ => Err(ParseError::UnknownLabel),
        }
    }

    fn parse<'a, P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        LabelHead::from_byte(try!(parser.parse_u8()))
    }

    fn split_from<'a>(slice: &'a[u8]) -> ParseResult<(LabelHead, &'a[u8])> {
        let (head, slice) = try!(slice.split_u8());
        Ok((try!(LabelHead::from_byte(head)), slice))
    }

    fn compose<C: ComposeBytes>(self, target: &mut C) -> ComposeResult<()> {
        match self {
            LabelHead::Normal(c) => {
                assert!(c <= 0x3F);
                target.push_u8(c)
            }
            LabelHead::Compressed(c) => {
                assert!(c != 0x3F);
                target.push_u8(c | 0xC0)
            }
            LabelHead::Binary => {
                target.push_u8(0x41)
            }
        }
    }

    fn push_vec(self, vec: &mut Vec<u8>) {
        match self {
            LabelHead::Normal(c) => {
                assert!(c <= 0x3F);
                vec.push_u8(c)
            }
            LabelHead::Compressed(c) => {
                assert!(c != 0x3F);
                vec.push_u8(c | 0xC0)
            }
            LabelHead::Binary => {
                vec.push_u8(0x41)
            }
        }
    }

    fn is_final(&self) -> bool {
        match *self {
            LabelHead::Normal(0) => true,
            LabelHead::Compressed(..) => true,
            _ => false
        }
    }
}


//------------ Internal Helpers ---------------------------------------------

fn split_zonefile_char(slice: &[u8]) -> Option<(u8, &[u8])> {
    let (head, tail) = match slice.split_first() {
        Some(x) => x, None => return None
    };
    if *head == b'\\' {
        let (c1, tail) = match slice.split_first() {
            Some((c, tail)) => (*c, tail), None => return None
        };
        if c1 >= b'0' && c1 <= b'2' {
            let (c2, tail) = match tail.split_first() {
                Some((c, tail)) => (*c, tail), _ => return None
            };
            if c2 < b'0' || c2 > b'9' { return None }
            let (c3, tail) = match tail.split_first() {
                Some((c, tail)) => (*c, tail), _ => return None
            };
            if c3 < b'0' || c2 > b'9' { return None }
            let v = ((c1 - b'0') as u16) * 100
                  + ((c2 - b'0') as u16) * 10
                  + ((c3 - b'0') as u16);
            if v > 255 { return None }
            Some(((v as u8), tail))
        }
        else {
            Some((c1, tail))
        }
    }
    else {
        Some((*head, tail))
    }
}

fn parse_escape(chars: &mut str::Chars) -> FromStrResult<u8> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch == '0' || ch == '1' || ch == '2' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        Ok(v as u8)
    }
    else { Ok(ch as u8) }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::ops::Deref;

    #[test]
    fn bogus() {
        let name = OwnedDName::from_str("foo.bar.").unwrap();
        let nameref = DNameRef::from_slice(name.deref());
        println!("{}", nameref.parent().unwrap())
    }
}
