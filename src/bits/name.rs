//! Domain names.
//!
//! This module contains various types for working with domain names.
//!
//! Domain names are a sequence of labels. For the most part, labels are a
//! sequence of up to 63 octets prefixed with the number of octets in an
//! octet of its own. If the domain name ends with an empty label it is an
//! absolute name, otherwise it is relative.
//!
//! There are two twists to this: One are binary labels which essentially
//! encode a sequence of bit labels, are somewhat esoteric, and have been
//! declared historic. The other is name compression. In order to save
//! space in DNS messages (which were originally limited to 512 bytes for
//! most cases), a name can end in a reference to another name stored
//! elsewhere in the message. This makes lazy message parsing somewhat
//! difficult since you need to carry around a reference to the original
//! message until actual parsing happens.
//!
//! This is why there is four types in this module. Two types represent
//! uncompressed domain names encoded in their wire format atop a bytes
//! sequence. The `DNameSlice` type uses a bytes slice and is an unsized
//! type similar essentially equivalent to `[u8]`. `DNameBuf` is an owned
//! uncompressed domain name, similar to a `Vec<u8>`. Like that type it
//! derefs into a `DNameSlice`. These two types can contain either absolute
//! or relative domain names.
//!
//! With a domain name slice you can do things like iterating over labels
//! or splitting off parts of the name to form other names. The owned domain
//! name in addition can be manipulated by adding labels or entire domain
//! name slices to its end.
//!
//! A compressed domain name inside some DNS message is represented by
//! `PackedDName`. It allows for lazy parsing: you can keep it around without
//! much bother until you actually need to look at it. Then you can either
//! iterate over its labels or turn it into an uncompressed domain name for
//! further processing. Because they are always embedded within a message,
//! packed domain names are always absolute.
//!
//! Finally, there are composite data structures in DNS, such as questions
//! or resource records, that contain domain names. In order to avoid having
//! to have three versions of these as well, the type `DName` exists which
//! combines the three types in the manner of a `Cow`. It can either be a
//! domain name slice, an owned domain name, or a packed domain name. Its
//! functionality is similar to the packed domain name since it is the
//! lowest common denominator of the three types.
//!
//! # TODO
//!
//! - Implement an optimization where the first byte of an owned domain
//!   name encodes whether the name is absolute or relative. This will
//!   speed up `DNameBuf::push()` and `DNameBuf::append()` significantly.
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
use super::parse::ParseBytes;
use super::u8::{BytesExt, BytesVecExt};


//------------ AsDName ------------------------------------------------------

/// A trait for any type that can be converted into a `DName` value.
///
/// This is a helper trait for allowing functions to be generic over all
/// types of domain names.
///
/// Note that because of lifetime restrictions, you cannot use this trait if
/// the name is supposed to be kept around beyond the scope of a function
/// (such as for creating types containing the domain name). In these cases,
/// use `DName` directly and, when calling the function, the `into()`
/// method.
pub trait AsDName {
    /// Converts `self` into a `DName`.
    fn as_dname(&self) -> DName;
}


//------------ DName --------------------------------------------------------

/// A domain name.
///
/// This type encapsulates one of the three fundamental domain name types,
/// `DNameSlice`, `DNameBuf`, or `PackedDName`. Its main use is as part of
/// other data structures containing domain names.
///
/// The functionality of this type is somewhat limited owing to the lazy
/// parsing nature of the `PackedDName`. In practice, it is limited to
/// iterating over the labels through the `iter()` method and comparing to
/// other domain names.
///
/// For more elaborate processing, you can turn the `DName` into a
/// `Cow<DNameSlice>` using the `into_cow()` method or into an owned
/// `DNameBuf` using the `into_owned()` method.
///
/// You can create a `DName` from a string using the `std::str::FromStr`
/// trait. See `DNameBuf` for details on the expexted format of the string.
#[derive(Clone, Debug)]
pub enum DName<'a> {
    /// A reference to a domain name slice.
    Slice(&'a DNameSlice),

    /// An owned domain name.
    Owned(DNameBuf),

    /// A packed domain name.
    Packed(PackedDName<'a>)
}

///  Creation and Conversion.
///
///  For creation, use the variants directly.
///
impl<'a> DName<'a> {
    /// Extracts an owned name.
    ///
    /// Clones the data if it isn’t already owned.
    pub fn into_owned(self) -> ParseResult<DNameBuf> {
        match self {
            DName::Slice(name) => Ok(name.to_owned()),
            DName::Owned(name) => Ok(name),
            DName::Packed(name) => name.to_owned(),
        }
    }

    /// Extracts a cow of the name.
    ///
    /// This will return a borrow for a slice, owned data for the owned
    /// variant, and either owned or borrowed data for a packed domain name
    /// depending on whether the name was compressed or not.
    pub fn into_cow(self) -> ParseResult<Cow<'a, DNameSlice>> {
        match self {
            DName::Slice(name) => Ok(Cow::Borrowed(name)),
            DName::Owned(name) => Ok(Cow::Owned(name)),
            DName::Packed(name) => name.unpack()
        }
    }

    /// Returns an iterator over the labels of the name.
    ///
    /// Because of the lazy parsing of packed domain names, this iterator
    /// will return elements of type `ParseResult<Label>>`. For the
    /// uncompressed variants, these are guaranteed to always be `Ok` so you
    /// can safely call `unwrap()` on them in this particular case only.
    pub fn iter<'b: 'a>(&'b self) -> DNameIter<'b> {
        match *self {
            DName::Slice(ref name) => DNameIter::Slice(name.iter()),
            DName::Owned(ref name) => DNameIter::Slice(name.iter()),
            DName::Packed(ref name) => DNameIter::Packed(name.iter())
        }
    }
}


//--- From

impl<'a> From<&'a DNameSlice> for DName<'a> {
    fn from(t: &'a DNameSlice) -> DName<'a> {
        DName::Slice(t)
    }
}

impl<'a> From<DNameBuf> for DName<'a> {
    fn from(t: DNameBuf) -> DName<'a> {
        DName::Owned(t)
    }
}

impl<'a> From<PackedDName<'a>> for DName<'a> {
    fn from(t: PackedDName<'a>) -> DName<'a> {
        DName::Packed(t)
    }
}


//--- FromStr

impl<'a> str::FromStr for DName<'a> {
    type Err = FromStrError;

    fn from_str(s: &str) -> FromStrResult<Self> {
        DNameBuf::from_str(s).map(|x| x.into())
    }
}


//--- AsDName

impl<'a> AsDName for DName<'a> {
    fn as_dname(&self) -> DName {
        self.clone()
    }
}


//--- PartialEq

impl<'a, T: AsRef<DNameSlice> + ?Sized> PartialEq<T> for DName<'a> {
    fn eq(&self, other: &T) -> bool {
        match *self {
            DName::Slice(ref name) => name.eq(&other),
            DName::Owned(ref name) => name.eq(other),
            DName::Packed(ref name) => name.eq(other),
        }
    }
}

impl<'a, 'b> PartialEq<PackedDName<'b>> for DName<'a> {
    fn eq(&self, other: &PackedDName<'b>) -> bool {
        match *self {
            DName::Slice(ref name) => name.eq(&other),
            DName::Owned(ref name) => name.eq(other),
            DName::Packed(ref name) => name.eq(other),
        }
    }
}

impl<'a, 'b> PartialEq<DName<'b>> for DName<'a> {
    fn eq(&self, other: &DName<'b>) -> bool {
        match *other {
            DName::Slice(ref name) => self.eq(name),
            DName::Owned(ref name) => self.eq(name),
            DName::Packed(ref name) => self.eq(name)
        }
    }
}


//--- PartialOrd

impl<'a, T: AsRef<DNameSlice> + ?Sized> PartialOrd<T> for DName<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        match *self {
            DName::Slice(name) => name.partial_cmp(other),
            DName::Owned(ref name) => name.partial_cmp(other),
            DName::Packed(ref name) => name.partial_cmp(other)
        }
    }
}

impl<'a, 'b> PartialOrd<PackedDName<'b>> for DName<'a> {
    fn partial_cmp(&self, other: &PackedDName<'b>) -> Option<cmp::Ordering> {
        match *self {
            DName::Slice(name) => name.partial_cmp(other),
            DName::Owned(ref name) => name.partial_cmp(other),
            DName::Packed(ref name) => name.partial_cmp(other)
        }
    }
}

impl<'a, 'b> PartialOrd<DName<'b>> for DName<'a> {
    fn partial_cmp(&self, other: &DName<'b>) -> Option<cmp::Ordering> {
        match *other {
            DName::Slice(name) => name.partial_cmp(self),
            DName::Owned(ref name) => name.partial_cmp(self),
            DName::Packed(ref name) => name.partial_cmp(self),
        }.map(|x| x.reverse())
    }
}


//--- Display

impl<'a> fmt::Display for DName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DName::Slice(ref name) => name.fmt(f),
            DName::Owned(ref name) => name.fmt(f),
            DName::Packed(ref name) => name.fmt(f)
        }
    }
}


//------------ DNameSlice ---------------------------------------------------

/// A bytes slice containing a domain name.
///
/// Values of this type are guaranteed to contain a bytes slice with a
/// domain name in correct encoding. The encoded domain name may be relative
/// or absolute but it will be uncompressed. Because of this, there is no
/// safe 
///
/// There are various operations for working with parts of the name or
/// labels.
///
/// This is an unsized type. You will have to use it with a reference,
/// pointer, or a box.
///
#[derive(Debug)]
pub struct DNameSlice {
    slice: [u8]
}

/// # Creation and Conversion
///
impl DNameSlice {
    /// Creates a domain name slice from a reference to a bytes slice.
    ///
    /// This will fail if `slice` is not in fact a correctly encoded,
    /// uncompressed domain name. In other words, this function walks over
    /// the slice and thus takes a bit of time.
    ///
    /// The slice used by the resulting value will end at the first
    /// encountered root label (resulting in an absolute domain name) or at
    /// the end of `slice` (for a relative domain name).
    pub fn from_bytes(slice: &[u8]) -> ParseResult<&DNameSlice> {
        let mut tmp = slice;
        let mut len = 0;
        loop {
            if tmp.is_empty() { break }
            let (label, tail) = try!(Label::split_from(tmp));
            len += label.len();
            tmp = tail;
            if label.is_root() { break }
        }
        Ok(unsafe { DNameSlice::from_bytes_unsafe(&slice[..len]) })
    }

    /// Creates a domain name slice from a bytes slice without checking.
    ///
    /// This is only safe if the input slice follows the encoding rules for
    /// a domain name and does not contain compressed labels.
    unsafe fn from_bytes_unsafe(slice: &[u8]) -> &DNameSlice {
        mem::transmute(slice)
    }

    /// Parses a domain name slice.
    ///
    /// Since a domain name slice cannot be compressed, the function fails
    /// with `Err(ParseError::CompressedLabel)` if it encounters a compressed
    /// name.
    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P)
                                        -> ParseResult<&'a DNameSlice> {
        let mut sub = parser.sub();
        loop {
            if try!(Label::skip_complete(&mut sub)) {
                let bytes = try!(parser.parse_bytes(sub.seen()));
                return Ok(unsafe { DNameSlice::from_bytes_unsafe(bytes) })
            }
        }
    }

    /// Returns a reference to the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.slice
    }

    /// Converts `self` into an owned domain name.
    pub fn to_owned(&self) -> DNameBuf {
        DNameBuf::from(self)
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
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Checks whether the domain name is empty.
    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    /// Returns the first label or `None` if the name is empty.
    pub fn first(&self) -> Option<Label> {
        self.iter().next()
    }

    /// Returns the last label or `None` if the name is empty.
    pub fn last(&self) -> Option<Label> {
        self.iter().last()
    }
}


/// # Working with Parts
///
impl DNameSlice {
    /// Returns a tuple of the first label and the rest of the name.
    ///
    /// Returns `None` if the name is empty.
    pub fn split_first(&self) -> Option<(Label, &DNameSlice)> {
        let mut iter = self.iter();
        iter.next().map(|l| (l, iter.as_name()))
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
    ///
    /// The method only considers whole labels and compares them
    /// case-insensitively. Everything starts with an empty domain name.
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
    /// case-insensitively. A domain name ends with an empty domain name if
    /// and only if it is a relative domain name.
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
                None => return self.is_relative()
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
    ///
    /// If `self` is already an absolute domain name, nothing happens.
    pub fn join<N: AsRef<Self>>(&self, base: N) -> DNameBuf {
        self._join(base.as_ref())
    }

    fn _join(&self, base: &Self) -> DNameBuf {
        let mut res = self.to_owned();
        res.append(base);
        res
    }
}


//--- AsRef

impl AsRef<DNameSlice> for DNameSlice {
    fn as_ref(&self) -> &DNameSlice { self }
}


//--- AsDName

impl AsDName for DNameSlice {
    fn as_dname(&self) -> DName {
        DName::Slice(self)
    }
}


//--- ToOwned

impl ToOwned for DNameSlice {
    type Owned = DNameBuf;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}


//--- PartialEq and Eq

impl<T: AsRef<DNameSlice> + ?Sized> PartialEq<T> for DNameSlice {
    fn eq(&self, other: &T) -> bool {
        self.iter().eq(other.as_ref().iter())
    }
}

impl<'a> PartialEq<PackedDName<'a>> for DNameSlice {
    /// Test whether `self` and `other` are equal.
    ///
    /// An unparsable `other` always compares false.
    fn eq(&self, other: &PackedDName<'a>) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<'a> PartialEq<DName<'a>> for DNameSlice {
    fn eq(&self, other: &DName<'a>) -> bool {
        other.eq(self)
    }
}

impl PartialEq<str> for DNameSlice {
    fn eq(&self, other: &str) -> bool {
        if !other.is_ascii() { return false }
        let mut other = other.as_bytes();
        let mut name = unsafe { DNameSlice::from_bytes_unsafe(&self.slice) };
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

impl<'a> PartialOrd<PackedDName<'a>> for DNameSlice {
    fn partial_cmp(&self, other: &PackedDName) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl<'a> PartialOrd<DName<'a>> for DNameSlice {
    fn partial_cmp(&self, other: &DName<'a>) -> Option<cmp::Ordering> {
        other.partial_cmp(self).map(|x| x.reverse())
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


//------------ DNameBuf ---------------------------------------------------

/// An owned complete domain name.
///
/// A value of this type contains a vector with a correctly encoded,
/// uncompressed domain name. It derefs to `DNameSlice` in order to make
/// all its methods available for working with domain names. In addition,
/// it provides two method, `push()` and `append()`, for manipulating
/// domain names by adding additional labels to its end.
///
/// `DNameBuf` values can be created from string via the `std::str::FromStr`
/// trait. Such strings must be in the usual zonefile encoding.
#[derive(Clone, Debug)]
pub struct DNameBuf {
    /// The underlying bytes vector.
    inner: Vec<u8>
}

/// # Creation and Conversion
///
impl DNameBuf {
    /// Creates an owned domain name using an existing bytes vector.
    ///
    /// If the content of the bytes vector does not constitute a correctly
    /// encoded uncompressed domain name, the function will fail.
    pub fn from_vec(mut vec: Vec<u8>) -> ParseResult<Self> {
        let mut len = 0;
        {
            let mut tmp = vec.as_slice();
            loop {
                if tmp.is_empty() { break }
                let (label, tail) = try!(Label::split_from(tmp));
                len += label.len();
                tmp = tail;
                if label.is_root() { break }
            }
        }
        vec.truncate(len);
        Ok(DNameBuf { inner: vec })
    }

    /// Creates an owned domain name by boldly cloing a bytes slice.
    ///
    /// This is only safe if the slice followes the domain name encoding
    /// rules and does not contain a compressed label.
    unsafe fn from_bytes_unsafe(slice: &[u8]) -> Self {
        DNameBuf { inner: Vec::from(slice) }
    }

    /// Creates a new empty domain name.
    pub fn new() -> DNameBuf {
        DNameBuf { inner: Vec::new() }
    }

    /// Creates a new empty domain name with the specified capacity.
    pub fn with_capacity(capacity: usize) -> DNameBuf {
        DNameBuf { inner: Vec::with_capacity(capacity) }
    }

    /// Creates a new domain name with only the root label.
    pub fn root() -> DNameBuf {
        let mut res = DNameBuf::with_capacity(1);
        res.push(&Label::root());
        res
    }

    /// Parses a complete domain name and clones it into an owned name.
    pub fn parse_complete<'a, P: ParseBytes<'a>>(parser: &mut P)
                                                 -> ParseResult<Self> {
        Ok(try!(DNameSlice::parse(parser)).to_owned())
    }

    /// Parses a packed domain name and clones it into an owned name.
    pub fn parse_compressed<'a, P>(parser: &mut P, context: &'a [u8])
                                   -> ParseResult<Self>
                            where P: ParseBytes<'a> {
        Ok(try!(try!(PackedDName::parse(parser, context)).to_owned()))
    }

    /// Returns a reference to a domain name slice of this domain name.
    pub fn as_slice(&self) -> &DNameSlice {
        self
    }
}


/// # Manipulation
///
impl DNameBuf {
    /// Extends a relative name with a label.
    ///
    /// If the name is absolute, nothing happens.
    pub fn push(&mut self, label: &Label) {
        if self.is_relative() {
            label.push_vec(&mut self.inner);
        }
    }

    /// Extends a relative name with a domain name.
    ///
    /// If the name is absolute, nothing happens. You can use this feature
    /// to simply make a name absolute:
    ///
    /// ```
    /// use std::str::FromStr;
    /// use domain::bits::DNameBuf;
    ///
    /// let root = DNameBuf::root();
    /// let mut some_name = DNameBuf::from_str("example.com").unwrap();
    /// some_name.append(&root);
    /// assert_eq!(some_name.to_string(), "example.com.");
    /// ```
    pub fn append<N: AsRef<DNameSlice>>(&mut self, name: N) {
        self._append(name.as_ref())
    }

    fn _append(&mut self, name: &DNameSlice) {
        if self.is_relative() {
            self.inner.extend(&name.slice)
        }
    }
}


//--- From and FromStr

impl<'a> From<&'a DNameSlice> for DNameBuf {
    fn from(name: &'a DNameSlice) -> DNameBuf {
        unsafe { DNameBuf::from_bytes_unsafe(&name.slice) }
    }
}

impl str::FromStr for DNameBuf {
    type Err = FromStrError;

    /// Creates a new domain name from a string.
    ///
    /// The string must followed zone file conventions. It must only contain
    /// of printable ASCII characters and no whitespace. Invidual labels are
    /// separated by a dot. A backslash escapes the next character unless
    /// that is a `0`, `1`, or `2`, in which case the next three characters
    /// are the byte value in decimal representation.
    fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = DNameBuf::new();
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
}


//--- AsDName

impl AsDName for DNameBuf {
    fn as_dname(&self) -> DName {
        DName::Slice(self)
    }
}

impl<'a> AsDName for &'a DNameBuf {
    fn as_dname(&self) -> DName {
        DName::Slice(self)
    }
}


//--- Deref, Borrow, and AsRef

impl Deref for DNameBuf {
    type Target = DNameSlice;

    fn deref(&self) -> &Self::Target {
        unsafe { DNameSlice::from_bytes_unsafe(&self.inner) }
    }
}

impl Borrow<DNameSlice> for DNameBuf {
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

impl<T: AsRef<DNameSlice> + ?Sized> PartialEq<T> for DNameBuf {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl<'a> PartialEq<PackedDName<'a>> for DNameBuf {
    fn eq(&self, other: &PackedDName<'a>) -> bool {
        other.eq(self)
    }
}

impl<'a> PartialEq<DName<'a>> for DNameBuf {
    fn eq(&self, other: &DName<'a>) -> bool {
        other.eq(self)
    }
}

impl Eq for DNameBuf { }


//--- PartialOrd and Ord

impl<T: AsRef<DNameSlice> + ?Sized> PartialOrd<T> for DNameBuf {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl<'a> PartialOrd<PackedDName<'a>> for DNameBuf {
    fn partial_cmp(&self, other: &PackedDName<'a>) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other)
    }
}

impl<'a> PartialOrd<DName<'a>> for DNameBuf {
    fn partial_cmp(&self, other: &DName<'a>) -> Option<cmp::Ordering> {
        other.partial_cmp(self).map(|x| x.reverse())
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


//--- Display

impl fmt::Display for DNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}


//------------ PackedDName ----------------------------------------------------

/// A possibly compressed domain name.
///
/// In order to avoid allocations, compression is only resolved when needed.
/// The consequence of this is that a packed domain name needs to have a
/// reference to the original message handy. To avoid too many type
/// parameters, this reference, called context, is always a bytes slice.
///
/// There is relatively few things you can do with a packed domain name,
/// such as iterating over labels or comparing it to another name. For most
/// interesting things, you first need to unpack the name. This will create
/// a `Cow<DNameSlice>`—if the name is not packed, it will become a simple
/// borrow; allocations will only happen for compressed names. Once you have
/// the cow, you can go ahead and work with the name.
///
/// Packed names implement both `PartialEq` and `PartialOrd` for all
/// possible domain name types. A packed name that fails to parse will always
/// be not equal to everything else and not have an ordering. Because of this,
/// `Eq` and `Ord` cannot be implemented.
#[derive(Clone, Debug)]
pub struct PackedDName<'a> {
    slice: &'a [u8],
    context: &'a [u8]
}


/// # Creation and Conversion
///
impl<'a> PackedDName<'a> {
    /// Creates a lazy domain name from its components.
    ///
    /// It is safe to use a slice that is longer than the actual domain name.
    /// In other words, you can safely use the remainder of a message from
    /// the start of the domain name as `slice`. Any operation will terminate
    /// at the actual end of the name.
    pub fn new(slice: &'a[u8], context: &'a[u8]) -> Self {
        PackedDName { slice: slice, context: context }
    }

    /// Splits a packed domain name from the beginning of a bytes slice.
    ///
    /// Upon success, returns the packed domain name and the remainder of
    /// the bytes slice.
    pub fn split_from(slice: &'a [u8], context: &'a [u8])
                      -> ParseResult<(Self, &'a[u8])> {
        Self::steal_from(slice, context).map(|(res, len)| (res, &slice[len..]))
    }

    /// Steal a lazy domain name from the beginning of a byte slice.
    ///
    /// Upon success, returns the name and the octet length of name.
    pub fn steal_from(slice: &'a[u8], context: &'a [u8])
                      -> ParseResult<(Self, usize)> {
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(slice, pos));
            if head.is_final() {
                return Ok((PackedDName::new(&slice[..end], context), end))
            }
            pos = end;
        }
    }

    /// Parses a packed domain name.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, context: &'a [u8])
                                    -> ParseResult<Self> {
        let mut sub = parser.sub();
        loop {
            if try!(Label::skip(&mut sub)) {
                let bytes = try!(parser.parse_bytes(sub.seen()));
                return Ok(PackedDName::new(bytes, context))
            }
        }
    }

    /// Converts the lazy domain name into an owned complete domain name.
    pub fn to_owned(&self) -> ParseResult<DNameBuf> {
        self.unpack().map(|res| res.into_owned())
    }

    /// Unpacks the packed domain name into a cow of a domain name slice.
    ///
    /// If the name is not compressed, a borrow of the underlying slice is
    /// returned. If it is compressed, allocations have to happen and
    /// owned data is returned.
    pub fn unpack(&self) -> ParseResult<Cow<'a, DNameSlice>> {
        // Walk over the name and return it if it ends without compression.
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(self.slice, pos));
            match head {
                LabelHead::Normal(0) => {
                    let name = unsafe { 
                        DNameSlice::from_bytes_unsafe(&self.slice[..end])
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
        let mut res = unsafe { DNameBuf::from_bytes_unsafe(bytes) };
        for label in PackedIter::new(slice, self.context) {
            let label = try!(label);
            res.push(&label)
        }
        Ok(Cow::Owned(res))
    }

    /// Converts the packed domain name into a string.
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
impl<'a> PackedDName<'a> {
    /// Returns an iterator over the labels.
    ///
    /// In line with the lazy parsing theme of packed domain name, the
    /// returned iterator actually walks over elements of type
    /// `ParseResult<Label>`. If parsing fails, the iterator will return
    /// `Some(Err(..))` once and then `None` next, ie., it will not loop
    /// over the error. Typically, the best way to use the iterator in a
    /// for loop is to use shadow the returned element using the `try!()`
    /// macro as first thing:
    ///
    /// ```ignore
    /// for label in name {
    ///     let label = try!(label);
    ///     // do things with label ...
    /// }
    /// ```
    pub fn iter(&self) -> PackedIter<'a> {
        PackedIter::from_name(self)
    }
}


//--- AsDName

impl<'a> AsDName for PackedDName<'a> {
    fn as_dname(&self) -> DName {
        DName::Packed(self.clone())
    }
}


//--- PartialEq

impl<'a, 'b> PartialEq<PackedDName<'b>> for PackedDName<'a> {
    fn eq(&self, other: &PackedDName<'b>) -> bool {
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

impl<'a, T: AsRef<DNameSlice> + ?Sized> PartialEq<T> for PackedDName<'a> {
    fn eq(&self, other: &T) -> bool {
        let mut self_iter = self.iter();
        let mut other_iter = other.as_ref().iter();

        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(Ok(x)), Some(y)) => if x != y { return false },
                (None, None) => return true,
                _ => return false
            }
        }
    }
}

impl<'a, 'b> PartialEq<DName<'b>> for PackedDName<'a> {
    fn eq(&self, other: &DName<'b>) -> bool {
        other.eq(self)
    }
}


//--- PartialOrd

impl<'a, 'b> PartialOrd<PackedDName<'b>> for PackedDName<'a> {
    fn partial_cmp(&self, other: &PackedDName<'b>) -> Option<cmp::Ordering> {
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

impl<'a, T: AsRef<DNameSlice> + ?Sized> PartialOrd<T> for PackedDName<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        use std::cmp::Ordering::*;

        let mut self_iter = self.iter();
        let mut other_iter = other.as_ref().iter();

        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(Ok(x)), Some(y)) => match x.partial_cmp(&y) {
                    Some(Equal) => (),
                    non_eq => return non_eq
                },
                (Some(Err(..)), _) => return None,
                (None, None) => return Some(Equal),
                (None, _) => return Some(Less),
                (_, None) => return Some(Greater)
            }
        }
    }
}

impl<'a, 'b> PartialOrd<DName<'b>> for PackedDName<'b> {
    fn partial_cmp(&self, other: &DName<'b>) -> Option<cmp::Ordering> {
        other.partial_cmp(self).map(|x| x.reverse())
    }
}


//--- Display

impl<'a> fmt::Display for PackedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut empty = true;
        for label in self.iter() {
            let label = match label {
                Ok(label) => label,
                Err(..) => {
                    try!(".<PARSE ERROR>".fmt(f));
                    return Ok(())
                }
            };
            if !empty { try!('.'.fmt(f)) }
            else {
                if label.is_root() { try!('.'.fmt(f)) }
                empty = false;
            }
            try!(label.fmt(f))
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

    /// Returns a domain name slice for the remaining portion of the name.
    pub fn as_name(&self) -> &'a DNameSlice {
        unsafe { DNameSlice::from_bytes_unsafe(self.slice) }
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


//------------ PackedIter ---------------------------------------------------

/// An iterator over the labels of a packed domain name.
///
/// Because this type only actually does some parsing when `next()` is being
/// called, the item type is `ParseResult<Label>`. If a parse error is
/// encountered, `next()` returns `Some(Err(_))`. If `next()` is called again
/// after, `None` is returned to avoid an endless loop.
///
/// A consequence of this is that the end of iteration does not indicate a
/// correctly encoded packed domain name.
#[derive(Clone, Debug)]
pub struct PackedIter<'a> {
    /// The slice with the remaining domain name to iterate over.
    slice: &'a[u8],

    /// The entire message.
    context: &'a[u8]
}

impl<'a> PackedIter<'a> {
    /// Creates a new value from its components.
    fn new(slice: &'a[u8], context: &'a[u8]) -> Self {
        PackedIter { slice: slice, context: context }
    }

    /// Creates a new value from a packed domain name.
    fn from_name(name: &PackedDName<'a>) -> Self {
        PackedIter::new(name.slice, name.context)
    }

    /// Returns the remaining domain name in its uncompressed form.
    ///
    /// Upon success, returns a value of type `Cow<DNameSlice>`. This value
    /// will contain borrowed data if the domain name wasn’t actually
    /// compressed and owned data if in fact it was.
    pub fn as_name(&self) -> ParseResult<Cow<'a, DNameSlice>> {
        PackedDName::new(self.slice, self.context).unpack()
    }
}

impl<'a> Iterator for PackedIter<'a> {
    type Item = ParseResult<Label<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() { return None }
        let (label, slice) = match Label::split_compressed(self.slice,
                                                           self.context) {
            Ok(value) => value,
            Err(err) => {
                self.slice = b"";
                return Some(Err(err))
            }
        };
        self.slice = if label.is_root() { b"" }
                     else { slice };
        Some(Ok(label))
    }
}


//------------ DNameIter ----------------------------------------------------

/// An iterator over the labels in a `DName`.
///
/// This iterator is either a `SliceIter` or a `PackedIter`. Because of that,
/// it behaves exactly like a `PackedIter`. That is, it returns elements of
/// type `ParseResult<Label>` and stops iteration once the name is complete
/// or an error has been encountered. Since `DName`s are not necessarily
/// absolute, a successful complete iteration does not necessarily end in
/// a root label.
#[derive(Clone, Debug)]
pub enum DNameIter<'a> {
    Slice(SliceIter<'a>),
    Packed(PackedIter<'a>)
}

impl<'a> Iterator for DNameIter<'a> {
    type Item = ParseResult<Label<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            DNameIter::Slice(ref mut iter) => iter.next().map(|x| Ok(x)),
            DNameIter::Packed(ref mut iter) => iter.next()
        }
    }
}


//------------ Label --------------------------------------------------------

/// The content of a domain name label.
///
/// There are two types of labels: normal labels and binary labels. Normal
/// labels consist of up to 63 bytes of data. Binary labels are a sequence
/// of up to 256 one-bit labels. They have been invented for reverse pointer
/// records for IPv6 but have quickly been found to be rather unwieldly and
/// were never widely implemented. Subsequently they have been declared
/// historic and shouldn’t really be found in the wild.
///
/// Additionally, there are compressed labels that point to a position in
/// the DNS message where the domain name continues. These labels are not
/// represented by this type but rather are resolved by
/// `PackedDName::unpack()` on the fly.
///
/// There is room for additional label types, but since experience has shown
/// introduction of new types to be difficult, their emergence is rather
/// unlikely.
///
/// The label type is encoded in the top two bits of the first byte of the
/// label, unless those two bits are `0b01`, then the entire first byte
/// describes the label type. Presently allocated label types are given in
/// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10.
#[derive(Clone, Debug)]
pub struct Label<'a>(LabelContent<'a>);

/// The actual content of a label.
///
/// This type is private so that it is possible to gate label creation
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

    /// Skips over a label and returns whether it was the final label.
    ///
    /// This function also considers compressed labels.
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

    /// Skips over a real label and returns whether it was the final label.
    ///
    /// This function fails for compressed labels.
    fn skip_complete<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<bool> {
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
                Err(ParseError::CompressedLabel)
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
    /// Returns the label and the slice with the rest of the domain name.
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

    /// Returns a string slice if this is a normal label and purely ASCII.
    pub fn as_str(&self) -> Option<&str> {
        match self.0 {
            LabelContent::Normal(s) => str::from_utf8(s).ok(),
            _ => None
        }
    }

    /// Returns a bytes slice if this is a normal label.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self.0 {
            LabelContent::Normal(s) => Some(s),
            _ => None
        }
    }

    /// Returns the length of the label’s wire representation in octets.
    ///
    /// This number includes the first byte. Thus, for normal labels, it is
    /// one more than the actual content.
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

    /// Push the label to the end of a compose target.
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

    /// Push a compressed label to the end of a compression target.
    ///
    /// The pushed label will indicate that the domain name continues at
    /// index `pos` in the message.
    pub fn compose_compressed<C: ComposeBytes>(target: &mut C, pos: u16)
                                               -> ComposeResult<()> {
        try!(LabelHead::Compressed(((pos & 0xFF00) >> 8) as u8)
                       .compose(target));
        target.push_u8((pos & 0xFF) as u8)
    }

    /// Push the label to the end of a bytes vector.
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
    /// Return the label head from an octet.
    fn from_byte(octet: u8) -> ParseResult<Self> {
        match octet {
            0 ... 0x3F => Ok(LabelHead::Normal(octet)),
            0xC0 ... 0xFF => Ok(LabelHead::Compressed(octet & 0x3F)),
            0x41 => Ok(LabelHead::Binary),
            _ => Err(ParseError::UnknownLabel),
        }
    }

    /// Parses a single label head from the start of the parser.
    fn parse<'a, P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        LabelHead::from_byte(try!(parser.parse_u8()))
    }

    /// Splits a label head from the start of a bytes slice.
    ///
    /// Returns the label head and the remainder of the bytes slice.
    fn split_from<'a>(slice: &'a[u8]) -> ParseResult<(LabelHead, &'a[u8])> {
        let (head, slice) = try!(slice.split_u8());
        Ok((try!(LabelHead::from_byte(head)), slice))
    }

    /// Pushes a label head to a compose target.
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

    /// Pushes a label head to the end of a bytes vector.
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
    use std::borrow::Cow;
    use std::ops::Deref;
    use std::str::FromStr;
    use bits::ParseError;
    use bits::parse::{ParseBytes, ContextParser};
    use super::*;

    fn slice(slice: &[u8]) -> &DNameSlice {
        DNameSlice::from_bytes(slice).unwrap()
    }

    #[test]
    fn slice_from_bytes() {
        assert!(slice(b"\x03foo\x03bar\x00").is_absolute());
        assert!(slice(b"\x00").is_absolute());
        assert!(slice(b"\x03foo\x03bar").is_relative());
        assert!(slice(b"").is_relative());
        assert_eq!(DNameSlice::from_bytes(b"\x03foo\x03ba"),
                   Err(ParseError::UnexpectedEnd));
        assert_eq!(DNameSlice::from_bytes(b"\x03foo\x03ba"),
                   Err(ParseError::UnexpectedEnd));
        assert_eq!(DNameSlice::from_bytes(b"\x03foo\x03bar\x00\x03foo")
                              .unwrap().as_bytes(),
                   b"\x03foo\x03bar\x00");
    }

    #[test]
    fn slice_to_string() {
        assert_eq!(slice(b"\x03foo").to_string(), "foo");
        assert_eq!(slice(b"\x03foo\x00").to_string(), "foo.");
        assert_eq!(slice(b"\x03foo\x03bar").to_string(), "foo.bar");
        assert_eq!(slice(b"\x03foo\x03bar\x00").to_string(), "foo.bar.");
        assert_eq!(slice(b"\x03f\xf0o").to_string(), "f\\240o");
        assert_eq!(slice(b"\x03f\x0Ao").to_string(), "f\\010o");
        assert_eq!(slice(b"\x03f.o").to_string(), "f\\.o");
        assert_eq!(slice(b"\x03f\\o").to_string(), "f\\\\o");

        // XXX TODO: Binary labels.
    }

    // DNameSlice::parse: see bits::parse::test.

    #[test]
    fn slice_methods() {
        let empty = slice(b"");
        let dot = slice(b"\x00");
        let foo = slice(b"\x03foo");
        let bar = slice(b"\x03bar");
        let foodot = slice(b"\x03foo\x00");
        let bardot = slice(b"\x03bar\x00");
        let foobar = slice(b"\x03foo\x03bar");
        let foobardot = slice(b"\x03foo\x03bar\00");

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
        assert!(!dot.ends_with(&empty)); assert!(dot.ends_with(&dot));
            assert!(!empty.ends_with(&foo));
        assert!(foo.ends_with(&empty)); assert!(dot.ends_with(&dot));
            assert!(foo.ends_with(&foo)); assert!(!foo.ends_with(&bar));
            assert!(!foo.ends_with(&foodot));
        assert!(!foodot.ends_with(&empty)); assert!(foodot.ends_with(&dot));
            assert!(!foodot.ends_with(&foo)); assert!(!foodot.ends_with(&bar));
            assert!(foodot.ends_with(&foodot));
        assert!(foobar.ends_with(&empty)); assert!(!foobar.ends_with(&dot));
            assert!(!foobar.ends_with(&foo)); assert!(foobar.ends_with(&bar));
        assert!(!foobardot.ends_with(&empty));
            assert!(foobardot.ends_with(&dot));
            assert!(!foobardot.ends_with(&foo));
            assert!(foobardot.ends_with(&bardot));
            assert!(foobardot.ends_with(&foobardot));

        assert_eq!(empty.join(&empty), empty);
        assert_eq!(empty.join(&dot), dot);
        assert_eq!(empty.join(&foo), foo);
        assert_eq!(empty.join(&foodot), foodot);
        assert_eq!(dot.join(&empty), dot);
        assert_eq!(dot.join(&dot), dot);
        assert_eq!(dot.join(&foo), dot);
        assert_eq!(dot.join(&foodot), dot);
        assert_eq!(foo.join(&empty), foo);
        assert_eq!(foo.join(&dot), foodot);
        assert_eq!(foo.join(&bar), foobar);
        assert_eq!(foo.join(&bardot), foobardot);
        assert_eq!(foodot.join(&empty), foodot);
        assert_eq!(foodot.join(&dot), foodot);
        assert_eq!(foodot.join(&foo), foodot);
        assert_eq!(foodot.join(&foodot), foodot);
    }

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
        assert_eq!(DNameBuf::from_vec(Vec::from(&b"\x03foo\x03ba"[..])),
                   Err(ParseError::UnexpectedEnd));
        assert_eq!(DNameBuf::from_vec(Vec::from(&b"\x03foo\x03ba"[..])),
                   Err(ParseError::UnexpectedEnd));
        assert_eq!(buf(b"\x03foo\x03bar\x00\x03foo").as_bytes(),
                   b"\x03foo\x03bar\x00");
    }

    #[test]
    fn buf_push() {
        let suffix_buf = DNameBuf::from_str("bazz").unwrap();
        let suffix = suffix_buf.first().unwrap();
        
        let mut name = DNameBuf::from_str("foo.bar").unwrap();
        name.push(&suffix);
        assert_eq!(name.to_string(), "foo.bar.bazz");
        let mut name = DNameBuf::from_str("foo.bar.").unwrap();
        name.push(&suffix);
        assert_eq!(name.to_string(), "foo.bar.");
    }

    #[test]
    fn buf_append() {
        let suffix = DNameBuf::from_str("wobble.wibble.").unwrap();

        let mut name = DNameBuf::from_str("foo.bar").unwrap();
        name.append(&suffix);
        let mut name = DNameBuf::from_str("foo.bar.").unwrap();
        name.append(&suffix);
        assert_eq!(name.to_string(), "foo.bar.");
    }

    #[test]
    fn packed_split_from() {
        let (name, tail) = PackedDName::split_from(b"\x03foo\x03bar\x00baz",
                                                   b"").unwrap();
        assert_eq!(name.slice, b"\x03foo\x03bar\x00");
        assert_eq!(tail, b"baz");

        let (name, tail) = PackedDName::split_from(b"\x03foo\xC0\0baz", b"")
                                       .unwrap();
        assert_eq!(name.slice, b"\x03foo\xC0\0");
        assert_eq!(tail, b"baz");

        assert!(PackedDName::split_from(b"\x03foo\x03bar", b"").is_err());
        assert!(PackedDName::split_from(b"\x70foo", b"").is_err());
    }

    fn context_parse_dname_ok(message: &[u8], name: &[u8], tail: &[u8]) {
        let mut parser = ContextParser::new(message);
        let parsed = parser.parse_dname().unwrap();
        if let DName::Packed(parsed) = parsed {
            assert_eq!(parsed.slice, name);
            assert_eq!(parsed.context, message);
            assert_eq!(parser.left(), tail.len());
            assert_eq!(parser.parse_bytes(tail.len()).unwrap(), tail);
        }
        else {
            panic!("Not a packed name");
        }
    }

    fn context_parse_dname_err(message: &[u8], err: ParseError) {
        let mut parser = ContextParser::new(message);
        assert_eq!(parser.parse_dname(), Err(err));
    }

    #[test]
    fn context_parse_dname() {
        context_parse_dname_ok(b"\x03foo\x03bar\x00baz", b"\x03foo\x03bar\x00",
                          b"baz");
        context_parse_dname_ok(b"\x03foo\xc0\x00baz", b"\x03foo\xc0\x00",
                          b"baz");

        context_parse_dname_err(b"\x03foo\x03ba", ParseError::UnexpectedEnd);
        context_parse_dname_err(b"\x03foo\x70ba", ParseError::UnknownLabel);
    }

    #[test]
    fn packed_unpack() {
        assert_eq!(PackedDName::new(b"\x03foo\x03bar\x00", b"")
                               .unpack().unwrap(),
                   Cow::Borrowed(
                      DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap()));
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x02",b"xx\x03bar\x00")
                               .unpack().unwrap().deref(),
                   DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap());
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x03",
                                    b"xx\x00\x03bar\xc0\x02")
                               .unpack().unwrap().deref(),
                   DNameSlice::from_bytes(b"\x03foo\x03bar\x00").unwrap());
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x03", b"xx").unpack(),
                   Err(ParseError::UnexpectedEnd));
    }

    #[test]
    fn packed_to_string() {
        assert_eq!(PackedDName::new(b"\x03foo\x03bar\x00", b"")
                               .to_string().unwrap(),
                   "foo.bar.");
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x02",b"xx\x03bar\x00")
                               .to_string().unwrap(),
                   "foo.bar.");
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x03",
                                    b"xx\x00\x03bar\xc0\x02")
                               .to_string().unwrap(),
                   "foo.bar.");
        assert_eq!(PackedDName::new(b"\x03foo\xc0\x03", b"xx").to_string(),
                   Err(ParseError::UnexpectedEnd));
    }
}

