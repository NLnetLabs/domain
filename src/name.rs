//! Domain name handling.
//!

use std::ascii::AsciiExt;
use std::borrow::{Borrow, Cow, ToOwned};
use std::cmp;
use std::convert::{self, Into};
use std::error;
use std::fmt;
use std::hash;
use std::mem;
use std::ops::Deref;
use std::result;
use std::str;

use super::bytes::{self, BytesBuf, BytesSlice};


//------------ DomainName ---------------------------------------------------

/// A trait common to all domain name types.
///
/// This trait only exists so that composed types containing domain names
/// can be generic over the various domain name types we have. The common
/// functionality, however, is very limited.
///
pub trait DomainName: fmt::Display {
    /// Converts the domain name into an owned domain name.
    fn to_owned(&self) -> Result<DomainNameBuf>;

    /// Converts the domain name into a self-contained cow.
    fn to_cow(&self) -> Result<Cow<DomainNameSlice>>;

    /// Pushes the domain name to the end of theprovided buffer.
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;

    /// Pushes the domain name to buffer using name compression.
    fn push_buf_compressed<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}


//------------ DomainNameSlice ----------------------------------------------

/// A byte slice representing a self-contained domain name.
///
/// This is an *unsized* type.
///
#[derive(Debug)]
pub struct DomainNameSlice {
    slice: [u8]
}


/// # Creation and Conversion
///
impl DomainNameSlice {
    /// Create a domain name slice from a bytes slice.
    ///
    /// This is only safe if the slice follows the encoding rules and does
    /// not contain a compressed label.
    ///
    unsafe fn from_bytes(slice: &[u8]) -> &DomainNameSlice {
        mem::transmute(slice)
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.slice
    }

    /// Converts `self` into an owned domain name.
    ///
    pub fn to_owned(&self) -> DomainNameBuf {
        DomainNameBuf::from(self)
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
impl DomainNameSlice {
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


/// # Iteration over labels.
///
impl DomainNameSlice {

    /// Produces an iterator over the labels in the name.
    ///
    pub fn iter(&self) -> NameIter {
        NameIter { slice: &self.slice }
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


/// # Manipulations
///
impl DomainNameSlice {
    /// Returns the first label and the rest of the name.
    ///
    /// Returns `None` if the name is empty.
    ///
    pub fn split_first(&self) -> Option<(Label, &DomainNameSlice)> {
        let mut iter = self.iter();
        iter.next().map(|l| (l, iter.as_name()))
    }

    /// Returns the domain name without its leftmost label.
    ///
    /// Returns `None` for an empty domain name. Returns an empty domain
    /// name for a single label domain name.
    pub fn parent(&self) -> Option<&DomainNameSlice> {
        self.split_first().map(|(_, tail)| tail)
    }

    /// Determines whether `base` is a prefix of `self`.
    ///
    /// The method only cosiders whole labels and compares them
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
    /// The method only cosiders whole labels and compares them
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
    pub fn join<N: AsRef<Self>>(&self, base: N) -> DomainNameBuf {
        self._join(base.as_ref())
    }

    fn _join(&self, base: &Self) -> DomainNameBuf {
        let mut res = self.to_owned();
        res.append(base);
        res
    }
}

impl DomainName for DomainNameSlice {
    fn to_owned(&self) -> Result<DomainNameBuf> {
        Ok(self.to_owned())
    }

    fn to_cow(&self) -> Result<Cow<DomainNameSlice>> {
        Ok(Cow::Borrowed(self))
    }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        buf.add_name_pos(self);
        buf.push_bytes(&self.slice);
        Ok(())
    }
    
    fn push_buf_compressed<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        let mut name = self;
        loop {
            match buf.get_name_pos(name) {
                Some(pos) => {
                    LabelHead::Compressed(((pos & 0xFF00) >> 8) as u8)
                                .push(buf);
                    buf.push_u8((pos & 0xFF) as u8);
                    break;
                }
                None => {
                    let (left, right) = match name.split_first() {
                        Some(x) => x,
                        None => break
                    };
                    buf.add_name_pos(name);
                    left.push_buf(buf);
                    name = right;
                }
            }
        }
        Ok(())
    }
}


impl AsRef<DomainNameSlice> for DomainNameSlice {
    fn as_ref(&self) -> &DomainNameSlice { self }
}


impl ToOwned for DomainNameSlice {
    type Owned = DomainNameBuf;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}

impl<T: AsRef<DomainNameSlice> + ?Sized> PartialEq<T> for DomainNameSlice {
    fn eq(&self, other: &T) -> bool {
        self.iter().eq(other.as_ref().iter())
    }
}

impl<'a> PartialEq<CompactDomainName<'a>> for DomainNameSlice {
    /// Test whether `self` and `other` are equal.
    ///
    /// An unparsable `other` always compares false.
    fn eq(&self, other: &CompactDomainName) -> bool {
        let mut self_iter = self.iter();
        let mut other_iter = other.iter();
        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(left), Some(Ok(right))) => {
                    if left != right { return false }
                }
                (None, None) => { return true }
                _ => { return false }
            }
        }
    }
}

//impl<T: AsRef<str> + ?Sized> PartialEq<T> for DomainNameSlice {
//    fn eq(&self, other: &T) -> bool {
impl PartialEq<str> for DomainNameSlice {
    fn eq(&self, other: &str) -> bool {
        if !other.is_ascii() { return false }
        let mut other = other.as_bytes();
        let mut name = unsafe { DomainNameSlice::from_bytes(&self.slice) };
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

impl cmp::Eq for DomainNameSlice { }


impl<T: AsRef<DomainNameSlice> + ?Sized> PartialOrd<T> for DomainNameSlice {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.as_ref().iter())
    }
}

impl<'a> PartialOrd<CompactDomainName<'a>> for DomainNameSlice {
    fn partial_cmp(&self, other: &CompactDomainName) -> Option<cmp::Ordering> {
        let mut self_iter = self.iter();
        let mut other_iter = other.iter();
        loop {
            match (self_iter.next(), other_iter.next()) {
                (None, None) => return Some(cmp::Ordering::Equal),
                (None, _   ) => return Some(cmp::Ordering::Less),
                (_   , None) => return Some(cmp::Ordering::Greater),
                (Some(left), Some(Ok(right))) => {
                    let ordering = left.partial_cmp(&right);
                    if ordering != Some(cmp::Ordering::Equal) {
                        return ordering;
                    }
                }
                (_, Some(Err(_))) => return None,
            }
        }
    }
}

impl Ord for DomainNameSlice {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


impl hash::Hash for DomainNameSlice {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        use std::hash::Hash;

        for label in self.iter() {
            label.hash(state)
        }
    }
}

impl fmt::Display for DomainNameSlice {
    fn fmt(&self,  f: &mut fmt::Formatter) -> fmt::Result {
        self.to_string().fmt(f)
    }
}


//------------ DomainNameBuf ------------------------------------------------

/// An owned, mutable, self-contained domain name.
///
#[derive(Clone, Debug)]
pub struct DomainNameBuf {
    inner: Vec<u8>
}

impl DomainNameBuf {
    /// Creates a `DomainNameBuf` from a `u8` slice.
    ///
    /// This is only safe if the slice follows the encoding rules.
    ///
    unsafe fn from_bytes(s: &[u8]) -> DomainNameBuf {
        DomainNameBuf { inner: Vec::from(s) }
    }

    /// Creates a new empty domain name.
    ///
    pub fn new() -> DomainNameBuf {
        DomainNameBuf { inner: Vec::new() }
    }

    /// Creates a new domain name with only the root label.
    pub fn root() -> DomainNameBuf {
        let mut res = DomainNameBuf::new();
        res.push(Label::Normal(b""));
        res
    }

    /// Creates a new domain name from a string.
    pub fn from_str(s: &str) -> ParseResult<DomainNameBuf> {
        let mut res = DomainNameBuf::new();
        let mut label = Vec::new();
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '.' => {
                            if label.len() > 63 {
                                return Err(ParseError::OverlongLabel)
                            }
                            res.inner.push(label.len() as u8);
                            res.inner.extend(&label);
                            label.clear();
                        }
                        '\\' => {
                            let ch = try!(chars.next()
                                          .ok_or(ParseError::PrematureEnd));
                            if ch.is_digit(10) {
                                let v = ch.to_digit(10).unwrap() * 100
                                      + try!(chars.next()
                                             .ok_or(ParseError::PrematureEnd)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                  ParseError::IllegalEscape)))
                                             * 10
                                      + try!(chars.next()
                                             .ok_or(ParseError::PrematureEnd)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                 ParseError::IllegalEscape)));
                                label.push(v as u8);
                            }
                            else {
                                label.push(ch as u8);
                            }
                        }
                        ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                            label.push(c as u8);
                        }
                        _ => return Err(ParseError::IllegalCharacter)
                    }
                }
                None => break
            }
        }
        res.inner.push(label.len() as u8);
        res.inner.extend(&label);
        Ok(res)
    }

    /// Coerces to a `DomainNameSlice` slice.
    ///
    pub fn as_name(&self) -> &DomainNameSlice {
        self
    }

    /// Extends self with a normal label.
    ///
    pub fn push_normal<L: AsRef<[u8]>>(&mut self, label: L) -> Result<()> {
        Ok(self.push(try!(Label::new_normal(label.as_ref()))))
    }

    /// Extends self with a binary label.
    ///
    pub fn push_binary(&mut self, count: u8, slice: &[u8]) -> Result<()>{
        Ok(self.push(try!(Label::new_binary(count, slice))))
    }

    /// Extends self with a label.
    pub fn push(&mut self, label: Label) {
        label.push_buf(&mut self.inner);
    }

    /// Extends `self` with a domain name.
    ///
    /// If `self` is already absolute, nothing will happen.
    /// 
    /// XXX Is this a good rule? Checking for absolute names is costly.
    ///
    pub fn append<N: AsRef<DomainNameSlice>>(&mut self, name: N) {
        self._append(name.as_ref())
    }

    fn _append(&mut self, name: &DomainNameSlice) {
        if !self.is_absolute() {
            self.inner.extend(&name.slice)
        }
    }
}

impl DomainName for DomainNameBuf {
    fn to_owned(&self) -> Result<DomainNameBuf> {
        Ok(self.clone())
    }

    fn to_cow(&self) -> Result<Cow<DomainNameSlice>> {
        Ok(Cow::Borrowed(&self))
    }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        self.deref().push_buf(buf)
    }

    fn push_buf_compressed<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        self.deref().push_buf_compressed(buf)
    }
}


impl<'a> From<&'a DomainNameSlice> for DomainNameBuf {
    fn from(n: &'a DomainNameSlice) -> DomainNameBuf {
        unsafe { DomainNameBuf::from_bytes(&n.slice) }
    }
}

impl str::FromStr for DomainNameBuf {
    type Err = ParseError;

    fn from_str(s: &str) -> ParseResult<DomainNameBuf> {
        DomainNameBuf::from_str(s)
    }

}

impl Deref for DomainNameBuf {
    type Target = DomainNameSlice;

    fn deref(&self) -> &Self::Target {
        unsafe { DomainNameSlice::from_bytes(&self.inner) }
    }
}

impl Borrow<DomainNameSlice> for DomainNameBuf {
    fn borrow(&self) -> &DomainNameSlice {
        self.deref()
    }
}


impl AsRef<DomainNameSlice> for DomainNameBuf {
    fn as_ref(&self) -> &DomainNameSlice { self }
}


impl cmp::PartialEq for DomainNameBuf {
    fn eq(&self, other: &Self) -> bool {
        self.deref().eq(other.deref())
    }
}

impl cmp::Eq for DomainNameBuf { }

impl cmp::PartialOrd for DomainNameBuf {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.deref())
    }
}

impl cmp::Ord for DomainNameBuf {
    fn cmp(&self, other: &DomainNameBuf) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}

impl hash::Hash for DomainNameBuf {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


impl fmt::Display for DomainNameBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.deref().fmt(f)
    }
}

//------------ CompactDomainName --------------------------------------------

/// A reference to a possibly compressed domain name.
///
/// This domain name is not self-contained but rather may reference
/// another domain name. Because if this, it always needs a second bytes
/// slice representing the message and called the *context*.
/// 
#[derive(Clone, Debug)]
pub struct CompactDomainName<'a> {
    slice: &'a [u8],
    context: &'a [u8],
}


/// # Creation and Conversion
///
impl<'a> CompactDomainName<'a> {
    /// Creates a new domain name from its components.
    pub fn new(slice: &'a[u8], context: &'a[u8]) -> CompactDomainName<'a> {
        CompactDomainName { slice: slice, context: context }
    }

    /// Splits a wire domain name from the beginning of a  bytes slice.
    pub fn split_from(slice: &'a[u8], context: &'a[u8])
                      -> Result<(CompactDomainName<'a>, &'a[u8])> {
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(slice, pos));
            if head.is_final() {
                let (bytes, slice) = try!(slice.split_bytes(end));
                return Ok((CompactDomainName::new(bytes, context), slice));
            }
            pos = end;
        }
    }

    /// Converts `self` into a self-contained, owned domain name.
    pub fn to_owned(&self) -> Result<DomainNameBuf> {
        Ok(try!(self.decompress()).into_owned())
    }

    /// Decompresses `self`.
    ///
    /// If `self` does not contain any compressed labels, it will be
    /// coerced into a regular domain name slice. If it does, it will be
    /// converted into an owned domain name.
    pub fn decompress(&self) -> Result<Cow<'a, DomainNameSlice>> {
        // Walk over the name and return it if it ends without compression.
        let mut pos = 0;
        loop {
            let (end, head) = try!(Label::peek(self.slice, pos));
            match head {
                LabelHead::Normal(0) => {
                    let name = unsafe { 
                        DomainNameSlice::from_bytes(&self.slice[..end])
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
        let mut res = unsafe { DomainNameBuf::from_bytes(bytes) };
        for label in CompactIter::new(slice, self.context) {
            let label = try!(label);
            res.push(label)
        }
        Ok(Cow::Owned(res))
    }

    pub fn to_string(&self) -> Result<String> {
        // Assuming a properly parsed out slice, the resulting string is
        // at least its sice.
        let mut res = String::with_capacity(self.slice.len());
        for label in self.iter() {
            let label = try!(label);
            if !res.is_empty() { res.push('.') }
            label.push_string(&mut res)
        }
        Ok(res)
    }
}


// # Iteration over Labels
//
impl<'a> CompactDomainName<'a> {
    /// Returns an iterator over the labels.
    pub fn iter(&self) -> CompactIter<'a> {
        CompactIter::new(self.slice, self.context)
    }
}


impl<'a> DomainName for CompactDomainName<'a> {
    fn to_owned(&self) -> Result<DomainNameBuf> {
        self.to_owned()
    }

    fn to_cow(&self) -> Result<Cow<DomainNameSlice>> {
        self.decompress()
    }

    fn push_buf<O: BytesBuf>(&self, buf: &mut O) -> Result<()> {
        for label in self.iter() {
            try!(label).push_buf(buf)
        }
        Ok(())
    }

    fn push_buf_compressed<O: BytesBuf>(&self, buf: &mut O) -> Result<()> {
        try!(self.decompress()).push_buf_compressed(buf)
    }
}


impl<'a> PartialEq for CompactDomainName<'a> {
    fn eq(&self, other: &CompactDomainName) -> bool {
        self.iter().eq(other.iter())
    }
}

impl<'a, T: AsRef<DomainNameSlice> + ?Sized> PartialEq<T> for CompactDomainName<'a>
{
    fn eq(&self, other: &T) -> bool {
        other.as_ref().eq(self)
    }
}

impl<'a, T: AsRef<DomainNameSlice> + ?Sized> PartialOrd<T> for CompactDomainName<'a>
{
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        other.as_ref().partial_cmp(self).map(|o| o.reverse())
    }
}

impl<'a> fmt::Display for CompactDomainName<'a> {
    fn fmt(&self,  f: &mut fmt::Formatter) -> fmt::Result {
        match self.to_string() {
            Ok(s) => s.fmt(f),
            Err(..) => "<PARSEERR>".fmt(f)
        }
    }
}


//------------ NameIter -----------------------------------------------------

/// An iterator over the labels in a domain name.
#[derive(Clone, Debug)]
pub struct NameIter<'a> {
    slice: &'a [u8]
}

impl<'a> NameIter<'a> {
    /// Returns the domain name for the remaining portion.
    pub fn as_name(&self) -> &'a DomainNameSlice {
        unsafe { DomainNameSlice::from_bytes(self.slice) }
    }
}

impl<'a> Iterator for NameIter<'a> {
    type Item = Label<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (label, slice) = match Label::split_from(self.slice) {
            Err(..) => return None,
            Ok(res) => res
        };
        self.slice = slice;
        Some(label)
    }
}


//------------ CompactIter --------------------------------------------------

/// An iterator over the labels in a frail domain name.
#[derive(Clone, Debug)]
pub struct CompactIter<'a> {
    slice: &'a[u8],
    context: &'a[u8],
}

impl<'a> CompactIter<'a> {
    fn new(slice: &'a[u8], context: &'a[u8]) -> CompactIter<'a> {
        CompactIter { slice: slice, context: context }
    }

    pub fn as_name(&self) -> Result<Cow<'a, DomainNameSlice>> {
        CompactDomainName::new(self.slice, self.context).decompress()
    }
}

impl<'a> Iterator for CompactIter<'a> {
    type Item = Result<Label<'a>>;

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
pub enum Label<'a> {
    /// A normal label containing up to 63 octets.
    Normal(&'a [u8]),

    /// A binary label.
    ///
    /// The first element is the number of bits in the label with zero
    /// indicating 256 bits. The second element is the byte slice
    /// representing the bit field padded to full octets.
    ///
    /// This vairant is historic and annoying and shouldn't really be
    /// encountered anymore.
    Binary(u8, &'a[u8]),
}


impl<'a> Label<'a> {
    /// Create a new normal label.
    fn new_normal(s: &[u8]) -> Result<Label> {
        if s.len() > 63 { ErrorKind::OverlongLabel.into() }
        else { Ok(Label::Normal(s)) }
    }

    /// Creates a new binary label.
    fn new_binary(count: u8, s: &[u8]) -> Result<Label> {
        let len = Self::binary_len(count);
        try!(s.check_len(len));
        return Ok(Label::Binary(count, &s[..len]))
    }

    /// Splits a label from the beginning of a bytes slice.
    ///
    /// Returns the label and the remainder of the slice.
    ///
    fn split_from(slice: &'a[u8]) -> Result<(Label<'a>, &'a[u8])> {
        let (head, slice) = try!(LabelHead::split_from(slice));
        match head {
            LabelHead::Normal(len) => {
                let (bytes, slice) = try!(slice.split_bytes(len as usize));
                Ok((Label::Normal(bytes), slice))
            }
            LabelHead::Binary => {
                let (count, slice) = try!(slice.split_u8());
                let len = Label::binary_len(count);
                let (bytes, slice) = try!(slice.split_bytes(len));
                Ok((Label::Binary(count, bytes), slice))
            }
            LabelHead::Compressed(_) => {
                ErrorKind::UnexpectedCompression.into()
            }
        }
    }

    /// Split a possibly compressed label from the beginning of a slice.
    ///
    /// Returns the label, whether this was a compressed label, and the
    /// slice to keep parsing the next labels from.
    fn split_compressed(slice: &'a[u8], context: &'a[u8])
                        -> Result<(Label<'a>, &'a[u8])> {
        let (head, slice) = try!(LabelHead::split_from(slice));
        match head {
            LabelHead::Normal(len) => {
                let (bytes, slice) = try!(slice.split_bytes(len as usize));
                Ok((Label::Normal(bytes), slice))
            }
            LabelHead::Binary => {
                let (count, slice) = try!(slice.split_u8());
                let len = Label::binary_len(count);
                let (bytes, slice) = try!(slice.split_bytes(len));
                Ok((Label::Binary(count, bytes), slice))
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
    fn peek(slice: &[u8], pos: usize) -> Result<(usize, LabelHead)> {
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
        match *self {
            Label::Normal(s) => str::from_utf8(s).ok(),
            _ => None
        }
    }

    /// Returns the length of the label’s wire representation in octets.
    pub fn len(&self) -> usize {
        match *self {
            Label::Normal(s) => s.len() + 1,
            Label::Binary(count, _) => Self::binary_len(count) + 2,
        }
    }

    /// Returns whether this is the root label
    pub fn is_root(&self) -> bool {
        match *self {
            Label::Normal(b"") => true,
            _ => false,
        }
    }

    /// Push the label to the end of an octet buffer.
    fn push_buf<O: BytesBuf>(&self, vec: &mut O) {
        match *self {
            Label::Normal(slice) => {
                assert!(slice.len() <= 63);
                vec.push_u8(slice.len() as u8);
                vec.push_bytes(slice);
            }
            Label::Binary(count, slice) => {
                assert!(slice.len() == Self::binary_len(count));
                LabelHead::Binary.push(vec);
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

        match *self {
            Label::Normal(slice) => {
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
            Label::Binary(count, slice) => {
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
    fn eq_zonefile<'b>(&self, mut s: &'b[u8]) -> result::Result<bool, &'b[u8]> {
        match *self {
            Label::Normal(l) => {
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
            Label::Binary(count, l) => {
                // XXX TODO
                let _ = (count, l);
                unimplemented!()
            }
        }
    }
}


impl<'a> PartialEq for Label<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (&Label::Normal(l), &Label::Normal(r)) => {
                l.eq_ignore_ascii_case(r)
            }
            (&Label::Binary(lc, ls), &Label::Binary(rc, rs)) => {
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
        match self {
            &Label::Normal(slice) => {
                slice.eq_ignore_ascii_case(other)
            }
            _ => false
        }
    }
}

impl<'a> PartialEq<str> for Label<'a> {
    fn eq(&self, other: &str) -> bool {
        self.eq(other.as_bytes())
    }
}

impl<'a> Eq for Label<'a> { }

impl<'a> PartialOrd for Label<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for Label<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (&Label::Normal(l), &Label::Normal(r)) => {
                l.iter().map(u8::to_ascii_lowercase).cmp(
                    r.iter().map(u8::to_ascii_lowercase))
            }
            (&Label::Binary(_, ls), &Label::Binary(_, rs)) => {
                // XXX This considers the padding bits and thus might
                //     be wrong.
                ls.cmp(rs)
            }
            (&Label::Normal(..), &Label::Binary(..)) => cmp::Ordering::Greater,
            (&Label::Binary(..), &Label::Normal(..)) => cmp::Ordering::Less,
        }
    }
}

impl<'a> hash::Hash for Label<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match self {
            &Label::Normal(slice) => {
                state.write_u8(0);
                for ch in slice {
                    state.write_u8(ch.to_ascii_lowercase())
                }
            }
            &Label::Binary(count, slice) => {
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


//------------ LabelHead ----------------------------------------------------

/// The first octet of a domain name.
///
/// This is an internal type used for parsing labels. We only have variants
/// for the defined label types. Illegal or unknown types will result in
/// parse errors.
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
    fn from_byte(octet: u8) -> Result<LabelHead> {
        match octet {
            0 ... 0x3F => Ok(LabelHead::Normal(octet)),
            0xC0 ... 0xFF => Ok(LabelHead::Compressed(octet & 0x3F)),
            0x41 => Ok(LabelHead::Binary),
            _ => ErrorKind::IllegalLabelType.into(),
        }
    }

    fn split_from<'a>(slice: &'a[u8]) -> Result<(LabelHead, &'a[u8])> {
        let (head, slice) = try!(slice.split_u8());
        Ok((try!(LabelHead::from_byte(head)), slice))
    }

    fn push<O: BytesBuf>(self, buf: &mut O) {
        match self {
            LabelHead::Normal(c) => {
                assert!(c <= 0x3F);
                buf.push_u8(c)
            }
            LabelHead::Compressed(c) => {
                assert!(c != 0x3F);
                buf.push_u8(c | 0xC0)
            }
            LabelHead::Binary => {
                buf.push_u8(0x41)
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


//------------ Error and Result ---------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum ErrorKind {
    OverlongLabel,
    IllegalEscape,
    IllegalCharacter,
    IllegalLabelType,
    UnexpectedCompression,
}

impl ErrorKind {
    pub fn description(&self) -> &str {
        match *self {
            ErrorKind::OverlongLabel => "a label exceeds maximum length",
            ErrorKind::IllegalEscape =>
                                    "illegal escape sequence in domain name",
            ErrorKind::IllegalCharacter => "illegal character in domain name",
            ErrorKind::IllegalLabelType => "illegal label type in domain name",
            ErrorKind::UnexpectedCompression => "unexpected compressed label",
        }
    }
}

impl<T> Into<Result<T>> for ErrorKind {
    fn into(self) -> Result<T> { Err(Error::NameError(self)) }
}


#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NameError(ErrorKind),
    OctetError(bytes::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::NameError(ref kind) => kind.description(),
            Error::OctetError(ref kind) => kind.description()
        }
    }
}

impl convert::From<bytes::Error> for Error {
    fn from(error: bytes::Error) -> Error {
        Error::OctetError(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}

pub type Result<T> = result::Result<T, Error>;


//------------ ParseError and ParseResult -----------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    PrematureEnd,
    OverlongLabel,
    IllegalEscape,
    IllegalCharacter,
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        use self::ParseError::*;

        match *self {
            PrematureEnd => "unexpected end",
            OverlongLabel => "a label exceeds the maximum length",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}

pub type ParseResult<T> = result::Result<T, ParseError>;


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


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn label_from_bytes() {
        assert_eq!(Label::split_from(b"\x05abcdefg"),
                   Ok((Label::Normal(b"abcde"), &b"fg"[..])));
        assert_eq!(Label::split_from(b"\x41\x03abc"),
                   Ok((Label::Binary(0x03, &b"a"[..]), &b"bc"[..])));
        assert_eq!(Label::split_from(b"\x41\x08abc"),
                   Ok((Label::Binary(0x08, &b"a"[..]), &b"bc"[..])));
        assert_eq!(Label::split_from(b"\x41\x09abc"),
                   Ok((Label::Binary(0x09, &b"ab"[..]), &b"c"[..])));

        assert!(Label::split_from(b"\xc1\x11abc").is_err());
        assert!(Label::split_from(b"\x83abd").is_err());
        assert!(Label::split_from(b"").is_err());
        assert!(Label::split_from(b"\x05abc").is_err());
        assert!(Label::split_from(b"\xc1").is_err());
    }

    #[test]
    fn starts_with() {
        assert!(dname!(b"abc", b"def", b"ghi")
                    .starts_with(dname!(b"abc")));
        assert!(dname!(b"abc", b"def", b"ghi", b"")
                    .starts_with(dname!(b"abc", b"DEF")));
        assert!(!dname!(b"abc", b"def", b"ghi")
                    .starts_with(dname!(b"abc", b"")));
        assert!(!dname!(b"abc", b"def", b"ghi", b"")
                    .starts_with(dname!(b"abc", b"iop")));
    }

    #[test]
    fn ends_with() {
        assert!(dname!(b"abc", b"def", b"ghi", b"")
                    .ends_with(dname!(b"ghi", b"")));
    }
}
