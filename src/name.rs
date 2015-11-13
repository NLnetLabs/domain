use std::ascii::AsciiExt;
use std::borrow::{Borrow, Cow, /* unstable IntoCow, */ ToOwned};
use std::cmp;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter;
use std::mem;
use std::ops::{self, Deref};
use std::str;


//------------ Domain Label -------------------------------------------------

/// The content of a domain name label.
///
/// This is basically just a `u8` slice. If the label is just ASCII, it can
/// be coerced into a `str`. This should be the case pretty much always, but
/// the protocol allows the full `u8` range in labels.
///
/// This is an *unsized* type.
///
pub struct Label {
    pub inner: [u8]
}

impl Label {
    fn from_bytes(s: &[u8]) -> &Label {
        unsafe { mem::transmute(s) }
    }

    fn from_str(s: &str) -> &Label {
        Label::from_bytes(s.as_bytes())
    }

    /// Coerces into a `Label` slice.
    ///
    pub fn new<L: AsRef<Label> + ?Sized>(l: &L) -> &Label {
        l.as_ref()
    }

    /// Yields a `&str` slice if `self` is purely ASCII.
    ///
    pub fn as_str(&self) -> Option<&str> {
        match self.inner.is_ascii() {
            true => str::from_utf8(&self.inner).ok(),
            false => None
        }
    }

    /// Converts `self` to a `Cow<str>`.
    ///
    /// Non-printable ASCII characters plus ' ', '.', and '\' are escaped
    /// zonefile-style.
    ///
    pub fn to_string_lossy(&self) -> Cow<str> {
        if self.needs_escaping() {
            let mut res = String::new();
            for &ch in self.inner.iter() {
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
            Cow::Owned(res)
        }
        else {
            unsafe {
                Cow::Borrowed(mem::transmute(&self.inner))
            }
        }
    }

    /// Convert `self` to an owned `Vec<u8>`.
    ///
    pub fn to_owned(&self) -> Vec<u8> {
        Vec::from(&self.inner)
    }

    /// Returns true if the label is empty.
    ///
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns whether the label needs escaping for string conversion.
    ///
    /// A label needs escaping if it contains non-printable ASCII
    /// characters, `' '`, `'.'` or `'\\'`.
    ///
    pub fn needs_escaping(&self) -> bool {
        self.inner.iter().any(|&ch| {
            ch <= b' ' || ch == b'.' || ch == b'\\' || ch >= 0x7F
        })
    }
}

impl AsRef<Label> for Label {
    fn as_ref(&self) -> &Label {
        self
    }
}

impl AsRef<Label> for [u8] {
    fn as_ref(&self) -> &Label {
        Label::from_bytes(self)
    }
}

impl AsRef<Label> for str {
    fn as_ref(&self) -> &Label {
        Label::from_str(self)
    }
}

impl<T: AsRef<Label> + ?Sized> cmp::PartialEq<T> for Label {
    fn eq(&self, other: &T) -> bool {
        self.inner.eq_ignore_ascii_case(&Label::new(other).inner)
    }
}

impl cmp::Eq for Label { }

impl<T: AsRef<Label> + ?Sized> cmp::PartialOrd<T> for Label {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.inner.to_ascii_lowercase().partial_cmp(
            &Label::new(other).inner.to_ascii_lowercase())
    }
}

impl cmp::Ord for Label {
    fn cmp(&self, other: &Label) -> cmp::Ordering {
        self.inner.to_ascii_lowercase().cmp(&other.inner.to_ascii_lowercase())
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.to_ascii_lowercase().hash(state)
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string_lossy(), formatter)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_string_lossy(), formatter)
    }
}


//------------ Iterator -----------------------------------------------------

/// The iterator over the labels of a domain name slice.
///
/// Due to the way domain names are stored, it can only iterate forwards.
///
#[derive(Clone)]
pub struct Iter<'a> {
    // the raw slice to eat labels from
    slice: &'a [u8]
}


impl<'a> Iter<'a> {

    /// Extracts a domain name slice corresponding to the portion of the
    /// domain name remaining for iteration.
    ///
    pub fn as_name(&self) -> &'a DomainName {
        unsafe { DomainName::from_bytes(self.slice) }
    }
}

impl<'a> iter::Iterator for Iter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        self.slice.first().map(|n| {
            let (head, tail) = self.slice.split_at(*n as usize + 1);
            let (_, head) = head.split_at(1);
            self.slice = &tail;
            Label::from_bytes(head)
        })
    }
}


//------------ Domain Name Buffer -------------------------------------------

/// An owned, mutable domain name (akin to `String).
///
#[derive(Clone)]
pub struct DomainNameBuf {
    inner: Vec<u8>
}

impl DomainNameBuf {
    // Create a `DomainNameBuf` from a `u8` slice. This is only safe it the
    // slice follows the encoding rules.
    //
    unsafe fn from_bytes(s: &[u8]) -> DomainNameBuf {
        DomainNameBuf { inner: Vec::from(s) }
    }

    /// Creates a new empty `DomainNameBuf`
    ///
    pub fn new() -> DomainNameBuf {
        DomainNameBuf { inner: Vec::new() }
    }

    /// Coerces to a `DomainName` slice.
    ///
    pub fn as_name(&self) -> &DomainName {
        self
    }

    /// Extends `self` with `name`.
    ///
    /// If `self` is already absolute, nothing happens.
    ///
    pub fn push<N: AsRef<DomainName>>(&mut self, name: N) {
        self._push(name.as_ref())
    }

    fn _push(&mut self, name: &DomainName) {
        if !self.is_absolute() {
            self.inner.extend(&name.inner)
        }
    }

}

impl<'a> From<&'a DomainName> for DomainNameBuf {
    fn from(n: &'a DomainName) -> DomainNameBuf {
        unsafe { DomainNameBuf::from_bytes(&n.inner) }
    }
}

impl<N: AsRef<DomainName>> iter::FromIterator<N> for DomainNameBuf {
    fn from_iter<I: IntoIterator<Item = N>>(iter: I) -> DomainNameBuf {
        let mut buf = DomainNameBuf::new();
        buf.extend(iter);
        buf
    }
}

impl<N: AsRef<DomainName>> iter::Extend<N> for DomainNameBuf {
    fn extend<I: IntoIterator<Item = N>>(&mut self, iter: I) {
        for p in iter {
            self.push(p.as_ref())
        }
    }
}

impl fmt::Debug for DomainNameBuf {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
    }
}

impl ops::Deref for DomainNameBuf {
    type Target = DomainName;

    fn deref(&self) -> &DomainName {
        unsafe { DomainName::from_bytes(&self.inner) }
    }
}

impl Borrow<DomainName> for DomainNameBuf {
    fn borrow(&self) -> &DomainName {
        self.deref()
    }
}

/* XXX Unstable

impl IntoCow<'static, DomainName> for DomainNameBuf {
    fn into_cow(self) -> Cow<'static, DomainName> {
        Cow::Owned(self)
    }
}

impl IntoCow<'a, DomainName> for &'a DomainName {
    fn into_cow(self) -> Cow<'a, DomainName> {
        Cow::Borrowed(self)
    }
}
*/

impl ToOwned for DomainName {
    type Owned = DomainNameBuf;
    fn to_owned(&self) -> DomainNameBuf { self.to_owned() }
}

impl cmp::PartialEq for DomainNameBuf {
    fn eq(&self, other: &DomainNameBuf) -> bool {
        self.inner.eq_ignore_ascii_case(&other.inner)
    }
}

impl cmp::Eq for DomainNameBuf { }

impl cmp::PartialOrd for DomainNameBuf {
    fn partial_cmp(&self, other: &DomainNameBuf) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.deref())
    }
}

impl cmp::Ord for DomainNameBuf {
    fn cmp(&self, other: &DomainNameBuf) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}

impl Hash for DomainNameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.to_ascii_lowercase().hash(state)
    }
}

impl str::FromStr for DomainNameBuf {
    type Err = Error;

    fn from_str(s: &str) -> Result<DomainNameBuf, Error> {
        let mut res = DomainNameBuf::new();
        let mut label = Vec::new();
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '.' => {
                            if label.len() > 63 {
                                return Err(Error::OverlongLabel)
                            }
                            res.inner.push(label.len() as u8);
                            res.inner.extend(&label);
                            label.clear();
                        }
                        '\\' => {
                            let ch = try!(chars.next()
                                          .ok_or(Error::PrematureEnd));
                            if ch.is_digit(10) {
                                let v = ch.to_digit(10).unwrap() * 100
                                      + try!(chars.next()
                                             .ok_or(Error::PrematureEnd)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                        Error::IllegalEscape)))
                                             * 10
                                      + try!(chars.next()
                                             .ok_or(Error::PrematureEnd)
                                             .and_then(|c| c.to_digit(10)
                                                       .ok_or(
                                                       Error::IllegalEscape)));
                                label.push(v as u8);
                            }
                            else {
                                label.push(ch as u8);
                            }
                        }
                        ' ' ... '-' | '/' ... '[' | ']' ... '~' => {
                            label.push(c as u8);
                        }
                        _ => return Err(Error::IllegalCharacter)
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

//------------ Domain Name Slice --------------------------------------------

/// A slice of a domain name (akin to `str`).
///
/// Domain names are stored in a wire-like format as a `u8` slice in the
/// form of a sequence of a single length byte followed by that many bytes
/// for the label. Compressed and extended labels are not supported. This
/// means the length byte can be at most 63. This also means that raw
/// `u8` slices may be illegal which is why you cannot safely coerce domain
/// names from `u8` slices.
///
/// This is an *unsized* type.
///
pub struct DomainName {
    inner: [u8]
}

impl DomainName {
    // Create a `DomainName` from a `u8` slice. This is only safe if the
    // slice follows the encoding rules.
    //
    unsafe fn from_bytes(s: &[u8]) -> &DomainName {
        mem::transmute(s)
    }

    /// Yields the underlying `[u8]`.
    ///
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Converts a `DomainName` to an owned `DomainNameBuf`.
    ///
    pub fn to_owned(&self) -> DomainNameBuf {
        DomainNameBuf::from(self)
    }

    /// A domain name is *absolute* if it ends with an empty label.
    ///
    pub fn is_absolute(&self) -> bool {
        self.last().map_or(false, |l| l.is_empty())
    }

    /// A domain name is *relative* if it is not absolute.
    ///
    /// Inicidentally, this means that an empty domain name is relative.
    ///
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// The domain name without its leftmost label.
    ///
    /// Returns `None` for an empty domain name. Returns an empty domain
    /// name for a single label domain name.
    ///
    pub fn parent(&self) -> Option<&DomainName> {
        self.split_first().map(|(_, tail)| tail)
    }

    /// Determines whether `base` is a prefix of `self`.
    ///
    /// Only considers whole labels. Comparision happens DNS-style, ie.,
    /// case insensitive.
    ///
    pub fn starts_with<N: AsRef<DomainName>>(&self, base: N) -> bool {
        self._starts_with(base.as_ref())
    }

    fn _starts_with(&self, base: &DomainName) -> bool {
        let mut self_iter = self.iter();
        let mut base_iter = base.iter();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (Some(_), None) => return true,
                (None, None) => return true,
                (None, Some(_)) => return false
            }
        }
    }

    /// Determines whether `base` is a suffix of `self`.
    ///
    /// Only considers whole labels. Comparision happens DNS-style, ie.,
    /// case insensitive.
    ///
    pub fn ends_with<N: AsRef<DomainName>>(&self, base: N) -> bool {
        self._ends_with(base.as_ref())
    }

    fn _ends_with(&self, base: &DomainName) -> bool {
        let mut self_iter = self.iter();

        loop {
            let mut base_iter = base.iter();
            let base_first = match base_iter.next() {
                Some(l) => l,
                None => return false
            };
            if self_iter.find(|&l| l == base_first).is_none() {
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
    pub fn join<N: AsRef<DomainName>>(&self, base: N) -> DomainNameBuf {
        self._join(base.as_ref())
    }

    fn _join(&self, base: &DomainName) -> DomainNameBuf {
        let mut buf = self.to_owned();
        buf.push(base);
        buf
    }

    /// Produce an iterator over the domain name’s labels.
    ///
    pub fn iter(&self) -> Iter {
        Iter { slice: &self.inner }
    }

    //--- Behave like a slice of labels
    //
    // None of these are particularily cheap.
    //

    /// Returns the number of labels in `self`.
    ///
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Returns true if there are no labels in `self`.
    ///
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the first label or `None` if the name is empty.
    ///
    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    /// Returns the last label or `None` if the name is empty.
    ///
    pub fn last(&self) -> Option<&Label> {
        self.iter().last()
    }

    /// Returns the first label and the rest of the name.
    ///
    /// Returns `None` if the name is empty.
    ///
    pub fn split_first(&self) -> Option<(&Label, &DomainName)> {
        let mut iter = self.iter();
        iter.next().map(|l| (l, iter.as_name()))
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        for label in self.iter() {
            if !first { try!(formatter.write_str(".")); }
            else { first = false; }
            try!(formatter.write_str(&label.to_string_lossy()));
        }
        Ok(())
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl<T: AsRef<DomainName> + ?Sized> cmp::PartialEq<T> for DomainName {
    fn eq(&self, other: &T) -> bool {
        // Since the maximum label size 63 is below the ASCII letters,
        // we can simply AsciiExt::eq_ignore_ascii_case the whole slice.
        self.inner.eq_ignore_ascii_case(&other.as_ref().inner)
    }
}

impl cmp::Eq for DomainName { }

impl<T: AsRef<DomainName> + ?Sized> cmp::PartialOrd<T> for DomainName {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        // Sadly, for ordering that trick doesn't work. We should
        // lexically compare label by label.

        // XXX Switch to this here once that's stable:
        // self.iter().partial_cmp(other.as_ref().iter())
        for (self_label, other_label) in self.iter().zip(other.as_ref().iter())
        {
            match self_label.cmp(other_label) {
                cmp::Ordering::Less => return Some(cmp::Ordering::Less),
                cmp::Ordering::Greater => return Some(cmp::Ordering::Greater),
                _ => continue
            }
        }
        Some(cmp::Ordering::Equal)
    }
}

impl cmp::Ord for DomainName {
    fn cmp(&self, other: &DomainName) -> cmp::Ordering {
        // XXX Switch to this here once that's stable:
        // self.iter().cmp(other.as_ref().iter())
        self.partial_cmp(other).unwrap()
    }
}

impl AsRef<DomainName> for DomainName {
    fn as_ref(&self) -> &DomainName { self }
}

impl AsRef<DomainName> for DomainNameBuf {
    fn as_ref(&self) -> &DomainName { self }
}


impl Hash for DomainName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.to_ascii_lowercase().hash(state)
    }
}


//------------ Errors -------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    OverlongLabel,
    PrematureEnd,
    IllegalEscape,
    IllegalCharacter
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "failed to parse domain name".fmt(f)
    }
}


//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::string::ToString;

    //--- From and to string

    fn assert_str(s: &str) {
        assert_eq!(DomainNameBuf::from_str(s).unwrap().to_string(), s);
    }

    #[test]
    pub fn test_from_string() {
        assert_str("foo.bar.baz.");
        assert_str("foo.bar.baz");
        assert_str("foo\\.bar.baz");
        assert_str("foo\\020.bar.baz");
    }
                

    //--- Label

    #[test]
    pub fn test_label_eq() {
        assert!(Label::new("foo") == Label::new("foo"));
        assert!(Label::new("foo") == "foo");
        assert!(Label::new("foo") == "foo".as_bytes());
    }

    #[test]
    pub fn test_label_neq() {
        assert!(Label::new("foo") != Label::new("bar"));
        assert!(Label::new("foo") != "bar");
        assert!(Label::new("foo") != "bar".as_bytes());
    }


    //--- DomainNameBuf
    

    //--- DomainName

    #[test]
    pub fn test_name_iter() {
    }
}
