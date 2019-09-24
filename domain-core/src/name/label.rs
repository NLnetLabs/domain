//! Domain name labels.
//!
//! This is a private module. Its public types are re-exported by the parent
//! module.

use core::{borrow, cmp, fmt, hash, ops};
use derive_more::Display;
use crate::octets::{Compose, OctetsBuilder, ShortBuf};


//------------ Label ---------------------------------------------------------

/// A slice with the content of a domain name label.
///
/// This is an unsized type wrapping the content of a valid label.
///
/// There are two types of such labels: normal labels and binary labels.
/// Normal labels consist of up to 63 bytes of data. Binary labels are a
/// sequence of up to 256 one-bit labels. They have been invented for reverse
/// pointer records for IPv6 but have quickly been found to be rather
/// unwieldly and were never widely implemented. Subsequently they have been
/// declared historic and are forbidden to be supported. So we don’t.
///
/// In theory there can be even more types of labels, but based on the
/// experience with binary labels, it is very unlikely that there ever will
/// be any.
///
/// Consequently, `Label` will only ever contain a byte slice of up to 63
/// bytes. It only contains the label’s content, not the length octet it is
/// preceded by in wire format. The type derefs to `[u8]`, providing access
/// to all of a byte slice’s methods. As an usized type, it needs to be used
/// behind some kind of pointer, most likely a reference.
///
/// `Label` differs from a byte slice in how it compares: as labels are to be
/// case-insensititve, all the comparision traits as well as `Hash` are
/// implemented igoring ASCII-case.
pub struct Label([u8]);

/// # Creation
///
impl Label {
    /// Creates a label from the underlying byte slice without any checking.
    pub(super) unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    /// Creates a label from the underlying byte slice without any checking.
    pub(super) unsafe fn from_slice_mut_unchecked(
        slice: &mut [u8]
    ) -> &mut Self {
        &mut *(slice as *mut [u8] as *mut Self)
    }

    /// Returns a static reference to the root label.
    ///
    /// The root label is an empty label.
    pub fn root() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"") }
    }

    /// Returns a static reference to the wildcard label `"*"`.
    pub fn wildcard() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"*") }
    }

    /// Converts a byte slice into a label.
    ///
    /// This will fail if the slice is longer than 63 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongLabelError> {
        if slice.len() > 63 {
            Err(LongLabelError)
        }
        else {
            Ok(unsafe { Self::from_slice_unchecked(slice) })
        }
    }

    /// Splits a label from the beginning of a byte slice.
    ///
    /// On success, the functon returns a label and the remainder of
    /// the slice.
    pub fn split_from(slice: &[u8])
                      -> Result<(&Self, &[u8]), SplitLabelError> {
        let head = match slice.get(0) {
            Some(ch) => *ch,
            None => return Err(SplitLabelError::ShortBuf)
        };
        let end = match head {
            0 ..= 0x3F => (head as usize) + 1,
            0x40 ..= 0x7F => {
                return Err(
                    SplitLabelError::BadType(LabelTypeError::Extended(head))
                )
            }
            0xC0 ..= 0xFF => {
                let res = match slice.get(1) {
                    Some(ch) => u16::from(*ch),
                    None => return Err(SplitLabelError::ShortBuf)
                };
                let res = res | ((u16::from(head) & 0x3F) << 8);
                return Err(SplitLabelError::Pointer(res))
            }
            _ => {
                return Err(
                    SplitLabelError::BadType(LabelTypeError::Undefined)
                )
            }
        };
        if slice.len() < end {
            return Err(SplitLabelError::ShortBuf)
        }
        Ok((unsafe { Self::from_slice_unchecked(&slice[1..end]) },
            &slice[end..]))
    }

    /// Iterates over the labels in a message slice.
    ///
    /// The first label is assumed to start at index `start`.
    ///
    /// Stops at the root label, the first broken label, or if a compression
    /// pointer is found that is pointing forward.
    ///
    /// # Panics
    ///
    /// Panics if `start` is beyond the end of `slice`.
    pub fn iter_slice(slice: &[u8], start: usize) -> SliceLabelsIter {
        SliceLabelsIter { slice, start }
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns a mutable reference to the underlying byte slice.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }

    /// Returns the label in canonical form.
    /// 
    /// In this form, all ASCII letters are lowercase.
    pub fn to_canonical(&self) -> OwnedLabel {
        let mut res = OwnedLabel::from_label(self);
        res.make_canonical();
        res
    }

    /// Returns the composed label ordering.
    pub fn composed_cmp(&self, other: &Self) -> cmp::Ordering {
        match self.0.len().cmp(&other.0.len()) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        self.0.cmp(other.as_ref())
    }

    /// Returns the composed ordering with ASCII letters lowercased.
    pub fn lowercase_composed_cmp(&self, other: &Self) -> cmp::Ordering {
        match self.0.len().cmp(&other.0.len()) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        self.cmp(other)
    }

    pub fn build<Builder: OctetsBuilder>(
        &self, target: &mut Builder
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            target.append_slice(&[self.len() as u8])?;
            target.append_slice(self.as_slice())
        })
    }

    pub fn build_lowercase<Builder: OctetsBuilder>(
        &self, target: &mut Builder
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            target.append_slice(&[self.len() as u8])?;
            for &ch in self.into_iter() {
                target.append_slice(&[ch.to_ascii_lowercase()])?;
            }
            Ok(())
        })
    }
}

/// # Properties
///
impl Label {
    /// Returns whether the label is the root label.
    pub fn is_root(&self) -> bool {
        self.is_empty()
    }

    /// Returns whether the label is the wildcard label.
    pub fn is_wildcard(&self) -> bool {
        self.0.len() == 1 && self.0[0] == b'*'
    }

    /// Returns the length of the composed version of the label.
    pub fn compose_len(&self) -> usize {
        self.len() + 1
    }
}


//--- Compose

impl Compose for Label {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.len() as u8).compose(target)?;
            target.append_slice(self.as_ref())
        })
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.len() as u8).compose(target)?;
            for &ch in self.into_iter() {
                ch.to_ascii_lowercase().compose(target)?;
            }
            Ok(())
        })
    }
}


//--- Deref, DerefMut, AsRef, and AsMut

impl ops::Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl ops::DerefMut for Label {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        unsafe { &*(self as *const Self as *const [u8]) }
    }
}

impl AsMut<[u8]> for Label {
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *(self as *mut Label as *mut [u8]) }
    }
}


//--- ToOwned

#[cfg(feature = "std")]
impl std::borrow::ToOwned for Label {
    type Owned = OwnedLabel;
    
    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}


//--- PartialEq and Eq

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_ascii_case(other)
    }
}

impl Eq for Label { }


//--- PartialOrd and Ord

impl PartialOrd for Label {
    /// Returns an ordering between `self` and `other`.
    ///
    /// The canonical sort order for labels is defined in section 6.1 of
    /// RFC 4034.
    ///
    /// In short, labels are ordered like octet strings except that
    /// the case of ASCII letters is ignored.
    ///
    /// [RFC 4034]: https://tools.ietf.org/html/rfc4034
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.iter().map(u8::to_ascii_lowercase).partial_cmp(
            other.iter().map(u8::to_ascii_lowercase)
        )
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().map(u8::to_ascii_lowercase).cmp(
            other.iter().map(u8::to_ascii_lowercase)
        )
    }
}


//--- Hash

impl hash::Hash for Label {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        // Include the length in the hash so we can simply hash over the
        // labels when building a name’s hash.
        (self.len() as u8).hash(state);
        for c in self.iter() {
            c.to_ascii_lowercase().hash(state)
        }
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a Label {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- Display and Debug

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.iter() {
            if ch == b' ' || ch == b'.' || ch == b'\\' {
                write!(f, "\\{}", ch as char)?;
            }
            else if ch < b' ' || ch >= 0x7F {
                write!(f, "\\{:03}", ch)?;
            }
            else {
                write!(f, "{}", (ch as char))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Label(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}


//------------ OwnedLabel ----------------------------------------------------

/// An owned label.
///
/// Since labels are relatively short, this type doesn’t actually allocate any
/// memory but is a 64 byte array.
//
//  This keeps the label in wire format, so the first octet is the length
//  octet, the remainder is the content.
pub struct OwnedLabel([u8; 64]);

impl OwnedLabel {
    /// Creates a new owned label from an existing label.
    pub fn from_label(label: &Label) -> Self {
        let mut res = [8; 64];
        res[0] = label.len() as u8;
        res[1..=label.len()].copy_from_slice(label.as_slice());
        OwnedLabel(res)
    }

    pub fn make_canonical(&mut self) {
        self.0[1..].make_ascii_lowercase()
    }

    /// Returns a reference to the label.
    pub fn as_label(&self) -> &Label {
        unsafe {
            Label::from_slice_unchecked(&self.0[1..=(self.0[0] as usize)])
        }
    }

    /// Returns a mutable reference to the label.
    pub fn as_label_mut(&mut self) -> &mut Label {
        let len = self.0[0] as usize;
        unsafe {
            Label::from_slice_mut_unchecked(
                &mut self.0[1..=len]
            )
        }
    }

    /// Returns a slice that is the wire-represenation of the label.
    pub fn as_wire_slice(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..=len]
    }
}


//--- From

impl<'a> From<&'a Label> for OwnedLabel {
    fn from(label: &'a Label) -> Self {
        Self::from_label(label)
    }
}


//--- Deref, DerefMut, AsRef, AsMut, Borrow, and BorrowMut

impl ops::Deref for OwnedLabel {
    type Target = Label;

    fn deref(&self) -> &Label {
        self.as_label()
    }
}

impl ops::DerefMut for OwnedLabel {
    fn deref_mut(&mut self) -> &mut Label {
        self.as_label_mut()
    }
}

impl AsRef<Label> for OwnedLabel {
    fn as_ref(&self) -> &Label {
        self.as_label()
    }
}

impl AsRef<[u8]> for OwnedLabel {
    fn as_ref(&self) -> &[u8] {
        self.as_label().as_slice()
    }
}

impl AsMut<Label> for OwnedLabel {
    fn as_mut(&mut self) -> &mut Label {
        self.as_label_mut()
    }
}

impl AsMut<[u8]> for OwnedLabel {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_label_mut().as_slice_mut()
    }
}

impl borrow::Borrow<Label> for OwnedLabel {
    fn borrow(&self) -> &Label {
        self.as_label()
    }
}

impl borrow::BorrowMut<Label> for OwnedLabel {
    fn borrow_mut(&mut self) -> &mut Label {
        self.as_label_mut()
    }
}


//--- PartialEq and Eq

impl<T: AsRef<Label>> PartialEq<T> for OwnedLabel {
    fn eq(&self, other: &T) -> bool {
        self.as_label().eq(other.as_ref())
    }
}

impl Eq for OwnedLabel { }


//--- PartialOrd and Ord

impl<T: AsRef<Label>> PartialOrd<T> for OwnedLabel {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.as_label().partial_cmp(other.as_ref())
    }
}

impl Ord for OwnedLabel {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_label().cmp(other.as_ref())
    }
}


//--- Hash

impl hash::Hash for OwnedLabel {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_label().hash(state)
    }
}


//------------ SliceLabelsIter -----------------------------------------------

pub struct SliceLabelsIter<'a> {
    /// The message slice to work on.
    slice: &'a [u8],

    /// The position in `slice` where the next label start.
    ///
    /// As a life hack, we use `usize::max_value` to fuse the iterator.
    start: usize
}

impl<'a> Iterator for SliceLabelsIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start == usize::max_value() {
            return None
        }
        loop {
            match Label::split_from(&self.slice[self.start..]) {
                Ok((label, _)) => {
                    if label.is_root() {
                        self.start = usize::max_value();
                    }
                    else {
                        self.start += label.compose_len();
                    }
                    return Some(label)
                }
                Err(SplitLabelError::Pointer(pos)) => {
                    let pos = pos as usize;
                    if pos > self.start {
                        // Incidentally, this also covers the case where
                        // pos points past the end of the message.
                        self.start = usize::max_value();
                        return None
                    }
                    self.start = pos;
                    continue;
                }
                Err(_) => {
                    self.start = usize::max_value();
                    return None
                }
            }
        }
    }
}


//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    #[display(fmt="undefined label type")]
    Undefined,

    /// The label was of extended label type given.
    /// 
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    #[display(fmt="unknown extended label 0x{:02x}", _0)]
    Extended(u8),
}

#[cfg(feature = "std")]
impl std::error::Error for LabelTypeError { }


//------------ LongLabelError ------------------------------------------------

/// A label was longer than the allowed 63 bytes.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="long label")]
pub struct LongLabelError;

#[cfg(feature = "std")]
impl std::error::Error for LongLabelError { }


//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from a bytes slice.
#[derive(Clone, Copy, Debug, Display, Eq,  PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    #[display(fmt="compressed domain name")]
    Pointer(u16),

    /// The label type was invalid.
    #[display(fmt="{}", _0)]
    BadType(LabelTypeError),

    /// The bytes slice was too short.
    #[display(fmt="unexpected end of input")]
    ShortBuf,
}

#[cfg(feature = "std")]
impl std::error::Error for SplitLabelError { }

impl From<LabelTypeError> for SplitLabelError {
    fn from(err: LabelTypeError) -> SplitLabelError {
        SplitLabelError::BadType(err)
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use unwrap::unwrap;
    use super::*;

    #[test]
    fn from_slice() {
        let x = [0u8; 10];
        assert_eq!(Label::from_slice(&x[..]).unwrap().as_slice(),
                   &x[..]);
        let x = [0u8; 63];
        assert_eq!(Label::from_slice(&x[..]).unwrap().as_slice(),
                   &x[..]);
        let x = [0u8; 64];
        assert!(Label::from_slice(&x[..]).is_err());
    }

    #[test]
    fn split_from() {
        // regular label
        assert_eq!(Label::split_from(b"\x03www\x07example\x03com\0").unwrap(),
                   (Label::from_slice(b"www").unwrap(),
                    &b"\x07example\x03com\0"[..]));

        // final regular label
        assert_eq!(Label::split_from(b"\x03www").unwrap(),
                   (Label::from_slice(b"www").unwrap(),
                    &b""[..]));

        // root label
        assert_eq!(Label::split_from(b"\0some").unwrap(),
                   (Label::from_slice(b"").unwrap(),
                    &b"some"[..]));

        // short slice
        assert_eq!(Label::split_from(b"\x03ww"),
                   Err(SplitLabelError::ShortBuf));

        // empty slice
        assert_eq!(Label::split_from(b""),
                   Err(SplitLabelError::ShortBuf));

        // compressed label
        assert_eq!(Label::split_from(b"\xc0\x05foo"),
                   Err(SplitLabelError::Pointer(5)));

        // undefined label type
        assert_eq!(Label::split_from(b"\xb3foo"),
                   Err(LabelTypeError::Undefined.into()));

        // extended label type
        assert_eq!(Label::split_from(b"\x66foo"),
                   Err(LabelTypeError::Extended(0x66).into()));
    }

    #[test]
    fn compose() {
        let mut buf = Vec::new();
        unwrap!(Label::root().compose(&mut buf));
        assert_eq!(buf, &b"\0"[..]);

        let mut buf = Vec::new();
        let label = Label::from_slice(b"123").unwrap();
        unwrap!(label.compose(&mut buf));
        assert_eq!(buf, &b"\x03123"[..]);
    }

    #[test]
    fn eq() {
        assert_eq!(Label::from_slice(b"example").unwrap(),
                   Label::from_slice(b"eXAMple").unwrap());
        assert_ne!(Label::from_slice(b"example").unwrap(),
                   Label::from_slice(b"e4ample").unwrap());
    }

    #[test]
    fn cmp() {
        use std::cmp::Ordering;

        let labels = [Label::root(),
                      Label::from_slice(b"\x01").unwrap(),
                      Label::from_slice(b"*").unwrap(),
                      Label::from_slice(b"\xc8").unwrap()];
        for i in 0..labels.len() {
            for j in 0..labels.len() {
                let ord = if i < j { Ordering::Less }
                          else if i == j { Ordering::Equal }
                          else { Ordering::Greater };
                assert_eq!(labels[i].partial_cmp(&labels[j]), Some(ord));
                assert_eq!(labels[i].cmp(&labels[j]), ord);
            }
        }

        let l1 = Label::from_slice(b"example").unwrap();
        let l2 = Label::from_slice(b"eXAMple").unwrap();
        assert_eq!(l1.partial_cmp(&l2), Some(Ordering::Equal));
        assert_eq!(l1.cmp(&l2), Ordering::Equal);
    }

    #[test]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Label::from_slice(b"example").unwrap().hash(&mut s1);
        Label::from_slice(b"eXAMple").unwrap().hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }
}

