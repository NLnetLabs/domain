//! Domain name labels.
//!
//! This is a private module. Its public types are re-exported by the parent
//! module.

use super::super::wire::{FormError, ParseError};
use super::builder::{parse_escape, LabelFromStrError};
use octseq::builder::OctetsBuilder;
use core::str::FromStr;
use core::{borrow, cmp, fmt, hash, ops};

//------------ Label ---------------------------------------------------------

/// An octets slice with the content of a domain name label.
///
/// This is an unsized type wrapping the content of a valid label.
///
/// There are two types of such labels: normal labels and binary labels.
/// Normal labels consist of up to 63 octets of data. Binary labels are a
/// sequence of up to 256 one-bit labels. They have been invented for reverse
/// pointer records for IPv6 but have quickly been found to be rather
/// unwieldy and were never widely implemented. Subsequently they have been
/// declared historic and are forbidden to be supported. So we don’t.
///
/// In theory there can be even more types of labels, but based on the
/// experience with binary labels, it is very unlikely that there ever will
/// be any.
///
/// Consequently, `Label` will only ever contain an octets slice of up to 63
/// octets. It only contains the label’s content, not the length octet it is
/// preceded by in wire format. The type `Deref`s to `[u8]`, providing access
/// to all of an octets slice’s methods. As an unsized type, it needs to be
/// used behind some kind of pointer, most likely a reference.
///
/// `Label` differs from an octets slice in how it compares: as labels are to
/// be case-insensitive, all the comparison traits as well as `Hash` are
/// implemented ignoring ASCII-case.
pub struct Label([u8]);

/// # Creation
///
impl Label {
    /// Creates a label from the underlying slice without any checking.
    ///
    /// # Safety
    ///
    /// The `slice` must be at most 63 octets long.
    pub(super) unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    /// Creates a mutable label from the underlying slice without checking.
    ///
    /// # Safety
    ///
    /// The `slice` must be at most 63 octets long.
    pub(super) unsafe fn from_slice_mut_unchecked(
        slice: &mut [u8],
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

    /// Converts an octets slice into a label.
    ///
    /// This will fail if the slice is longer than 63 octets.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongLabelError> {
        if slice.len() > 63 {
            Err(LongLabelError)
        } else {
            Ok(unsafe { Self::from_slice_unchecked(slice) })
        }
    }

    /// Converts a mutable octets slice into a label.
    ///
    /// This will fail of the slice is longer than 63 octets.
    pub fn from_slice_mut(
        slice: &mut [u8],
    ) -> Result<&mut Self, LongLabelError> {
        if slice.len() > 63 {
            Err(LongLabelError)
        } else {
            Ok(unsafe { Self::from_slice_mut_unchecked(slice) })
        }
    }

    /// Splits a label from the beginning of an octets slice.
    ///
    /// On success, the function returns a label and the remainder of
    /// the slice.
    pub fn split_from(
        slice: &[u8],
    ) -> Result<(&Self, &[u8]), SplitLabelError> {
        let head = match slice.first() {
            Some(ch) => *ch,
            None => return Err(SplitLabelError::ShortInput),
        };
        let end = match head {
            0..=0x3F => (head as usize) + 1,
            0x40..=0x7F => {
                return Err(SplitLabelError::BadType(
                    LabelTypeError::Extended(head),
                ))
            }
            0xC0..=0xFF => {
                let res = match slice.get(1) {
                    Some(ch) => u16::from(*ch),
                    None => return Err(SplitLabelError::ShortInput),
                };
                let res = res | ((u16::from(head) & 0x3F) << 8);
                return Err(SplitLabelError::Pointer(res));
            }
            _ => {
                return Err(SplitLabelError::BadType(
                    LabelTypeError::Undefined,
                ))
            }
        };
        if slice.len() < end {
            return Err(SplitLabelError::ShortInput);
        }
        Ok((
            unsafe { Self::from_slice_unchecked(&slice[1..end]) },
            &slice[end..],
        ))
    }

    /// Iterates over the labels in some part of an octets slice.
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

    /// Returns a reference to the underlying octets slice.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { &*(self as *const Self as *const [u8]) }
    }

    /// Returns a mutable reference to the underlying octets slice.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { &mut *(self as *mut Label as *mut [u8]) }
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
            cmp::Ordering::Equal => {}
            other => return other,
        }
        self.0.cmp(other.as_ref())
    }

    /// Returns the composed ordering with ASCII letters lowercased.
    pub fn lowercase_composed_cmp(&self, other: &Self) -> cmp::Ordering {
        match self.0.len().cmp(&other.0.len()) {
            cmp::Ordering::Equal => {}
            other => return other,
        }
        self.cmp(other)
    }

    /// Appends the label to an octets builder.
    ///
    /// The method builds the encoded form of the label that starts with a
    /// one octet length indicator.
    pub fn compose<Builder: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Builder,
    ) -> Result<(), Builder::AppendError> {
        target.append_slice(&[self.len() as u8])?;
        target.append_slice(self.as_slice())
    }

    /// Appends the lowercased label to an octets builder.
    ///
    /// The method builds the encoded form of the label that starts with a
    /// one octet length indicator. It also converts all ASCII letters into
    /// their lowercase form.
    pub fn compose_canonical<Builder: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Builder,
    ) -> Result<(), Builder::AppendError> {
        target.append_slice(&[self.len() as u8])?;
        for &ch in self.into_iter() {
            target.append_slice(&[ch.to_ascii_lowercase()])?;
        }
        Ok(())
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
    ///
    /// This length is one more than the length of the label as their is a
    /// leading length octet.
    pub fn compose_len(&self) -> u16 {
        u16::try_from(self.len()).expect("long label") + 1
    }
}

//--- Deref, DerefMut, AsRef, and AsMut

impl ops::Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl ops::DerefMut for Label {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsMut<[u8]> for Label {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
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

impl<T: AsRef<[u8]> + ?Sized> PartialEq<T> for Label {
    fn eq(&self, other: &T) -> bool {
        self.eq_ignore_ascii_case(other.as_ref())
    }
}

impl Eq for Label {}

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
        self.iter()
            .map(u8::to_ascii_lowercase)
            .partial_cmp(other.iter().map(u8::to_ascii_lowercase))
    }
}

impl Ord for Label {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter()
            .map(u8::to_ascii_lowercase)
            .cmp(other.iter().map(u8::to_ascii_lowercase))
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
            } else if !(0x20..0x7F).contains(&ch) {
                write!(f, "\\{:03}", ch)?;
            } else {
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
/// memory but is a 64 octet array.
//
//  This keeps the label in wire format, so the first octet is the length
//  octet, the remainder is the content.
#[derive(Clone, Copy)]
pub struct OwnedLabel([u8; 64]);

impl OwnedLabel {
    /// Creates a new owned label from an existing label.
    pub fn from_label(label: &Label) -> Self {
        let mut res = [0; 64];
        res[0] = label.len() as u8;
        res[1..=label.len()].copy_from_slice(label.as_slice());
        OwnedLabel(res)
    }

    /// Creates a label from a sequence of chars.
    pub fn from_chars(
        mut chars: impl Iterator<Item = char>,
    ) -> Result<Self, LabelFromStrError> {
        let mut res = [0; 64];
        while let Some(ch) = chars.next() {
            if res[0] >= 63 {
                return Err(LabelFromStrError::LongLabel);
            }
            let ch = match ch {
                ' '..='-' | '/'..='[' | ']'..='~' => ch as u8,
                '\\' => parse_escape(&mut chars, res[0] > 0)?,
                _ => return Err(LabelFromStrError::IllegalCharacter(ch)),
            };
            res[(res[0] as usize) + 1] = ch;
            res[0] += 1;
        }
        Ok(OwnedLabel(res))
    }

    /// Converts the label into the canonical form.
    ///
    /// This form has all octets representing ASCII letters converted to their
    /// lower case form.
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
        unsafe { Label::from_slice_mut_unchecked(&mut self.0[1..=len]) }
    }

    /// Returns a slice that is the wire-representation of the label.
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

//--- FromStr

impl FromStr for OwnedLabel {
    type Err = LabelFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_chars(s.chars())
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

impl Eq for OwnedLabel {}

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

//--- Display and Debug

impl fmt::Display for OwnedLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_label().fmt(f)
    }
}

impl fmt::Debug for OwnedLabel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("OwnedLabel").field(&self.as_label()).finish()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl serde::Serialize for OwnedLabel {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        use octseq::serde::SerializeOctets;

        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "OwnedLabel",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "OwnedLabel",
                &self.as_label().as_slice().as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for OwnedLabel {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use serde::de::Error;

        struct InnerVisitor;

        impl<'de> serde::de::Visitor<'de> for InnerVisitor {
            type Value = OwnedLabel;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an domain name label")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                OwnedLabel::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                Label::from_slice(value)
                    .map(OwnedLabel::from_label)
                    .map_err(E::custom)
            }
        }

        struct NewtypeVisitor;

        impl<'de> serde::de::Visitor<'de> for NewtypeVisitor {
            type Value = OwnedLabel;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an domain name label")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer.deserialize_str(InnerVisitor)
                } else {
                    deserializer.deserialize_bytes(InnerVisitor)
                }
            }
        }

        deserializer.deserialize_newtype_struct("OwnedLabel", NewtypeVisitor)
    }
}

//------------ SliceLabelsIter -----------------------------------------------

/// An iterator over the labels in an octets slice.
///
/// This keeps returning [`Label`]s until it encounters the root label. If
/// the slice ends before a root label is seen, returns the last label seen
/// and then stops.
///
/// [`Label`]: struct.Label.html
pub struct SliceLabelsIter<'a> {
    /// The message slice to work on.
    slice: &'a [u8],

    /// The position in `slice` where the next label start.
    ///
    /// As a life hack, we use `usize::max_value` to fuse the iterator.
    start: usize,
}

impl<'a> Iterator for SliceLabelsIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start == usize::max_value() {
            return None;
        }
        loop {
            match Label::split_from(&self.slice[self.start..]) {
                Ok((label, _)) => {
                    if label.is_root() {
                        self.start = usize::max_value();
                    } else {
                        self.start += label.len();
                    }
                    return Some(label);
                }
                Err(SplitLabelError::Pointer(pos)) => {
                    let pos = pos as usize;
                    if pos > self.start {
                        // Incidentally, this also covers the case where
                        // pos points past the end of the message.
                        self.start = usize::max_value();
                        return None;
                    }
                    self.start = pos;
                    continue;
                }
                Err(_) => {
                    self.start = usize::max_value();
                    return None;
                }
            }
        }
    }
}

//============ Error Types ===================================================

//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    Undefined,

    /// The label was of the extended label type given.
    ///
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    Extended(u8),
}

//--- Display and Error

impl fmt::Display for LabelTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelTypeError::Undefined => f.write_str("undefined label type"),
            LabelTypeError::Extended(value) => {
                write!(f, "unknown extended label 0x{:02x}", value)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LabelTypeError {}

//------------ LongLabelError ------------------------------------------------

/// A label was longer than the allowed 63 octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongLabelError;

//--- Display and Error

impl fmt::Display for LongLabelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("long label")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongLabelError {}

//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from an octets slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    Pointer(u16),

    /// The label type was invalid.
    BadType(LabelTypeError),

    /// The octets slice was shorter than indicated by the label length.
    ShortInput,
}

//--- From

impl From<LabelTypeError> for SplitLabelError {
    fn from(err: LabelTypeError) -> SplitLabelError {
        SplitLabelError::BadType(err)
    }
}

impl From<SplitLabelError> for ParseError {
    fn from(err: SplitLabelError) -> ParseError {
        match err {
            SplitLabelError::Pointer(_) => {
                ParseError::Form(FormError::new("compressed domain name"))
            }
            SplitLabelError::BadType(_) => {
                ParseError::Form(FormError::new("invalid label type"))
            }
            SplitLabelError::ShortInput => ParseError::ShortInput,
        }
    }
}

//--- Display and Error

impl fmt::Display for SplitLabelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SplitLabelError::Pointer(_) => {
                f.write_str("compressed domain name")
            }
            SplitLabelError::BadType(ltype) => ltype.fmt(f),
            SplitLabelError::ShortInput => ParseError::ShortInput.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SplitLabelError {}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use octseq::builder::infallible;

    #[test]
    fn from_slice() {
        let x = [0u8; 10];
        assert_eq!(Label::from_slice(&x[..]).unwrap().as_slice(), &x[..]);
        let x = [0u8; 63];
        assert_eq!(Label::from_slice(&x[..]).unwrap().as_slice(), &x[..]);
        let x = [0u8; 64];
        assert!(Label::from_slice(&x[..]).is_err());
    }

    #[test]
    fn split_from() {
        // regular label
        assert_eq!(
            Label::split_from(b"\x03www\x07example\x03com\0").unwrap(),
            (
                Label::from_slice(b"www").unwrap(),
                &b"\x07example\x03com\0"[..]
            )
        );

        // final regular label
        assert_eq!(
            Label::split_from(b"\x03www").unwrap(),
            (Label::from_slice(b"www").unwrap(), &b""[..])
        );

        // root label
        assert_eq!(
            Label::split_from(b"\0some").unwrap(),
            (Label::from_slice(b"").unwrap(), &b"some"[..])
        );

        // short slice
        assert_eq!(
            Label::split_from(b"\x03ww"),
            Err(SplitLabelError::ShortInput)
        );

        // empty slice
        assert_eq!(Label::split_from(b""), Err(SplitLabelError::ShortInput));

        // compressed label
        assert_eq!(
            Label::split_from(b"\xc0\x05foo"),
            Err(SplitLabelError::Pointer(5))
        );

        // undefined label type
        assert_eq!(
            Label::split_from(b"\xb3foo"),
            Err(LabelTypeError::Undefined.into())
        );

        // extended label type
        assert_eq!(
            Label::split_from(b"\x66foo"),
            Err(LabelTypeError::Extended(0x66).into())
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn compose() {
        use std::vec::Vec;

        let mut buf = Vec::new();
        infallible(Label::root().compose(&mut buf));
        assert_eq!(buf, &b"\0"[..]);

        let mut buf = Vec::new();
        let label = Label::from_slice(b"123").unwrap();
        infallible(label.compose(&mut buf));
        assert_eq!(buf, &b"\x03123"[..]);
    }

    #[test]
    fn eq() {
        assert_eq!(
            Label::from_slice(b"example").unwrap(),
            Label::from_slice(b"eXAMple").unwrap()
        );
        assert_ne!(
            Label::from_slice(b"example").unwrap(),
            Label::from_slice(b"e4ample").unwrap()
        );
    }

    #[test]
    fn cmp() {
        use core::cmp::Ordering;

        let labels = [
            Label::root(),
            Label::from_slice(b"\x01").unwrap(),
            Label::from_slice(b"*").unwrap(),
            Label::from_slice(b"\xc8").unwrap(),
        ];
        for i in 0..labels.len() {
            for j in 0..labels.len() {
                let ord = i.cmp(&j);
                assert_eq!(labels[i].partial_cmp(labels[j]), Some(ord));
                assert_eq!(labels[i].cmp(labels[j]), ord);
            }
        }

        let l1 = Label::from_slice(b"example").unwrap();
        let l2 = Label::from_slice(b"eXAMple").unwrap();
        assert_eq!(l1.partial_cmp(l2), Some(Ordering::Equal));
        assert_eq!(l1.cmp(l2), Ordering::Equal);
    }

    #[test]
    #[cfg(feature = "std")]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Label::from_slice(b"example").unwrap().hash(&mut s1);
        Label::from_slice(b"eXAMple").unwrap().hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // XXX OwnedLabel::from_str

    #[cfg(feature = "serde")]
    #[test]
    fn owned_label_ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let label =
            OwnedLabel::from_label(Label::from_slice(b"fo.").unwrap());
        assert_tokens(
            &label.compact(),
            &[
                Token::NewtypeStruct { name: "OwnedLabel" },
                Token::BorrowedBytes(b"fo."),
            ],
        );
        assert_tokens(
            &label.readable(),
            &[
                Token::NewtypeStruct { name: "OwnedLabel" },
                Token::Str("fo\\."),
            ],
        );
    }
}
