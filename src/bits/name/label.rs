//! Domain name labels.
//!
//! This is a private module. Its public types are re-exported by the parent
//! module.

use std::{cmp, fmt, hash, ops};
use bytes::BufMut;
use ::bits::compose::Compose;
use ::bits::parse::ShortBuf;


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
            0 ... 0x3F => (head as usize) + 1,
            0x40 ... 0x7F => {
                return Err(
                    SplitLabelError::BadType(LabelTypeError::Extended(head))
                )
            }
            0xC0 ... 0xFF => {
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

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }

    /// Returns a mutable reference to the underlying byte slice.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        self.as_mut()
    }
}

/// # Properties
///
impl Label {
    /// Returns whether the label is the root label.
    pub fn is_root(&self) -> bool {
        self.is_empty()
    }
}


//--- Compose

impl Compose for Label {
    fn compose_len(&self) -> usize {
        self.len() + 1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self.as_ref());
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
    type IntoIter = ::std::slice::Iter<'a, u8>;

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


//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    #[fail(display="undefined label type")]
    Undefined,

    /// The label was of extended label type given.
    /// 
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    #[fail(display="unknown extended label 0x{:02x}", _0)]
    Extended(u8),
}


//------------ LongLabelError ------------------------------------------------

/// A label was longer than the allowed 63 bytes.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="long label")]
pub struct LongLabelError;


//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from a bytes slice.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    #[fail(display="compressed domain name")]
    Pointer(u16),

    /// The label type was invalid.
    #[fail(display="{}", _0)]
    BadType(LabelTypeError),

    /// The bytes slice was too short.
    #[fail(display="unexpected end of input")]
    ShortBuf,
}

impl From<LabelTypeError> for SplitLabelError {
    fn from(err: LabelTypeError) -> SplitLabelError {
        SplitLabelError::BadType(err)
    }
}

impl From<ShortBuf> for SplitLabelError {
    fn from(_: ShortBuf) -> SplitLabelError {
        SplitLabelError::ShortBuf
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
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
        use bytes::BytesMut;

        let mut buf = BytesMut::with_capacity(64);
        assert_eq!(Label::root().compose_len(), 1);
        Label::root().compose(&mut buf);
        assert_eq!(buf.freeze(), &b"\0"[..]);

        let mut buf = BytesMut::with_capacity(64);
        let label = Label::from_slice(b"123").unwrap();
        assert_eq!(label.compose_len(), 4);
        label.compose(&mut buf);
        assert_eq!(buf.freeze(), &b"\x03123"[..]);
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
