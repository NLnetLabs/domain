//! Domain name labels.

use std::{cmp, error, fmt, hash, mem, ops};
use std::ascii::AsciiExt;
use bytes::BufMut;
use ::bits::compose::Composable;


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
/// bytes. The type derefs to `[u8]`, providing access to all of a byte
/// slice’s methods. As an usized type, it needs to be used behind some kind
/// of pointer, most likely a reference.
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
        mem::transmute(slice)
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
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LabelError> {
        if slice.len() > 63 {
            Err(LabelError)
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
            None => return Err(SplitLabelError::ShortSlice)
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
                    Some(ch) => *ch as u16,
                    None => return Err(SplitLabelError::ShortSlice)
                };
                let res = res | (((head as u16) & 0x3F) << 8);
                return Err(SplitLabelError::Pointer(res))
            }
            _ => {
                return Err(
                    SplitLabelError::BadType(LabelTypeError::Undefined)
                )
            }
        };
        if slice.len() < end {
            return Err(SplitLabelError::ShortSlice)
        }
        Ok((unsafe { Self::from_slice_unchecked(&slice[1..end]) },
            &slice[end..]))
    }

    /// Returns whether the label is the root label.
    pub fn is_root(&self) -> bool {
        self.is_empty()
    }
}


//--- Composable

impl Composable for Label {
    fn compose_len(&self) -> usize {
        self.len() + 1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self.as_ref());
    }
}


//--- Deref and AsRef

impl ops::Deref for Label {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        unsafe { mem::transmute(self) }
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


//------------ LabelError ----------------------------------------------------

/// An error happend while creating a label.
///
/// This can only mean that the underlying byte slice was too long.
#[derive(Clone, Copy, Debug)]
pub struct LabelError;


//------------ LabelTypeError ------------------------------------------------

/// A bad label type was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelTypeError {
    /// The label was of the undefined type `0b10`.
    Undefined,

    /// The label was of extended label type given.
    /// 
    /// The type value will be in the range `0x40` to `0x7F`, that is, it
    /// includes the original label type bits `0b01`.
    Extended(u8),
}

impl error::Error for LabelTypeError {
    fn description(&self) -> &str {
        use self::LabelTypeError::*;

        match *self {
            Undefined => "undefined label type",
            Extended(0x41) => "binary label",
            Extended(_) => "unknown extended label type",
        }
    }
}

impl fmt::Display for LabelTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LabelTypeError::*;

        match *self {
            Undefined => f.write_str("undefined label type"),
            Extended(0x41) => f.write_str("binary label"),
            Extended(t) => write!(f, "extended label type 0x{:x}", t),
        }
    }
}


//------------ SplitLabelError -----------------------------------------------

/// An error happened while splitting a label from a bytes slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SplitLabelError {
    /// The label was a pointer to the given position.
    Pointer(u16),

    /// The label type was invalid.
    BadType(LabelTypeError),

    /// The bytes slice was too short.
    ShortSlice,
}

impl error::Error for SplitLabelError {
    fn description(&self) -> &str {
        use self::SplitLabelError::*;
        
        match *self {
            Pointer(_) => "compressed domain name",
            BadType(ref err) => err.description(),
            ShortSlice => "short domain name",
        }
    }
}

impl fmt::Display for SplitLabelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(::std::error::Error::description(self))
    }
}

