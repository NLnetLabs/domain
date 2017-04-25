//! Domain name labels.

use std::{borrow, cmp, fmt, hash, mem, ops, str};
use std::borrow::Cow;
use std::ascii::AsciiExt;
use std::ops::Deref;
use super::plain::{DNameBuf, DNameSlice, PushError};


//------------ Label ---------------------------------------------------------

/// An uncompressed domain name label.
///
/// This type wraps the bytes slice of a wire-encoded domain name label. It
/// is only used for labels with their own content, not for ‘pointer labels’
/// used with name compression.
///
/// There are two types of such labels: normal labels and binary labels.
/// Normal labels consist of up to 63 bytes of data. Binary labels are a
/// sequence of up to 256 one-bit labels. They have been invented for reverse
/// pointer records for IPv6 but have quickly been found to be rather
/// unwieldly and were never widely implemented. Subsequently they have been
/// declared historic and shouldn’t really be found in the wild.
///
/// There is room for even more label types, but since experience has shown
/// the introduction of new types to be difficult, their emergence is rather
/// unlikely.
///
/// The main purpose of the `Label` type is to make implementing the other
/// domain name type more easy. It is unlikely that you will have to deal
/// with it too often. If at all, you can use it to get at its content via
/// the [`content()`] method. This method returns a variant of the
/// [`LabelContent`] enum. See its documentation for a discussion of the
/// formatting of the various label types.
///
/// [`content()`]: #method.content
/// [`LabelType`]: enum.LabelType.html
pub struct Label {
    inner: [u8]
}


/// # Creation
///
impl Label {
    /// Creates a label from the underlying bytes without any checking.
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    /// Returns a reference to the root label.
    ///
    /// The root label is an empty normal label. That is, it is the bytes
    /// slice `b"\0"`.
    pub fn root() -> &'static Self {
        unsafe { Self::from_bytes_unsafe(b"\0") }
    }

    /// Splits a label from the beginning of a bytes slice.
    ///
    /// If this succeeds, the functon returns a label and the remainder of
    /// the slice. If it fails for whatever reason, be it because of
    /// illegal values somewhere or because of a short bytes slice, the
    /// function quietly returns `None`.
    pub fn split_from(bytes: &[u8]) -> Option<(&Label, &[u8])> {
        let head = match bytes.get(0) {
            Some(ch) => *ch,
            None => return None
        };
        let len = match head {
            0 ... 0x3F => (head as usize) + 1,
            0x41 => {
                let count = match bytes.get(1) {
                    Some(ch) => *ch,
                    None => return None
                };
                binary_len(count) + 2
            }
            _ => return None
        };
        if bytes.len() < len { return None }
        let (label, tail) = bytes.split_at(len);
        Some((unsafe { Self::from_bytes_unsafe(label) }, tail))
    }

    /// Returns a label from a bytes slice.
    ///
    /// Returns `Some(_)` if the bytes slice contains a correctly encoded,
    /// uncompressed label or `None` otherwise. Also returns `None` if the
    /// label ends short of the entire slice.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Label> {
        match Self::split_from(bytes) {
            Some((label, tail)) => {
                if tail.is_empty() { Some(label) }
                else { None }
            }
            None => None
        }
    }
}


/// # Properties
///
impl Label {
    /// Returns the length of the label.
    ///
    /// This is equal to the length of the wire representation of the label.
    /// For normal labels, it is one more than the length of the content.
    /// For binary labels, things are a wee bit more complicated. See the
    /// discussion of label encodings with the [`LabelContent`] type for
    /// more details.
    ///
    /// [`LabelContent`]: enum.LabelContent.html
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the label is empty.
    ///
    /// (A well-formed label never is.)
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns whether this label is the root label.
    pub fn is_root(&self) -> bool {
        self.inner.len() == 1 && self.inner[0] == 0
    }
}


/// # Working with the Label’s Content
///
impl Label {
    /// Returns the label’s content.
    pub fn content(&self) -> LabelContent {
        match self.inner[0] {
            0 ... 0x3F => LabelContent::Normal(&self.inner[1..]),
            0x41 => LabelContent::Binary(self.inner[1], &self.inner[2..]),
            _ => panic!("illegal label")
        }
    }

    /// Returns a string slice if this is a normal label and purely ASCII.
    ///
    /// To get a string representation of any label, you can use the
    /// `format!()` macro as `Label` implements the `Display` trait.
    pub fn as_str(&self) -> Option<&str> {
        match self.content() {
            LabelContent::Normal(s) => str::from_utf8(s).ok(),
            _ => None
        }
    }

    /// Returns a bytes slice with the raw content of this label.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns an iterator over the labelettes in this label.
    ///
    /// See ['Labelette'] for what labelettes are supposed to be.
    pub fn iter(&self) -> LabelIter {
        LabelIter::new(self)
    }
}


//--- AsRef

impl AsRef<Label> for Label {
    fn as_ref(&self) -> &Self {
        self
    }
}


//--- ToOwned

impl borrow::ToOwned for Label {
    type Owned = LabelBuf;

    fn to_owned(&self) -> Self::Owned {
        self.into()
    }
}


//--- PartialEq and Eq

impl PartialEq for Label {
    /// Tests whether `self` and `other` are equal.
    ///
    /// As per the RFC, normal labels are compared ignoring the case of
    /// ASCII letters.
    fn eq(&self, other: &Self) -> bool {
        match (self.content(), other.content()) {
            (LabelContent::Normal(l), LabelContent::Normal(r)) => {
                l.eq_ignore_ascii_case(r)
            }
            (LabelContent::Binary(lc, ls), LabelContent::Binary(rc, rs)) => {
                // We can skip checking the length of ls and rs given that
                // labels are always well-formed.
                if lc != rc { false }
                else {
                    // Some bits in the last byte are irrelevant and we need
                    // to ignore them.
                    let (ll, ls) = ls.split_last().unwrap();
                    let (rl, rs) = rs.split_last().unwrap();
                    if ls != rs { false }
                    else {
                        match lc & 0x7 {
                            0 => ll == rl,
                            c => {
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

impl<T: AsRef<Label>> PartialEq<T> for Label {
    fn eq(&self, other: &T) -> bool {
        self.eq(other.as_ref())
    }
}

impl PartialEq<[u8]> for Label {
    fn eq(&self, other: &[u8]) -> bool {
        match self.content() {
            LabelContent::Normal(bytes) => {
                bytes.eq_ignore_ascii_case(other)
            }
            _ => false
        }
    }
}

impl Eq for Label { }


//--- PartialOrd and Ord
//
// Note: There is no implementation for PartialOrd and Ord since ordering
//       happens on the level of labeletts.


//--- Hash

impl hash::Hash for Label {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match self.content() {
            LabelContent::Normal(bytes) => {
                state.write_u8(0);
                for ch in bytes {
                    state.write_u8(ch.to_ascii_lowercase())
                }
            }
            LabelContent::Binary(count, slice) => {
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


//--- IntoIterator

impl<'a> IntoIterator for &'a Label {
    type Item = Labelette<'a>;
    type IntoIter = LabelIter<'a>;
    
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- Display and Debug

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.content(), f)
    }
}

impl fmt::Octal for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Octal::fmt(&self.content(), f)
    }
}

impl fmt::LowerHex for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.content(), f)
    }
}

impl fmt::UpperHex for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.content(), f)
    }
}

impl fmt::Binary for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(&self.content(), f)
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("Label("));
        try!(fmt::Display::fmt(self, f));
        f.write_str(")")
    }
}


//------------ LabelBuf ------------------------------------------------------

/// An owned domain name label.
/// 
/// This type is the owned companion of and derefs to [`Label`].
pub struct LabelBuf {
    inner: Vec<u8>
}


impl LabelBuf {
    /// Creates an owned label from the underlying vec without checking.
    unsafe fn from_vec_unsafe(vec: Vec<u8>) -> Self {
        LabelBuf{inner: vec}
    }

    /// Creates an owned label from a label slice.
    ///
    /// `LabelBuf` also implements `From<&Label>`, so the canonical form of
    /// this function is actually `label.into()`.
    pub fn from_slice(label: &Label) -> Self {
        unsafe { Self::from_vec_unsafe(label.inner.into()) }
    }

    /// Returns an owned root label.
    pub fn root() -> Self {
        Label::root().into()
    }

    /// Returns a reference to a slice of the label.
    pub fn as_slice(&self) -> &Label {
        unsafe { Label::from_bytes_unsafe(&self.inner) }
    }
}


//--- From

impl<'a> From<&'a Label> for LabelBuf {
    fn from(label: &'a Label) -> Self {
        Self::from_slice(label)
    }
}


//--- Deref, Borrow, and AsRef

impl ops::Deref for LabelBuf {
    type Target = Label;

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl borrow::Borrow<Label> for LabelBuf {
    fn borrow(&self) -> &Label {
        self
    }
}

impl AsRef<Label> for LabelBuf {
    fn as_ref(&self) -> &Label {
        self
    }
}


//--- PartialEq and Eq

impl<T: AsRef<Label>> PartialEq<T> for LabelBuf {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl Eq for LabelBuf { }


//--- Hash

impl hash::Hash for LabelBuf {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- std::fmt traits

impl fmt::Display for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.deref(), f)
    }
}

impl fmt::Octal for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Octal::fmt(self.deref(), f)
    }
}

impl fmt::LowerHex for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(self.deref(), f)
    }
}

impl fmt::UpperHex for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.deref(), f)
    }
}

impl fmt::Binary for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Binary::fmt(self.deref(), f)
    }
}

impl fmt::Debug for LabelBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self.deref(), f)
    }
}


//------------ LabelIter -----------------------------------------------------

/// An iterator over the labelettes in a label.
///
/// See ['Labelette'] for what labelettes are supposed to be.
#[derive(Clone, Debug)]
pub struct LabelIter<'a>(LabelIterInner<'a>);

#[derive(Clone, Debug)]
enum LabelIterInner<'a> {
    Normal(Option<&'a [u8]>),
    Binary(BinaryLabelIter<'a>),
}

impl<'a> LabelIter<'a> {
    /// Creates a new iterator for a label.
    fn new(label: &'a Label) -> Self {
        match label.content() {
            LabelContent::Normal(bytes) => {
                LabelIter(LabelIterInner::Normal(Some(bytes)))
            }
            LabelContent::Binary(count, bits) => {
                LabelIter(LabelIterInner::Binary(BinaryLabelIter::new(count,
                                                                      bits)))
            }
        }
    }

    /// Returns whether the label under the iterator is a normal label.
    pub fn is_normal(&self) -> bool {
        match self.0 {
            LabelIterInner::Normal(_) => true,
            LabelIterInner::Binary(_) => false
        }
    }

    /// Returns a domain name with the remaining content of the iterator.
    ///
    /// If the iterator is a normal label that hasn’t been consumed yet,
    /// returns `Some(Cow::Borrowed(_))`. If the iterator is for a binary
    /// label that hasn’t been consumed yet completely, `Some(Cow::Owned(_))`.
    /// If the iterator has been consumed completely, returns `None`.
    pub fn to_name(&self) -> Option<Cow<'a, DNameSlice>> {
        match self.0 {
            LabelIterInner::Normal(None) => None,
            LabelIterInner::Normal(Some(bytes)) => {
                Some(Cow::Borrowed(
                        unsafe { DNameSlice::from_bytes_unsafe(bytes)}))
            }
            LabelIterInner::Binary(ref binary) => binary.to_name()
        }
    }

    /// Pushes a label with the remaining content to an owned domain name.
    pub fn push_name(&self, name: &mut DNameBuf) -> Result<(), PushError> {
        match self.0 {
            LabelIterInner::Normal(None) => Ok(()),
            LabelIterInner::Normal(Some(bytes)) => name.push_normal(bytes),
            LabelIterInner::Binary(ref binary) => binary.push_name(name)
        }
    }
}


impl<'a> Iterator for LabelIter<'a> {
    type Item = Labelette<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.0 {
            LabelIterInner::Normal(ref mut slice) => {
                slice.take().map(Labelette::Normal)
            }
            LabelIterInner::Binary(ref mut inner) => inner.next(),
        }
    }
}

impl<'a> DoubleEndedIterator for LabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.0 {
            LabelIterInner::Normal(ref mut slice) => {
                slice.take().map(Labelette::Normal)
            }
            LabelIterInner::Binary(ref mut inner) => inner.next_back()
        }
    }
}


//------------ BinaryLabelIter -----------------------------------------------

/// An iterator over the labeletts in a binary label.
///
/// The order of one-bit labels is reversed. That is, the most-significant
/// bit in the first byte is the right-most label. Since our iterators track
/// labels left to right (as is the way normal labels are arranged in a
/// domain name), the `Iterator` implementation walks backwards and
/// `DoubleEndedIterator` forwards.
#[derive(Clone, Debug)]
struct BinaryLabelIter<'a> {
    /// The bytes of the binary label.
    bits: &'a [u8],

    /// The bit returned by the next call to `next_back()`.
    front: usize,

    /// The bit returned by the last call to `next()`.
    back: usize
}

impl<'a> BinaryLabelIter<'a> {
    fn new(count: u8, bits: &'a [u8]) -> Self {
        BinaryLabelIter {
            bits: bits,
            front: 0,
            back: if count == 0 { 256 }
                  else { count as usize }
        }
    }

    fn get_bit(&self, bit: usize) -> Labelette<'a> {
        Labelette::Bit(self.bits[bit >> 3] & (0x80 >> (bit & 7)) != 0)
    }

    fn to_name(&self) -> Option<Cow<'a, DNameSlice>> {
        if self.front == self.back {
            return None
        }
        let mut res = DNameBuf::new();
        self.push_name(&mut res).unwrap();
        Some(Cow::Owned(res))
    }

    fn push_name(&self, name: &mut DNameBuf) -> Result<(), PushError> {
        if self.front != self.back {
            return Ok(())
        }
        let mut bits = match name.push_empty_binary(self.back - self.front) {
            Ok(Some(bits)) => bits,
            Ok(None) => return Ok(()),
            Err(err) => return Err(err)
        };
        for (i, j) in (self.front .. self.back)
                        .zip(0 .. (self.back - self.front)) {
            if let Labelette::Bit(true) = self.get_bit(i) {
                bits[j >> 3] |= 0x80 >> (j & 7);
            }
            else {
                bits[j >> 3] &= !bits[j >> 3] | (0x80 >> (j & 7));
            }
        }
        Ok(())
    }
}

impl<'a> Iterator for BinaryLabelIter<'a> {
    type Item = Labelette<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            None
        }
        else {
            self.back -= 1;
            Some(self.get_bit(self.back))
        }
    }
}

impl<'a> DoubleEndedIterator for BinaryLabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            None
        }
        else {
            let res = self.get_bit(self.front);
            self.front += 1;
            Some(res)
        }
    }
}


//------------ LabelContent -------------------------------------------------

/// The contents of a label.
///
/// There are two types of labels with content currently in use: termed
/// normal labels and binary labels herein. The type of a label is
/// determined by the first octet of the label’s wire representation.
///
/// Originally, [RFC 1035] decreed that the label type shall encoded in this
/// octet’s two most-significant bits. `0b00` was to mean a normal label
/// and `0b11` was to indicate the pointer of a compressed domain name.
/// Since that left only two more types, [RFC 2671] declared `0b01` to
/// signal an *extended label type* with the rest of the first octet
/// stating which label type exactly. [RFC 2673] used this mechanism to
/// define binary labels as type `0x41`.
///
/// However, because domain names are such a fundamental part of the DNS,
/// it turned out that adding a new label type resulted in all sorts of
/// compatibility issues. It was thus decided with [RFC 6891] to abandon
/// this experiment and deprecate binary labels.
///
/// The `LabelContent` type still has two variants for normal and binary
/// labels. Because it is an enum, creation of values cannot be regulated
/// which means that any value of this type not directly acquired through
/// a call to `Label::content()` may contain invalid data. Despite that,
/// the implementations of the various `std::fmt` traits provided by this
/// type happily assume correctly encoded data and will panic.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 2671]: https://tools.ietf.org/html/rfc2671
/// [RFC 2673]: https://tools.ietf.org/html/rfc2673
/// [RFC 6891]: https://tools.ietf.org/html/rfc6891
pub enum LabelContent<'a> {
    /// A normal label.
    ///
    /// Normal labels consist of up to 63 octets of data. While [RFC 1034]
    /// proposes to limit the octets to ASCII letters, digits, and hyphens,
    /// no hard restriction exists and all values are allowed.
    ///
    /// When encoded, normal labels start with a one-octet value containing
    /// the number of octets in the label’s content followed by that
    /// content. Because the label type in the most-significant bits of that
    /// first octet is `0b00`, the value of the octet really is length and
    /// no masking is required.
    /// 
    /// [RFC 1034]: https://tools.ietf.org/html/rfc1034
    Normal(&'a [u8]),

    /// A binary label, also called a bit-string label.
    ///
    /// Binary labels contains a sequence of one-bit labels. The bits in the
    /// label are treated each as a label of its own. The intention was to
    /// provide a way to express arbitrary binary data in DNS allowing
    /// zone cuts at any point in the data. This was supposed to make
    /// the zone delgation for reverse pointers in IPv6 easier and more
    /// flexible.
    ///
    /// The content of a binary label consists of one octet giving the number
    /// of bits in the label. The value of zero indicates 256 bits in order
    /// to make empty labels impossible. This octet is followed by the
    /// smallest number of octets necessary to contain that many bits with
    /// excess bits set to zero.
    ///
    /// Confusingly, the bits are arranged in reverse order. The
    /// most-significant bit (bit 7 of the first octet) contains the
    /// right-most label in customary label order. However, two consecutive
    /// binary labels are arranged as normal.
    ///
    /// This variant contains the number of bits in its first element and
    /// a bytes slice of the bits in its second element. The bit count is
    /// kept as is, ie., `0` still means 256 bits.
    Binary(u8, &'a[u8])
}


impl<'a> LabelContent<'a> {
    /// Formats a normal label.
    ///
    /// This is here because normal labels don’t depend on the format
    /// specifier.
    fn fmt_normal(bytes: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in bytes {
            if ch == b' ' || ch == b'.' || ch == b'\\' {
                try!(write!(f, "\\{}", ch as char));
            }
            else if ch < b' '  || ch >= 0x7F {
                try!(write!(f, "\\{:03}", ch));
            }
            else {
                try!(write!(f, "{}", (ch as char)));
            }
        }
        Ok(())
    }
}

// Note: LabelContent doesn’t get implementations for PartialEq, etc. since
//       it is a public enum and users can create all sorts of malformed
//       values which makes comparisions somewhat difficult to define
//       clearly.


//--- std::fmt traits

impl<'a> fmt::Display for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(b) => LabelContent::fmt_normal(b, f),
            LabelContent::Binary(count, bits) => {
                if count <= 32 {
                    try!(write!(f, "\\[{}.{}.{}.{}",
                                bits[0],
                                bits.get(1).map_or(0, |&c| c),
                                bits.get(2).map_or(0, |&c| c),
                                bits.get(3).map_or(0, |&c| c),
                                ));
                    if count != 32 {
                        try!(write!(f, "/{}", count));
                    }
                    write!(f, "]")
                }
                else {
                    write!(f, "{:x}", self)
                }
            }
        }
    }
}

impl<'a> fmt::Octal for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(b) => LabelContent::fmt_normal(b, f),
            LabelContent::Binary(count, bits) => {
                try!(write!(f, "\\[o"));
                for octet in bits {
                    try!(write!(f, "{:o}", octet));
                }
                write!(f, "/{}]", count)
            }
        }
    }
}

impl<'a> fmt::LowerHex for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(b) => LabelContent::fmt_normal(b, f),
            LabelContent::Binary(count, bits) => {
                try!(write!(f, "\\[x"));
                for octet in bits {
                    try!(write!(f, "{:x}", octet));
                }
                write!(f, "/{}]", count)
            }
        }
    }
}

impl<'a> fmt::UpperHex for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(b) => LabelContent::fmt_normal(b, f),
            LabelContent::Binary(count, bits) => {
                try!(write!(f, "\\[x"));
                for octet in bits {
                    try!(write!(f, "{:X}", octet));
                }
                write!(f, "/{}]", count)
            }
        }
    }
}

impl<'a> fmt::Binary for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(b) => LabelContent::fmt_normal(b, f),
            LabelContent::Binary(count, bits) => {
                try!(write!(f, "\\[b"));
                for item in BinaryLabelIter::new(count, bits) {
                    match item {
                        Labelette::Bit(false) => try!(write!(f, "0")),
                        Labelette::Bit(true) => try!(write!(f, "1")),
                        _ => unreachable!()
                    }
                }
                write!(f, "]")
            }
        }
    }
}

impl<'a> fmt::Debug for LabelContent<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelContent::Normal(..) => {
                try!(f.write_str("LabelContent::Normal("));
                try!(fmt::Display::fmt(self, f));
                f.write_str(")")
            }
            LabelContent::Binary(count, slice) => {
                try!(f.write_str("LabelContent::Binary("));
                try!(count.fmt(f));
                try!(f.write_str(","));
                try!(fmt::Debug::fmt(slice, f));
                f.write_str(")")
            }
        }
    }
}


//------------ Labelette ----------------------------------------------------

/// A labelette is an atomic label.
///
/// Various operations on domain names such as comparisons or ordering are
/// done label by label. However, [binary labels] are actually a sequence of
/// labels themselves. Worse, a binary label within a name can actually be
/// broken up into several binary labels with the same overall number of bits
/// while still retaining the same domain name. All these operations need to
/// consider the individual bits labels of a binary label.
///
/// In order to disperse the confusion of having labels inside labels, we
/// invented the term *labelette* exclusively for this crate to mean either
/// a normal label or one single bit-label of a binary label.
///
/// You get labelettes by iterating over [`Label`]s. For a normal label, this
/// iterator will return exactly once with a `Normal` variant. For binary
/// labels, the iterator will return once for each bit label with the `Bit`
/// variant.
///
/// [binary labels]: enum.LabelContent.html#variant.Binary
/// [`Label`]: struct.Label.html
pub enum Labelette<'a> {
    /// A labelette for a normal label.
    Normal(&'a [u8]),

    /// A labelette for a single bit-label of a binary label.
    Bit(bool)
}


impl<'a> Labelette<'a> {
    /// Returns whether the labelette is the root label.
    pub fn is_root(&self) -> bool {
        if let Labelette::Normal(bytes) = *self {
            bytes.is_empty()
        }
        else {
            false
        }
    }
}


//--- PartialEq and Eq

impl<'a> PartialEq for Labelette<'a> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (&Labelette::Normal(l), &Labelette::Normal(r)) => {
                l.eq_ignore_ascii_case(r)
            }
            (&Labelette::Bit(l), &Labelette::Bit(r)) => l == r,
            _ => false
        }
    }
}

impl<'a> Eq for Labelette<'a> { }


//--- PartialOrd and Ord

impl<'a> PartialOrd for Labelette<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a> Ord for Labelette<'a> {
    /// Returns the ordering between `self` and `other`.
    ///
    /// The canonical sort order for labels is defined in section 6.1 of
    /// RFC 4034, that for binary labels in section 3.3 of RFC 2673.
    ///
    /// In short, normal labels are ordered like octet strings except that
    /// the case of ASCII letters is ignored. Bit labels sort before
    /// normal labels and `false` sorts before `true`.
    ///
    /// [RFC 4034]: https://tools.ietf.org/html/rfc4034
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match (self, other) {
            (&Labelette::Normal(l), &Labelette::Normal(r)) => {
                l.iter().map(u8::to_ascii_lowercase).cmp(
                    r.iter().map(u8::to_ascii_lowercase))
            }
            (&Labelette::Normal(_), &Labelette::Bit(_)) => {
                cmp::Ordering::Greater
            }
            (&Labelette::Bit(_), &Labelette::Normal(_)) => {
                cmp::Ordering::Less
            }
            (&Labelette::Bit(l), &Labelette::Bit(r)) => {
                l.cmp(&r)
            }
        }
    }
}


//--- Hash

impl<'a> hash::Hash for Labelette<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match *self {
            Labelette::Bit(false) => {
                state.write_u8(0);
            }
            Labelette::Bit(true) => {
                state.write_u8(1);
            }
            Labelette::Normal(slice) => {
                state.write_u8(2);
                state.write(slice)
            }
        }
    }
}


//--- Debug

impl<'a> fmt::Debug for Labelette<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Labelette::Normal(slice) => {
                try!(f.write_str("Labelette::Normal("));
                try!(LabelContent::Normal(slice).fmt(f));
                f.write_str(")")
            }
            Labelette::Bit(bit) => {
                try!(f.write_str("Labelette::Bit("));
                try!(bit.fmt(f));
                f.write_str(")")
            }
        }
    }
}


//------------ Helper Functions ---------------------------------------------

/// Returns the bit label length for a binary label with `count` bits.
fn binary_len(count: u8) -> usize {
    if count == 0 { 32 }
    else { ((count - 1) / 8 + 1) as usize }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn binary_iter() {
        let (label, tail) = Label::split_from(b"\x41\x0e\xd0\x74").unwrap();
        assert!(tail.is_empty());
        let bits = label.iter().map(|l| {
            match l {
                Labelette::Bit(false) => b'0',
                Labelette::Bit(true) => b'1',
                _ => panic!("got normal labelette")
            }
        }).collect::<Vec<_>>();
        assert_eq!(bits, b"10111000001011");
        let bits = label.iter().rev().map(|l| {
            match l {
                Labelette::Bit(false) => b'0',
                Labelette::Bit(true) => b'1',
                _ => panic!("got normal labelette")
            }
        }).collect::<Vec<_>>();
        assert_eq!(bits, b"11010000011101");
    }

}
