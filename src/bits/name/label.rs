//! Domain name labels.

use std::ascii::AsciiExt;
use std::cmp;
use std::fmt;
use std::hash;
use std::mem;
use std::str;


//------------ Label ---------------------------------------------------------

/// An uncompressed domain name label.
pub struct Label {
    inner: [u8]
}


/// Creation
///
impl Label {
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    /// Returns a reference to the root label.
    pub fn root() -> &'static Self {
        unsafe { Self::from_bytes_unsafe(b"\0") }
    }

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
    /// This is equal to the length of the wire representation of the label
    /// if it weren’t compressed. For normal labels, it is one more than the
    /// length of the content. For binary labels, things are a wee bit more
    /// complicated.
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


//------------ LabelIter -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct LabelIter<'a>(LabelIterInner<'a>);

#[derive(Clone, Debug)]
enum LabelIterInner<'a> {
    Normal(Option<&'a [u8]>),
    Binary(BinaryLabelIter<'a>),
}

impl<'a> LabelIter<'a> {
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
/// Note: The implementations of the various `std::fmt` traits will panic
/// for illegal values.
pub enum LabelContent<'a> {
    Normal(&'a [u8]),
    Binary(u8, &'a[u8])
}


impl<'a> LabelContent<'a> {
    fn fmt_normal(bytes: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in bytes {
            if ch == b' ' || ch == b'.' || ch == b'\\' {
                try!(write!(f, "\\{}", ch));
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
                                bits[0], bits[1], bits[2], bits[3]));
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

/// A labelette is the smallest possible label.
///
/// A normal label is a labelette all by itself. A binary label is a sequence
/// of bit labeletts.
///
/// Note that this term was invented wholesale for this crate and is not
/// official DNS terminology.
pub enum Labelette<'a> {
    Normal(&'a [u8]),
    Bit(bool)
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
