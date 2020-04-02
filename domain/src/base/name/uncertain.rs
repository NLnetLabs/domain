//! A domain name that can be both relative or absolute.
//!
//! This is a private module. Its public types are re-exported by the parent.

use core::{fmt, hash, str};
#[cfg(feature = "std")] use std::vec::Vec;
#[cfg(feature = "bytes")] use bytes::Bytes;
#[cfg(feature = "master")] use bytes::BytesMut;
#[cfg(feature="master")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError
};
use super::super::octets::{
    Compose, EmptyBuilder, FromBuilder, IntoBuilder, IntoOctets,
    OctetsBuilder, ShortBuf
};
#[cfg(feature = "master")] use super::super::str::Symbol;
use super::builder::{DnameBuilder, FromStrError, PushError};
use super::chain::{Chain, LongChainError};
use super::dname::Dname;
use super::label::Label;
use super::relative::{DnameIter, RelativeDname};
use super::traits::{ToEitherDname, ToLabelIter};


//------------ UncertainDname ------------------------------------------------

/// A domain name that may be absolute or relative.
///
/// This type is helpful when reading a domain name from some source where it
/// may end up being absolute or not.
#[derive(Clone)]
pub enum UncertainDname<Octets> {
    Absolute(Dname<Octets>),
    Relative(RelativeDname<Octets>),
}

impl<Octets> UncertainDname<Octets> {
    /// Creates a new uncertain domain name from an absolute domain name.
    pub fn absolute(name: Dname<Octets>) -> Self {
        UncertainDname::Absolute(name)
    }

    /// Creates a new uncertain domain name from a relative domain name.
    pub fn relative(name: RelativeDname<Octets>) -> Self {
        UncertainDname::Relative(name)
    }

    /// Creates a new uncertain domain name containing the root label only.
    pub fn root() -> Self
    where Octets: From<&'static [u8]> {
        UncertainDname::Absolute(Dname::root())
    }

    /// Creates a new uncertain yet empty domain name.
    pub fn empty() -> Self
    where Octets: From<&'static [u8]> {
        UncertainDname::Relative(RelativeDname::empty())
    }

    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// If the last character is a dot, the name will be absolute, otherwise
    /// it will be relative.
    ///
    /// If you have a string, you can also use the `FromStr` trait, which
    /// really does the same thing.
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
        C: IntoIterator<Item=char>
    {
        let mut builder =
            DnameBuilder::<<Octets as FromBuilder>::Builder>::new();
        builder.append_chars(chars)?;
        if builder.in_label() || builder.is_empty() {
            Ok(builder.finish().into())
        }
        else {
            Ok(builder.into_dname()?.into())
        }
    }
}


impl UncertainDname<&'static [u8]> {
    /// Creates an empty relative name atop a slice reference.
    pub fn empty_ref() -> Self {
        Self::empty()
    }

    /// Creates an absolute name that is the root label atop a slice reference.
    pub fn root_ref() -> Self {
        Self::root()
    }
}

#[cfg(feature = "std")]
impl UncertainDname<Vec<u8>> {
    /// Creates an empty relative name atop a `Vec<u8>`.
    pub fn empty_vec() -> Self {
        Self::empty()
    }

    /// Creates an absolute name from the root label atop a `Vec<u8>`.
    pub fn root_vec() -> Self {
        Self::root()
    }
}

#[cfg(feature="bytes")] 
impl UncertainDname<Bytes> {
    /// Creates an empty relative name atop a bytes value.
    pub fn empty_bytes() -> Self {
        Self::empty()
    }

    /// Creates an absolute name from the root label atop a bytes value.
    pub fn root_bytes() -> Self {
        Self::root()
    }
}

impl<Octets> UncertainDname<Octets> {
    /// Returns whether the name is absolute.
    pub fn is_absolute(&self) -> bool {
        match *self {
            UncertainDname::Absolute(_) => true,
            UncertainDname::Relative(_) => false,
        }
    }

    /// Returns whether the name is relative.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns a reference to an absolute name, if this name is absolute.
    pub fn as_absolute(&self) -> Option<&Dname<Octets>> {
        match *self {
            UncertainDname::Absolute(ref name) => Some(name),
            _ => None
        }
    }

    /// Returns a reference to a relative name, if the name is relative.
    pub fn as_relative(&self) -> Option<&RelativeDname<Octets>> {
        match *self {
            UncertainDname::Relative(ref name) => Some(name),
            _ => None,
        }
    }

    /// Converts the name into an absolute name.
    ///
    /// If the name is relative, appends the root label to it using
    /// [`RelativeDname::into_absolute`].
    ///
    /// [`RelativeDname::into_absolute`]:
    ///     struct.RelativeDname.html#method.into_absolute
    pub fn into_absolute(
        self
    ) -> Result<
        Dname<<<Octets as IntoBuilder>::Builder as IntoOctets>::Octets>,
        PushError
    >
    where
        Octets: AsRef<[u8]> + IntoBuilder,
        <Octets as IntoBuilder>::Builder: IntoOctets<Octets = Octets>,
    {
        match self {
            UncertainDname::Absolute(name) => Ok(name),
            UncertainDname::Relative(name) => name.into_absolute()
        }
    }

    /// Converts the name into an absolute name if it is absolute.
    ///
    /// Otherwise, returns itself as the error.
    pub fn try_into_absolute(self) -> Result<Dname<Octets>, Self> {
        if let UncertainDname::Absolute(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }

    /// Converts the name into a relative name if it is relative.
    ///
    /// Otherwise just returns itself as the error.
    pub fn try_into_relative(self) -> Result<RelativeDname<Octets>, Self> {
        if let UncertainDname::Relative(name) = self {
            Ok(name)
        }
        else {
            Err(self)
        }
    }

    /// Returns a reference to the underlying octets sequence.
    pub fn as_octets(&self) -> &Octets {
        match *self {
            UncertainDname::Absolute(ref name) => name.as_octets(),
            UncertainDname::Relative(ref name) => name.as_octets()
        }
    }

    /// Returns an octets slice with the raw content of the name.
    pub fn as_slice(&self) -> &[u8]
    where Octets: AsRef<[u8]> {
        match *self {
            UncertainDname::Absolute(ref name) => name.as_slice(),
            UncertainDname::Relative(ref name) => name.as_slice(),
        }
    }

    /// Makes an uncertain name absolute by chaining on a suffix if needed.
    ///
    /// The method converts the uncertain name into a chain that will
    /// be absolute. If the name is already absolute, the chain will be the
    /// name itself. If it is relative, if will be the concatenation of the
    /// name and `suffix`.
    pub fn chain<S: ToEitherDname>(
        self,
        suffix: S
    ) -> Result<Chain<Self, S>, LongChainError>
    where Octets: AsRef<[u8]> {
        Chain::new_uncertain(self, suffix)
    }
}


//--- From

impl<Octets> From<Dname<Octets>> for UncertainDname<Octets> {
    fn from(src: Dname<Octets>) -> Self {
        UncertainDname::Absolute(src)
    }
}

impl<Octets> From<RelativeDname<Octets>> for UncertainDname<Octets> {
    fn from(src: RelativeDname<Octets>) -> Self {
        UncertainDname::Relative(src)
    }
}


//--- FromStr

impl<Octets> str::FromStr for UncertainDname<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: EmptyBuilder,
{
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_chars(s.chars())
    }
}


//--- AsRef

impl<Octets: AsRef<T>, T> AsRef<T> for UncertainDname<Octets> {
    fn as_ref(&self) -> &T {
        match *self {
            UncertainDname::Absolute(ref name) => name.as_ref(),
            UncertainDname::Relative(ref name) => name.as_ref(),
        }
    }
}


//--- PartialEq, and Eq

impl<Octets, Other> PartialEq<UncertainDname<Other>>
for UncertainDname<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &UncertainDname<Other>) -> bool {
        use UncertainDname::*;

        match (self, other) {
            (&Absolute(ref l), &Absolute(ref r)) => l.eq(r),
            (&Relative(ref l), &Relative(ref r)) => l.eq(r),
            _ => false
        }
    }
}

impl<Octets: AsRef<[u8]>> Eq for UncertainDname<Octets> { }


//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for UncertainDname<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter_labels() {
            item.hash(state)
        }
    }
}


//--- ToLabelIter

impl<'a, Octets: AsRef<[u8]>> ToLabelIter<'a> for UncertainDname<Octets>  {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        match *self {
            UncertainDname::Absolute(ref name) => name.iter_labels(),
            UncertainDname::Relative(ref name) => name.iter_labels(),
        }
    }
}


//--- IntoIterator

impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a UncertainDname<Octets> {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_labels()
    }
}


//--- Compose

impl<Octets: AsRef<[u8]>> Compose for UncertainDname<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        match *self {
            UncertainDname::Absolute(ref name) => name.compose(target),
            UncertainDname::Relative(ref name) => name.compose(target),
        }
    }
    
    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        match *self {
            UncertainDname::Absolute(ref name) => {
                name.compose_canonical(target)
            }
            UncertainDname::Relative(ref name) => {
                name.compose_canonical(target)
            }
        }
    }
}


//--- Scan

#[cfg(feature="master")]
impl Scan for UncertainDname<Bytes> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        if let Ok(()) = scanner.skip_literal(".") {
            return Ok(UncertainDname::root())
        }
        scanner.scan_word(
            DnameBuilder::<BytesMut>::new(),
            |name, symbol| {
                match symbol {
                    Symbol::Char('.') => {
                        if name.in_label() {
                            name.end_label();
                        }
                        else {
                            return Err(FromStrError::EmptyLabel.into())
                        }
                    }
                    Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                        if ch.is_ascii() {
                            if let Err(err) = name.push(ch as u8) {
                                return Err(FromStrError::from(err).into())
                            }
                        }
                        else {
                            return Err(FromStrError::IllegalCharacter(ch)
                                                    .into())
                        }
                    }
                    Symbol::DecimalEscape(ch) => {
                        if let Err(err) = name.push(ch) {
                            return Err(FromStrError::from(err).into())
                        }
                    }
                }
                Ok(())
            },
            |name| {
                if name.in_label() || name.is_empty() {
                    Ok(UncertainDname::from(name.finish()))
                }
                else {
                    Ok(UncertainDname::from(name.into_dname().unwrap()))
                }
            }
        )
    }
}


//--- Display and Debug

impl<Octets: AsRef<[u8]>> fmt::Display for UncertainDname<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => name.fmt(f),
            UncertainDname::Relative(ref name) => name.fmt(f),
        }
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for UncertainDname<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainDname::Absolute(ref name) => {
                write!(f, "UncertainDname::Absolute({})", name)
            }
            UncertainDname::Relative(ref name) => {
                write!(f, "UncertainDname::Relative({})", name)
            }
        }
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use std::string::String;
    use super::*;

    #[test]
    fn from_str() {
        use std::str::FromStr;

        type U = UncertainDname<Vec<u8>>;

        fn name(s: &str) -> U {
            U::from_str(s).unwrap()
        }

        assert_eq!(name("www.example.com").as_relative().unwrap().as_slice(),
                   b"\x03www\x07example\x03com");
        assert_eq!(name("www.example.com.").as_absolute().unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");

        assert_eq!(name(r"www\.example.com").as_slice(),
                   b"\x0bwww.example\x03com");
        assert_eq!(name(r"w\119w.example.com").as_slice(),
                   b"\x03www\x07example\x03com");
        assert_eq!(name(r"w\000w.example.com").as_slice(),
                   b"\x03w\0w\x07example\x03com");

        assert_eq!(U::from_str(r"w\01"),
                   Err(FromStrError::UnexpectedEnd));
        assert_eq!(U::from_str(r"w\"),
                   Err(FromStrError::UnexpectedEnd));
        assert_eq!(U::from_str(r"www..example.com"),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(U::from_str(r"www.example.com.."),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(U::from_str(r".www.example.com"),
                   Err(FromStrError::EmptyLabel));
        assert_eq!(U::from_str(r"www.\[322].example.com"),
                   Err(FromStrError::BinaryLabel));
        assert_eq!(U::from_str(r"www.\2example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(U::from_str(r"www.\29example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(U::from_str(r"www.\299example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(U::from_str(r"www.\892example.com"),
                   Err(FromStrError::IllegalEscape));
        assert_eq!(U::from_str("www.e\0ample.com"),
                   Err(FromStrError::IllegalCharacter('\0')));
        assert_eq!(U::from_str("www.eüample.com"),
                   Err(FromStrError::IllegalCharacter('ü')));

        // LongLabel
        let mut s = String::from("www.");
        for _ in 0..63 {
            s.push('x');
        }
        s.push_str(".com");
        assert!(U::from_str(&s).is_ok());
        let mut s = String::from("www.");
        for _ in 0..64 {
            s.push('x');
        }
        s.push_str(".com");
        assert_eq!(U::from_str(&s),
                   Err(FromStrError::LongLabel));

        // Long Name
        let mut s = String::new();
        for _ in 0..50 {
            s.push_str("four.");
        }
        let mut s1 = s.clone();
        s1.push_str("com.");
        assert_eq!(name(&s1).as_slice().len(), 255);
        let mut s1 = s.clone();
        s1.push_str("com");
        assert_eq!(name(&s1).as_slice().len(), 254);
        let mut s1 = s.clone();
        s1.push_str("coma.");
        assert_eq!(U::from_str(&s1), Err(FromStrError::LongName));
        let mut s1 = s.clone();
        s1.push_str("coma");
        assert_eq!(U::from_str(&s1), Err(FromStrError::LongName));
    }
}

