//! A domain name that can be both relative or absolute.
//!
//! This is a private module. Its public types are re-exported by the parent.

use super::super::scan::Scanner;
use super::super::wire::ParseError;
use super::absolute::Name;
use super::builder::{BuildError, NameBuilder, ScanError};
use super::chain::{Chain, LongChainError};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::relative::{NameIter, RelativeName};
use super::traits::ToLabelIter;
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::{fmt, hash, str};
use octseq::builder::{FreezeBuilder, IntoBuilder};
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ UncertainName ------------------------------------------------

/// A domain name that may be absolute or relative.
///
/// This type is helpful when reading a domain name from some source where it
/// may end up being absolute or not.
#[derive(Clone)]
pub enum UncertainName<Octets> {
    Absolute(Name<Octets>),
    Relative(RelativeName<Octets>),
}

impl<Octets> UncertainName<Octets> {
    /// Creates a new uncertain domain name from an absolute domain name.
    pub fn absolute(name: Name<Octets>) -> Self {
        UncertainName::Absolute(name)
    }

    /// Creates a new uncertain domain name from a relative domain name.
    pub fn relative(name: RelativeName<Octets>) -> Self {
        UncertainName::Relative(name)
    }

    /// Creates a new uncertain domain name containing the root label only.
    #[must_use]
    pub fn root() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        UncertainName::Absolute(Name::root())
    }

    /// Creates a new uncertain yet empty domain name.
    #[must_use]
    pub fn empty() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        UncertainName::Relative(RelativeName::empty())
    }

    /// Creates a new domain name from its wire format representation.
    ///
    /// The returned name will correctly be identified as an absolute or
    /// relative name.
    pub fn from_octets(octets: Octets) -> Result<Self, UncertainDnameError>
    where
        Octets: AsRef<[u8]>,
    {
        if Self::is_slice_absolute(octets.as_ref())? {
            Ok(UncertainName::Absolute(unsafe {
                Name::from_octets_unchecked(octets)
            }))
        } else {
            Ok(UncertainName::Relative(unsafe {
                RelativeName::from_octets_unchecked(octets)
            }))
        }
    }

    /// Checks an octet slice for a name and returns whether it is absolute.
    fn is_slice_absolute(
        mut slice: &[u8],
    ) -> Result<bool, UncertainDnameError> {
        if slice.len() > Name::MAX_LEN {
            return Err(UncertainDnameErrorEnum::LongName.into());
        }
        loop {
            let (label, tail) = Label::split_from(slice)?;
            if label.is_root() {
                if tail.is_empty() {
                    return Ok(true);
                } else {
                    return Err(UncertainDnameErrorEnum::TrailingData.into());
                }
            }
            if tail.is_empty() {
                return Ok(false);
            }
            slice = tail;
        }
    }

    pub fn scan<S: Scanner<Name = Name<Octets>>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_name().map(UncertainName::Absolute)
    }
}

impl UncertainName<&'static [u8]> {
    /// Creates an empty relative name atop a slice reference.
    #[must_use]
    pub fn empty_ref() -> Self {
        Self::empty()
    }

    /// Creates an absolute name that is the root label atop a slice reference.
    #[must_use]
    pub fn root_ref() -> Self {
        Self::root()
    }
}

#[cfg(feature = "std")]
impl UncertainName<Vec<u8>> {
    /// Creates an empty relative name atop a `Vec<u8>`.
    #[must_use]
    pub fn empty_vec() -> Self {
        Self::empty()
    }

    /// Creates an absolute name from the root label atop a `Vec<u8>`.
    #[must_use]
    pub fn root_vec() -> Self {
        Self::root()
    }
}

#[cfg(feature = "bytes")]
impl UncertainName<Bytes> {
    /// Creates an empty relative name atop a bytes value.
    pub fn empty_bytes() -> Self {
        Self::empty()
    }

    /// Creates an absolute name from the root label atop a bytes value.
    pub fn root_bytes() -> Self {
        Self::root()
    }
}

impl<Octets> UncertainName<Octets> {
    /// Returns whether the name is absolute.
    pub fn is_absolute(&self) -> bool {
        match *self {
            UncertainName::Absolute(_) => true,
            UncertainName::Relative(_) => false,
        }
    }

    /// Returns whether the name is relative.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns a reference to an absolute name, if this name is absolute.
    pub fn as_absolute(&self) -> Option<&Name<Octets>> {
        match *self {
            UncertainName::Absolute(ref name) => Some(name),
            _ => None,
        }
    }

    /// Returns a reference to a relative name, if the name is relative.
    pub fn as_relative(&self) -> Option<&RelativeName<Octets>> {
        match *self {
            UncertainName::Relative(ref name) => Some(name),
            _ => None,
        }
    }

    /// Converts the name into an absolute name.
    ///
    /// If the name is relative, appends the root label to it using
    /// [`RelativeName::into_absolute`].
    pub fn to_absolute(self) -> Result<Name<Octets>, BuildError>
    where
        Octets: AsRef<[u8]> + IntoBuilder,
        Octets::Builder: FreezeBuilder<Octets = Octets>,
    {
        match self {
            UncertainName::Absolute(name) => Ok(name),
            UncertainName::Relative(name) => name.into_absolute(),
        }
    }

    /// Converts the name into an absolute name if it is absolute.
    ///
    /// Otherwise, returns itself as the error.
    pub fn try_into_absolute(self) -> Result<Name<Octets>, Self> {
        if let UncertainName::Absolute(name) = self {
            Ok(name)
        } else {
            Err(self)
        }
    }

    /// Converts the name into a relative name if it is relative.
    ///
    /// Otherwise just returns itself as the error.
    pub fn try_into_relative(self) -> Result<RelativeName<Octets>, Self> {
        if let UncertainName::Relative(name) = self {
            Ok(name)
        } else {
            Err(self)
        }
    }

    /// Returns a reference to the underlying octets sequence.
    pub fn as_octets(&self) -> &Octets {
        match *self {
            UncertainName::Absolute(ref name) => name.as_octets(),
            UncertainName::Relative(ref name) => name.as_octets(),
        }
    }

    /// Returns an octets slice with the raw content of the name.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        match *self {
            UncertainName::Absolute(ref name) => name.as_slice(),
            UncertainName::Relative(ref name) => name.as_slice(),
        }
    }

    /// Makes an uncertain name absolute by chaining on a suffix if needed.
    ///
    /// The method converts the uncertain name into a chain that will
    /// be absolute. If the name is already absolute, the chain will be the
    /// name itself. If it is relative, if will be the concatenation of the
    /// name and `suffix`.
    pub fn chain<S: ToLabelIter>(
        self,
        suffix: S,
    ) -> Result<Chain<Self, S>, LongChainError>
    where
        Octets: AsRef<[u8]>,
    {
        Chain::new_uncertain(self, suffix)
    }
}

//--- From

impl<Octets> From<Name<Octets>> for UncertainName<Octets> {
    fn from(src: Name<Octets>) -> Self {
        UncertainName::Absolute(src)
    }
}

impl<Octets> From<RelativeName<Octets>> for UncertainName<Octets> {
    fn from(src: RelativeName<Octets>) -> Self {
        UncertainName::Relative(src)
    }
}

//--- FromStr

impl<Octets> str::FromStr for UncertainName<Octets>
where
    Octets: for<'a> TryFrom<&'a [u8]>,
{
    type Err = ScanError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.scan_name(name)?;
        builder.as_uncertain().map_err(|_| ScanError::ShortBuf)
    }
}

//--- AsRef

impl<Octs> AsRef<Octs> for UncertainName<Octs> {
    fn as_ref(&self) -> &Octs {
        match *self {
            UncertainName::Absolute(ref name) => name.as_ref(),
            UncertainName::Relative(ref name) => name.as_ref(),
        }
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for UncertainName<Octs> {
    fn as_ref(&self) -> &[u8] {
        match *self {
            UncertainName::Absolute(ref name) => name.as_ref(),
            UncertainName::Relative(ref name) => name.as_ref(),
        }
    }
}

//--- PartialEq, and Eq

impl<Octets, Other> PartialEq<UncertainName<Other>> for UncertainName<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &UncertainName<Other>) -> bool {
        use UncertainName::*;

        match (self, other) {
            (Absolute(l), Absolute(r)) => l.eq(r),
            (Relative(l), Relative(r)) => l.eq(r),
            _ => false,
        }
    }
}

impl<Octets: AsRef<[u8]>> Eq for UncertainName<Octets> {}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for UncertainName<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter_labels() {
            item.hash(state)
        }
    }
}

//--- ToLabelIter

impl<Octs: AsRef<[u8]>> ToLabelIter for UncertainName<Octs> {
    type LabelIter<'a> = NameIter<'a> where Octs: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        match *self {
            UncertainName::Absolute(ref name) => name.iter_labels(),
            UncertainName::Relative(ref name) => name.iter_labels(),
        }
    }

    fn compose_len(&self) -> u16 {
        match *self {
            UncertainName::Absolute(ref name) => name.compose_len(),
            UncertainName::Relative(ref name) => name.compose_len(),
        }
    }
}

//--- IntoIterator

impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a UncertainName<Octets> {
    type Item = &'a Label;
    type IntoIter = NameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_labels()
    }
}

//--- Display and Debug

impl<Octets: AsRef<[u8]>> fmt::Display for UncertainName<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainName::Absolute(ref name) => {
                write!(f, "{}.", name)
            }
            UncertainName::Relative(ref name) => name.fmt(f),
        }
    }
}

impl<Octets: AsRef<[u8]>> fmt::Debug for UncertainName<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UncertainName::Absolute(ref name) => {
                write!(f, "UncertainName::Absolute({})", name)
            }
            UncertainName::Relative(ref name) => {
                write!(f, "UncertainName::Relative({})", name)
            }
        }
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octets> serde::Serialize for UncertainName<Octets>
where
    Octets: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "UncertainName",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "UncertainName",
                &self.as_octets().as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for UncertainName<Octets>
where
    Octets: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]> + DeserializeOctets<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: AsRef<[u8]>
                + for<'a> TryFrom<&'a [u8]>
                + DeserializeOctets<'de>,
        {
            type Value = UncertainName<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a domain name")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                use core::str::FromStr;

                UncertainName::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    UncertainName::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    UncertainName::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: AsRef<[u8]>
                + for<'a> TryFrom<&'a [u8]>
                + DeserializeOctets<'de>,
        {
            type Value = UncertainName<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a domain name")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "UncertainName",
            NewtypeVisitor(PhantomData),
        )
    }
}

//============ Error Types ===================================================

//------------ UncertainDnameError -------------------------------------------

/// A domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UncertainDnameError(UncertainDnameErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UncertainDnameErrorEnum {
    /// The encoding contained an unknown or disallowed label type.
    BadLabel(LabelTypeError),

    /// The encoding contained a compression pointer.
    CompressedName,

    /// The name was longer than 255 octets.
    LongName,

    /// There was more data after the root label was encountered.
    TrailingData,

    /// The input ended in the middle of a label.
    ShortInput,
}

//--- From

impl From<LabelTypeError> for UncertainDnameError {
    fn from(err: LabelTypeError) -> Self {
        Self(UncertainDnameErrorEnum::BadLabel(err))
    }
}

impl From<SplitLabelError> for UncertainDnameError {
    fn from(err: SplitLabelError) -> UncertainDnameError {
        Self(match err {
            SplitLabelError::Pointer(_) => {
                UncertainDnameErrorEnum::CompressedName
            }
            SplitLabelError::BadType(t) => {
                UncertainDnameErrorEnum::BadLabel(t)
            }
            SplitLabelError::ShortInput => {
                UncertainDnameErrorEnum::ShortInput
            }
        })
    }
}

impl From<UncertainDnameErrorEnum> for UncertainDnameError {
    fn from(err: UncertainDnameErrorEnum) -> Self {
        Self(err)
    }
}

//--- Display and Error

impl fmt::Display for UncertainDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            UncertainDnameErrorEnum::BadLabel(ref err) => err.fmt(f),
            UncertainDnameErrorEnum::CompressedName => {
                f.write_str("compressed domain name")
            }
            UncertainDnameErrorEnum::LongName => {
                f.write_str("long domain name")
            }
            UncertainDnameErrorEnum::TrailingData => {
                f.write_str("trailing data")
            }
            UncertainDnameErrorEnum::ShortInput => {
                ParseError::ShortInput.fmt(f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UncertainDnameError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use std::str::FromStr;
    use std::string::String;

    #[test]
    fn from_str() {
        type U = UncertainName<Vec<u8>>;

        fn name(s: &str) -> U {
            U::from_str(s).unwrap()
        }

        assert_eq!(
            name("www.example.com").as_relative().unwrap().as_slice(),
            b"\x03www\x07example\x03com"
        );
        assert_eq!(
            name("www.example.com.").as_absolute().unwrap().as_slice(),
            b"\x03www\x07example\x03com\0"
        );

        assert_eq!(
            name(r"www\.example.com").as_slice(),
            b"\x0bwww.example\x03com"
        );
        assert_eq!(
            name(r"w\119w.example.com").as_slice(),
            b"\x03www\x07example\x03com"
        );
        assert_eq!(
            name(r"w\000w.example.com").as_slice(),
            b"\x03w\0w\x07example\x03com"
        );

        U::from_str(r"w\01").unwrap_err();
        U::from_str(r"w\").unwrap_err();
        U::from_str(r"www..example.com").unwrap_err();
        U::from_str(r"www.example.com..").unwrap_err();
        U::from_str(r".www.example.com").unwrap_err();
        U::from_str(r"www.\[322].example.com").unwrap_err();
        U::from_str(r"www.\2example.com").unwrap_err();
        U::from_str(r"www.\29example.com").unwrap_err();
        U::from_str(r"www.\299example.com").unwrap_err();
        U::from_str(r"www.\892example.com").unwrap_err();
        U::from_str("www.e\0ample.com").unwrap_err();
        U::from_str("www.eüample.com").unwrap_err();

        // LongLabel
        let mut s = String::from("www.");
        for _ in 0..Label::MAX_LEN {
            s.push('x');
        }
        s.push_str(".com");
        assert!(U::from_str(&s).is_ok());
        let mut s = String::from("www.");
        for _ in 0..64 {
            s.push('x');
        }
        s.push_str(".com");
        U::from_str(&s).unwrap_err();

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
        U::from_str(&s1).unwrap_err();
        let mut s1 = s.clone();
        s1.push_str("coma");
        U::from_str(&s1).unwrap_err();
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let abs_name =
            UncertainName::<Vec<u8>>::from_str("www.example.com.").unwrap();
        assert!(abs_name.is_absolute());

        assert_tokens(
            &abs_name.clone().compact(),
            &[
                Token::NewtypeStruct {
                    name: "UncertainName",
                },
                Token::ByteBuf(b"\x03www\x07example\x03com\0"),
            ],
        );
        assert_tokens(
            &abs_name.readable(),
            &[
                Token::NewtypeStruct {
                    name: "UncertainName",
                },
                Token::Str("www.example.com."),
            ],
        );

        let rel_name =
            UncertainName::<Vec<u8>>::from_str("www.example.com").unwrap();
        assert!(rel_name.is_relative());

        assert_tokens(
            &rel_name.clone().compact(),
            &[
                Token::NewtypeStruct {
                    name: "UncertainName",
                },
                Token::ByteBuf(b"\x03www\x07example\x03com"),
            ],
        );
        assert_tokens(
            &rel_name.readable(),
            &[
                Token::NewtypeStruct {
                    name: "UncertainName",
                },
                Token::Str("www.example.com"),
            ],
        );
    }
}
