// XXX For transitioning to octseq, we re-export the relevant types here.
//     If all looks nice, we drop the re-exports again and clean up.

pub use octseq::{
    EmptyBuilder, FromBuilder, IntoBuilder, Octets, OctetsBuilder,
    OctetsFrom, OctetsInto, Parser, ShortBuf, ShortInput, Truncate,
};
pub use super::wire::{
    Compose, Composer, FormError, Parse, ParseError
};
#[cfg(feature = "serde")]
pub use octseq::serde::{DeserializeOctets, SerializeOctets};

/*
use super::name::ToDname;
use super::net::{Ipv4Addr, Ipv6Addr};
#[cfg(feature = "bytes")]
use bytes::{Bytes, BytesMut};
use core::cmp::Ordering;
use core::convert::TryFrom;
use core::{borrow, fmt, hash};
#[cfg(feature = "smallvec")]
use smallvec::{Array, SmallVec};
#[cfg(feature = "std")]
use std::borrow::Cow;
#[cfg(feature = "std")]
use std::mem;
#[cfg(feature = "std")]
use std::vec::Vec;

//============ Octets and Octet Builders =====================================

//------------ OctetsBuilder -------------------------------------------------

/// A buffer to construct an octet sequence.
///
/// Octet builders represent a buffer of space available for building an
/// octets sequence by appending the contents of octet slices. The buffers
/// may consist of a predefined amount of space or grow as needed.
///
/// The trait does not require octet builder to provide access to the already
/// assembled data. However, implementations are likely to do so, anyway, via
/// implementations of `AsRef<[u8]>` and `AsMut<[u8]>`. If access becomes
/// necessary when using an octets builder, simply add these as extra trait
/// bounds.
pub trait OctetsBuilder: Sized {
    /// The type of the octets the builder can be converted into.
    ///
    /// If `Octets` implements [`IntoBuilder`], the `Builder` associated
    /// type of that trait must be `Self`.
    ///
    /// [`IntoBuilder`]: trait.IntoBuilder.html
    type Octets;

    /// Appends the content of a slice to the builder.
    ///
    /// If there isn’t enough space available for appending the slice,
    /// returns an error and leaves the builder alone.
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf>;

    /// Truncates the builder back to a length of `len` octets.
    fn truncate(&mut self, len: usize);

    /// Converts the builder into immutable octets.
    fn freeze(self) -> Self::Octets;

    /// Returns the length of the already assembled data.
    fn len(&self) -> usize;

    /// Returns whether the builder is currently empty.
    fn is_empty(&self) -> bool;

    /// Appends all data or nothing.
    ///
    /// The method executes the provided closure that presumably will try to
    /// append data to the builder and propagates an error from the builder.
    /// If the closure returns with an error, the builder is truncated back
    /// to the length from before the closure was executed.
    ///
    /// Note that upon an error the builder is _only_ truncated. If the
    /// closure modified any already present data via `AsMut<[u8]>`, these
    /// modification will survive.
    fn append_all<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where
        F: FnOnce(&mut Self) -> Result<(), ShortBuf>,
    {
        let pos = self.len();
        match op(self) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.truncate(pos);
                Err(ShortBuf)
            }
        }
    }

    /// Appends a domain name using name compression if supported.
    ///
    /// Domain name compression attempts to lower the size of a DNS message
    /// by avoiding to include repeated domain name suffixes. Instead of
    /// adding the full suffix, a pointer to the location of the previous
    /// occurence is added. Since that occurence may itself contain a
    /// compressed suffix, doing name compression isn’t cheap and therefore
    /// optional. However, in order to be able to opt in, we need to know
    /// if we are dealing with a domain name that ought to be compressed.
    ///
    /// The trait provides a default implementation which simply appends the
    /// name uncompressed.
    fn append_compressed_dname<N: ToDname>(
        &mut self,
        name: &N,
    ) -> Result<(), ShortBuf> {
        if let Some(slice) = name.as_flat_slice() {
            self.append_slice(slice)
        } else {
            self.append_all(|target| {
                for label in name.iter_labels() {
                    label.build(target)?;
                }
                Ok(())
            })
        }
    }

    /// Prepends some appended data with its length as a `u16`.
    ///
    /// The method will append the data being added via the closure `op` to
    /// the builder prepended with a 16 bit unsigned value of its length.
    ///
    /// The implementation will prepend a `0u16` before executing the closure
    /// and update it to the number of octets added afterwards. If the
    /// closure adds more than 65535 octets or if any appending fails, the
    /// builder will be truncated to its previous length.
    fn u16_len_prefixed<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where
        Self: AsMut<[u8]>,
        F: FnOnce(&mut Self) -> Result<(), ShortBuf>,
    {
        let pos = self.len();
        self.append_slice(&[0; 2])?;
        match op(self) {
            Ok(_) => {
                let len = self.len() - pos - 2;
                if len > usize::from(u16::max_value()) {
                    self.truncate(pos);
                    Err(ShortBuf)
                } else {
                    self.as_mut()[pos..pos + 2]
                        .copy_from_slice(&(len as u16).to_be_bytes());
                    Ok(())
                }
            }
            Err(_) => {
                self.truncate(pos);
                Err(ShortBuf)
            }
        }
    }
}

impl<'a, T: OctetsBuilder<Octets = T>> OctetsBuilder for &'a mut T {
    type Octets = &'a mut T;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        (*self).append_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        (*self).truncate(len)
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        OctetsBuilder::len(*self)
    }

    fn is_empty(&self) -> bool {
        OctetsBuilder::is_empty(*self)
    }
}

#[cfg(feature = "std")]
impl OctetsBuilder for Vec<u8> {
    type Octets = Self;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len)
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}

#[cfg(feature = "std")]
impl<'a> OctetsBuilder for Cow<'a, [u8]> {
    type Octets = Self;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        if let Cow::Owned(ref mut vec) = *self {
            vec.extend_from_slice(slice);
        } else {
            let mut vec = mem::replace(self, Cow::Borrowed(b"")).into_owned();
            vec.extend_from_slice(slice);
            *self = Cow::Owned(vec);
        }
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        match *self {
            Cow::Owned(ref mut vec) => vec.truncate(len),
            Cow::Borrowed(ref mut slice) => {
                if len < slice.len() {
                    *slice = &slice[..len]
                }
            }
        }
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

#[cfg(feature = "bytes")]
impl OctetsBuilder for BytesMut {
    type Octets = Bytes;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len)
    }

    fn freeze(self) -> Self::Octets {
        self.freeze()
    }

    fn len(&self) -> usize {
        Self::len(self)
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> OctetsBuilder for SmallVec<A> {
    type Octets = Self;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        SmallVec::truncate(self, len)
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        Self::len(self)
    }

    fn is_empty(&self) -> bool {
        Self::is_empty(self)
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> OctetsBuilder for heapless::Vec<u8, N> {
    type Octets = Self;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice).map_err(|_| ShortBuf)
    }

    fn truncate(&mut self, len: usize) {
        heapless::Vec::truncate(self, len)
    }

    fn freeze(self) -> Self::Octets {
        self
    }

    fn len(&self) -> usize {
        self.as_slice().len()
    }

    fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

//------------ EmptyBuilder --------------------------------------------------

/// An octets builder that can be newly created empty.
pub trait EmptyBuilder {
    /// Creates a new empty octets builder with a default size.
    fn empty() -> Self;

    /// Creates a new empty octets builder with a suggested initial size.
    ///
    /// The builder may or may not use the size provided by `capacity` as the
    /// initial size of the buffer. It may very well be possibly that the
    /// builder is never able to grow to this capacity at all. Therefore,
    /// even if you create a builder for your data size via this function,
    /// appending may still fail.
    fn with_capacity(capacity: usize) -> Self;
}

#[cfg(feature = "std")]
impl EmptyBuilder for Vec<u8> {
    fn empty() -> Self {
        Vec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        Vec::with_capacity(capacity)
    }
}

#[cfg(feature = "bytes")]
impl EmptyBuilder for BytesMut {
    fn empty() -> Self {
        BytesMut::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        BytesMut::with_capacity(capacity)
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> EmptyBuilder for SmallVec<A> {
    fn empty() -> Self {
        SmallVec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        SmallVec::with_capacity(capacity)
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> EmptyBuilder for heapless::Vec<u8, N> {
    fn empty() -> Self {
        heapless::Vec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity <= N);
        heapless::Vec::new()
    }
}

//------------ IntoBuilder ---------------------------------------------------

/// An octets type that can be converted into an octets builder.
pub trait IntoBuilder {
    /// The type of octets builder this octets type can be converted into.
    type Builder: OctetsBuilder;

    /// Converts an octets value into an octets builder.
    fn into_builder(self) -> Self::Builder;
}

#[cfg(feature = "std")]
impl IntoBuilder for Vec<u8> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}

#[cfg(feature = "std")]
impl<'a> IntoBuilder for &'a [u8] {
    type Builder = Vec<u8>;

    fn into_builder(self) -> Self::Builder {
        self.into()
    }
}

#[cfg(feature = "std")]
impl<'a> IntoBuilder for Cow<'a, [u8]> {
    type Builder = Vec<u8>;

    fn into_builder(self) -> Self::Builder {
        self.into_owned()
    }
}

#[cfg(feature = "bytes")]
impl IntoBuilder for Bytes {
    type Builder = BytesMut;

    fn into_builder(self) -> Self::Builder {
        // XXX Currently, we need to copy to do this. If bytes gains a way
        //     to convert from Bytes to BytesMut for non-shared data without
        //     copying, we should change this.
        BytesMut::from(self.as_ref())
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> IntoBuilder for SmallVec<A> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> IntoBuilder for heapless::Vec<u8, N> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}

//------------ FromBuilder ---------------------------------------------------

/// An octets type that can be created from an octets builder.
pub trait FromBuilder: AsRef<[u8]> + Sized {
    /// The type of builder this octets type can be created from.
    type Builder: OctetsBuilder<Octets = Self>;

    /// Creates an octets value from an octets builder.
    fn from_builder(builder: Self::Builder) -> Self;
}

#[cfg(feature = "std")]
impl FromBuilder for Vec<u8> {
    type Builder = Self;

    fn from_builder(builder: Self::Builder) -> Self {
        builder
    }
}

#[cfg(feature = "bytes")]
impl FromBuilder for Bytes {
    type Builder = BytesMut;

    fn from_builder(builder: Self::Builder) -> Self {
        builder.freeze()
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> FromBuilder for SmallVec<A> {
    type Builder = Self;

    fn from_builder(builder: Self::Builder) -> Self {
        builder
    }
}

#[cfg(feature = "heapless")]
impl<const N: usize> FromBuilder for heapless::Vec<u8, N> {
    type Builder = Self;

    fn from_builder(builder: Self::Builder) -> Self {
        builder
    }
}

//============ Serialization =================================================

#[cfg(feature = "serde")]
pub use self::serde::*;

#[cfg(feature = "serde")]
mod serde {
    use core::fmt;
    use core::marker::PhantomData;
    use serde::de::Visitor;

    //------------ SerializeOctets -------------------------------------------

    pub trait SerializeOctets {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error>;

        fn as_serialized_octets(&self) -> AsSerializedOctets<Self> {
            AsSerializedOctets(self)
        }
    }

    impl<'a> SerializeOctets for &'a [u8] {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self)
        }
    }

    #[cfg(feature = "std")]
    impl<'a> SerializeOctets for std::borrow::Cow<'a, [u8]> {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_ref())
        }
    }

    #[cfg(feature = "std")]
    impl SerializeOctets for std::vec::Vec<u8> {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_ref())
        }
    }

    #[cfg(feature = "bytes")]
    impl SerializeOctets for bytes::Bytes {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_ref())
        }
    }

    #[cfg(feature = "smallvec")]
    impl<A> SerializeOctets for smallvec::SmallVec<A>
    where
        A: smallvec::Array<Item = u8>,
    {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_ref())
        }
    }

    #[cfg(feature = "heapless")]
    impl<const N: usize> SerializeOctets for heapless::Vec<u8, N> {
        fn serialize_octets<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(self.as_ref())
        }
    }

    //------------ AsSerializedOctets ----------------------------------------

    /// A wrapper forcing a value to serialize through its octets.
    ///
    /// This type can be used where a `Serialize` value is required.
    pub struct AsSerializedOctets<'a, T: ?Sized>(&'a T);

    impl<'a, T: SerializeOctets> serde::Serialize for AsSerializedOctets<'a, T> {
        fn serialize<S: serde::Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            self.0.serialize_octets(serializer)
        }
    }

    //------------ DeserializeOctets -----------------------------------------

    pub trait DeserializeOctets<'de>: Sized {
        type Visitor: Visitor<'de, Value = Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error>;

        fn deserialize_with_visitor<
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        >(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>;

        fn visitor() -> Self::Visitor;
    }

    impl<'de> DeserializeOctets<'de> for &'de [u8] {
        type Visitor = BorrowedVisitor<Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_bytes(visitor)
        }

        fn visitor() -> Self::Visitor {
            BorrowedVisitor::new()
        }
    }

    #[cfg(feature = "std")]
    impl<'de> DeserializeOctets<'de> for std::borrow::Cow<'de, [u8]> {
        type Visitor = BorrowedVisitor<Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_bytes(visitor)
        }

        fn visitor() -> Self::Visitor {
            BorrowedVisitor::new()
        }
    }

    #[cfg(feature = "std")]
    impl<'de> DeserializeOctets<'de> for std::vec::Vec<u8> {
        type Visitor = BufVisitor<Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_byte_buf(visitor)
        }

        fn visitor() -> Self::Visitor {
            BufVisitor::new()
        }
    }

    #[cfg(feature = "bytes")]
    impl<'de> DeserializeOctets<'de> for bytes::Bytes {
        type Visitor = BufVisitor<Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_byte_buf(visitor)
        }

        fn visitor() -> Self::Visitor {
            BufVisitor::new()
        }
    }

    #[cfg(feature = "smallvec")]
    impl<'de, A> DeserializeOctets<'de> for smallvec::SmallVec<A>
    where
        A: smallvec::Array<Item = u8>,
    {
        type Visitor = BufVisitor<Self>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_byte_buf(visitor)
        }

        fn visitor() -> Self::Visitor {
            BufVisitor::new()
        }
    }

    #[cfg(feature = "heapless")]
    impl<'de, const N: usize> DeserializeOctets<'de> for heapless::Vec<u8, N> {
        type Visitor = HeaplessVecVisitor<N>;

        fn deserialize_octets<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            Self::visitor().deserialize(deserializer)
        }

        fn deserialize_with_visitor<D, V>(
            deserializer: D,
            visitor: V,
        ) -> Result<V::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
            V: serde::de::Visitor<'de>,
        {
            deserializer.deserialize_byte_buf(visitor)
        }

        fn visitor() -> Self::Visitor {
            HeaplessVecVisitor::new()
        }
    }

    //------------ BorrowedVisitor -------------------------------------------

    pub struct BorrowedVisitor<T>(PhantomData<T>);

    impl<T> BorrowedVisitor<T> {
        fn new() -> Self {
            BorrowedVisitor(PhantomData)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<T, D::Error>
        where
            T: From<&'de [u8]>,
        {
            deserializer.deserialize_bytes(self)
        }
    }

    impl<'de, T> serde::de::Visitor<'de> for BorrowedVisitor<T>
    where
        T: From<&'de [u8]>,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an octet sequence")
        }

        fn visit_borrowed_bytes<E: serde::de::Error>(
            self,
            value: &'de [u8],
        ) -> Result<Self::Value, E> {
            Ok(value.into())
        }
    }

    //------------ BufVisitor ------------------------------------------------

    #[cfg(feature = "std")]
    pub struct BufVisitor<T>(PhantomData<T>);

    #[cfg(feature = "std")]
    impl<T> BufVisitor<T> {
        fn new() -> Self {
            BufVisitor(PhantomData)
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<T, D::Error>
        where
            T: From<std::vec::Vec<u8>>,
        {
            deserializer.deserialize_byte_buf(self)
        }
    }

    #[cfg(feature = "std")]
    impl<'de, T> serde::de::Visitor<'de> for BufVisitor<T>
    where
        T: From<std::vec::Vec<u8>>,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an octet sequence")
        }

        fn visit_borrowed_bytes<E: serde::de::Error>(
            self,
            value: &'de [u8],
        ) -> Result<Self::Value, E> {
            Ok(std::vec::Vec::from(value).into())
        }

        fn visit_byte_buf<E: serde::de::Error>(
            self,
            value: std::vec::Vec<u8>,
        ) -> Result<Self::Value, E> {
            Ok(value.into())
        }
    }

    #[cfg(feature = "heapless")]
    pub struct HeaplessVecVisitor<const N: usize>;

    #[cfg(feature = "heapless")]
    impl<const N: usize> HeaplessVecVisitor<N> {
        fn new() -> Self {
            Self
        }

        pub fn deserialize<'de, D: serde::Deserializer<'de>>(
            self,
            deserializer: D,
        ) -> Result<heapless::Vec<u8, N>, D::Error> {
            deserializer.deserialize_byte_buf(self)
        }
    }

    #[cfg(feature = "heapless")]
    impl<'de, const N: usize> serde::de::Visitor<'de> for HeaplessVecVisitor<N> {
        type Value = heapless::Vec<u8, N>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_fmt(format_args!(
                "an octet sequence of length {} of shorter",
                N
            ))
        }

        fn visit_bytes<E: serde::de::Error>(
            self,
            value: &[u8],
        ) -> Result<Self::Value, E> {
            if value.len() > N {
                return Err(E::invalid_length(value.len(), &self));
            }

            Ok(heapless::Vec::from_iter(value.iter().copied()))
        }
    }
}

//============ Parsing =======================================================

//------------ Parser --------------------------------------------------------

/// A parser for sequentially extracting data from an octets sequence.
///
/// The parser wraps an [octets reference] and remembers the read position on
/// the referenced sequence. Methods allow reading out data and progressing
/// the position beyond processed data.
///
/// [octets reference]: trait.OctetsRef.html
#[derive(Clone, Copy, Debug)]
pub struct Parser<Ref> {
    /// The underlying octets reference.
    octets: Ref,

    /// The current position of the parser from the beginning of `octets`.
    pos: usize,

    /// The length of the octets sequence.
    ///
    /// This starts out as the length of the underlying sequence and is kept
    /// here to be able to temporarily limit the allowed length for
    /// `parse_blocks`.
    len: usize,
}

impl<Ref> Parser<Ref> {
    /// Creates a new parser atop a reference to an octet sequence.
    pub fn from_ref(octets: Ref) -> Self
    where
        Ref: AsRef<[u8]>,
    {
        Parser {
            pos: 0,
            len: octets.as_ref().len(),
            octets,
        }
    }

    /// Returns the wrapped reference to the underlying octets sequence.
    pub fn octets_ref(&self) -> Ref
    where
        Ref: Copy,
    {
        self.octets
    }

    /// Returns the current parse position as an index into the octets.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the length of the underlying octet sequence.
    ///
    /// This is _not_ the number of octets left for parsing. Use
    /// [`remaining`] for that.
    ///
    /// [`remaining`]: #method.remaining
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the underlying octets sequence is empty.
    ///
    /// This does _not_ return whether there are no more octets left to parse.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Parser<&'static [u8]> {
    /// Creates a new parser atop a static byte slice.
    ///
    /// This function is most useful for testing.
    pub fn from_static(slice: &'static [u8]) -> Self {
        Self::from_ref(slice)
    }
}

impl<Ref: AsRef<[u8]>> Parser<Ref> {
    /// Returns an octets slice of the underlying sequence.
    ///
    /// The slice covers the entire sequence, not just the remaining data. You
    /// can use [`peek`] for that.
    ///
    /// [`peek`]: #method.peek
    pub fn as_slice(&self) -> &[u8] {
        &self.octets.as_ref()[..self.len]
    }

    /// Returns a mutable octets slice of the underlying sequence.
    ///
    /// The slice covers the entire sequence, not just the remaining data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Ref: AsMut<[u8]>,
    {
        &mut self.octets.as_mut()[..self.len]
    }

    /// Returns the number of remaining octets to parse.
    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Returns a slice for the next `len` octets.
    ///
    /// If less than `len` octets are left, returns an error.
    pub fn peek(&self, len: usize) -> Result<&[u8], ParseError> {
        self.check_len(len)?;
        Ok(&self.peek_all()[..len])
    }

    /// Returns a slice of the data left to parse.
    pub fn peek_all(&self) -> &[u8] {
        &self.octets.as_ref()[self.pos..]
    }

    /// Repositions the parser to the given index.
    ///
    /// It is okay to reposition anywhere within the sequence. However,
    /// if `pos` is larger than the length of the sequence, an error is
    /// returned.
    pub fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.len {
            Err(ParseError::ShortInput)
        } else {
            self.pos = pos;
            Ok(())
        }
    }

    /// Advances the parser‘s position by `len` octets.
    ///
    /// If this would take the parser beyond its end, an error is returned.
    pub fn advance(&mut self, len: usize) -> Result<(), ParseError> {
        if len > self.remaining() {
            Err(ParseError::ShortInput)
        } else {
            self.pos += len;
            Ok(())
        }
    }

    /// Advances to the end of the parser.
    pub fn advance_to_end(&mut self) {
        self.pos = self.len
    }

    /// Checks that there are `len` octets left to parse.
    ///
    /// If there aren’t, returns an error.
    pub fn check_len(&self, len: usize) -> Result<(), ParseError> {
        if self.remaining() < len {
            Err(ParseError::ShortInput)
        } else {
            Ok(())
        }
    }
}

impl<Ref: AsRef<[u8]>> Parser<Ref> {
    /// Takes and returns the next `len` octets.
    ///
    /// Advances the parser by `len` octets. If there aren’t enough octets
    /// left, leaves the parser untouched and returns an error instead.
    pub fn parse_octets(
        &mut self,
        len: usize,
    ) -> Result<Ref::Range, ParseError>
    where
        Ref: OctetsRef,
    {
        let end = self.pos + len;
        if end > self.len {
            return Err(ParseError::ShortInput);
        }
        let res = self.octets.range(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    /// Fills the provided buffer by taking octets from the parser.
    ///
    /// Copies as many octets as the buffer is long from the parser into the
    /// buffer and advances the parser by that many octets.
    ///
    /// If there aren’t enough octets left in the parser to fill the buffer
    /// completely, returns an error and leaves the parser untouched.
    pub fn parse_buf(&mut self, buf: &mut [u8]) -> Result<(), ParseError> {
        let pos = self.pos;
        self.advance(buf.len())?;
        buf.copy_from_slice(&self.octets.as_ref()[pos..self.pos]);
        Ok(())
    }

    /// Takes an `i8` from the beginning of the parser.
    ///
    /// Advances the parser by one octet. If there aren’t enough octets left,
    /// leaves the parser untouched and returns an error instead.
    pub fn parse_i8(&mut self) -> Result<i8, ParseError> {
        let res = self.peek(1)?[0] as i8;
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `u8` from the beginning of the parser.
    ///
    /// Advances the parser by one octet. If there aren’t enough octets left,
    /// leaves the parser untouched and returns an error instead.
    pub fn parse_u8(&mut self) -> Result<u8, ParseError> {
        let res = self.peek(1)?[0];
        self.pos += 1;
        Ok(res)
    }

    /// Takes an `i16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two octets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_i16(&mut self) -> Result<i16, ParseError> {
        let mut res = [0; 2];
        self.parse_buf(&mut res)?;
        Ok(i16::from_be_bytes(res))
    }

    /// Takes a `u16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two ocetets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_u16(&mut self) -> Result<u16, ParseError> {
        let mut res = [0; 2];
        self.parse_buf(&mut res)?;
        Ok(u16::from_be_bytes(res))
    }

    /// Takes an `i32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four octets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_i32(&mut self) -> Result<i32, ParseError> {
        let mut res = [0; 4];
        self.parse_buf(&mut res)?;
        Ok(i32::from_be_bytes(res))
    }

    /// Takes a `u32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four octets. If
    /// there aren’t enough octets left, leaves the parser untouched and
    /// returns an error instead.
    pub fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let mut res = [0; 4];
        self.parse_buf(&mut res)?;
        Ok(u32::from_be_bytes(res))
    }

    /// Parses a given amount of octets through a closure.
    ///
    /// Parses a block of `limit` octets and moves the parser to the end of
    /// that block or, if less than `limit` octets are still available, to
    /// the end of the parser.
    ///
    /// The closure `op` will be allowed to parse up to `limit` octets. If it
    /// does so successfully or returns with a form error, the method returns
    /// its return value. If it returns with a short buffer error, the method
    /// returns a form error. If it returns successfully with less than
    /// `limit` octets parsed, returns a form error indicating trailing data.
    /// If the limit is larger than the remaining number of octets, returns a
    /// `ParseError::ShortInput`.
    ///
    //  XXX NEEDS TESTS!!!
    pub fn parse_block<F, U>(
        &mut self,
        limit: usize,
        op: F,
    ) -> Result<U, ParseError>
    where
        F: FnOnce(&mut Self) -> Result<U, ParseError>,
    {
        let end = self.pos + limit;
        if end > self.len {
            self.advance_to_end();
            return Err(ParseError::ShortInput);
        }
        let len = self.len;
        self.len = end;
        let res = op(self);
        self.len = len;
        let res = if self.pos != end {
            Err(ParseError::Form(FormError::new("trailing data in field")))
        } else if let Err(ParseError::ShortInput) = res {
            Err(ParseError::Form(FormError::new("short field")))
        } else {
            res
        };
        self.pos = end;
        res
    }
}

//============ Composing =====================================================

//------------ Compose -------------------------------------------------------

/// A type that knows how to compose itself into an octets builder.
///
/// The term ‘composing’ refers to the process of creating a DNS wire-format
/// representation of a value’s data by appending this representation to the
/// end of an [octets builder].
///
/// The trait supports two different representations: a concrete and a
/// canonical representation. The former represents the actual data of the
/// value. For instance, it reflects the capitalisation of strings. The
/// canonical representation is used when calculating digests or ordering
/// values. Typically, it ignores capitalization and never compresses domain
/// names. See the documentation of [`CanonicalOrd`] for more details on
/// canonical representation.
///
/// [octets builder]: trait.OctetsBuilder.html
/// [`CanonicalOrd`]: ../cmp/trait.CanonicalOrd.html
pub trait Compose {
    /// Appends the concrete representation of the value to the target.
    ///
    /// If the representation doesn’t fit into the builder, returns an error.
    /// In this case the target is considered undefined. If it is supposed to
    /// be reused, it needs to be reset specifically.
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf>;

    /// Appends the canonical representation of the value to the target.
    ///
    /// If the representation doesn’t fit into the builder, returns an error.
    /// In this case the target is considered undefined. If it is supposed to
    /// be reused, it needs to be reset specifically.
    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        self.compose(target)
    }
}

impl<'a, C: Compose + ?Sized> Compose for &'a C {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        (*self).compose(target)
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        (*self).compose_canonical(target)
    }
}

impl Compose for i8 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&[*self as u8])
    }
}

impl Compose for u8 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&[*self])
    }
}

impl Compose for i16 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u16 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for i32 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u32 {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for Ipv4Addr {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.octets())
    }
}

impl Compose for Ipv6Addr {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.octets())
    }
}

//------------ octets_array --------------------------------------------------

#[macro_export]
macro_rules! octets_array {
    ( $vis:vis $name:ident => $len:expr) => {
        /// A fixed length octet buffer.
        ///
        /// The type functions both as an octets sequence and an octets
        /// builder atop a fixed size bytes array.
        #[derive(Clone)]
        $vis struct $name {
            octets: [u8; $len],
            len: usize
        }

        impl $name {
            /// Creates a new empty value.
            pub fn new() -> Self {
                Default::default()
            }

            /// Returns the contents as an octet slice.
            pub fn as_slice(&self) -> &[u8] {
                &self.octets[..self.len]
            }

            /// Returns the contents as a mutable octet slice.
            pub fn as_slice_mut(&mut self) -> &mut [u8] {
                &mut self.octets[..self.len]
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    octets: [0; $len],
                    len: 0
                }
            }
        }

        impl<'a> TryFrom<&'a [u8]> for $name {
            type Error = ShortBuf;

            fn try_from(src: &'a [u8]) -> Result<Self, ShortBuf> {
                let len = src.len();
                if len > $len {
                    Err(ShortBuf)
                }
                else {
                    let mut res = Self::default();
                    res.octets[..len].copy_from_slice(src);
                    res.len = len;
                    Ok(res)
                }
            }
        }

        impl core::ops::Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl core::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl borrow::Borrow<[u8]> for $name {
            fn borrow(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl borrow::BorrowMut<[u8]> for $name {
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl $crate::base::octets::OctetsBuilder for $name {
            type Octets = Self;

            fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
                if slice.len() > $len - self.len {
                    Err(ShortBuf)
                }
                else {
                    let end = self.len + slice.len();
                    self.octets[self.len..end].copy_from_slice(slice);
                    self.len = end;
                    Ok(())
                }
            }

            fn truncate(&mut self, len: usize) {
                if len < self.len {
                    self.len = len
                }
            }

            fn freeze(self) -> Self::Octets {
                self
            }

            fn len(&self) -> usize {
                self.len
            }

            fn is_empty(&self) -> bool {
                self.len == 0
            }
        }

        impl $crate::base::octets::EmptyBuilder for $name {
            fn empty() -> Self {
                $name {
                    octets: [0; $len],
                    len: 0
                }
            }

            fn with_capacity(_capacity: usize) -> Self {
                Self::empty()
            }
        }

        impl $crate::base::octets::IntoBuilder for $name {
            type Builder = Self;

            fn into_builder(self) -> Self::Builder {
                self
            }
        }

        impl $crate::base::octets::FromBuilder for $name {
            type Builder = Self;

            fn from_builder(builder: Self::Builder) -> Self {
                builder
            }
        }

        impl<T: AsRef<[u8]>> PartialEq<T> for $name {
            fn eq(&self, other: &T) -> bool {
                self.as_slice().eq(other.as_ref())
            }
        }

        impl Eq for $name { }

        impl<T: AsRef<[u8]>> PartialOrd<T> for $name {
            fn partial_cmp(&self, other: &T) -> Option<Ordering> {
                self.as_slice().partial_cmp(other.as_ref())
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.as_slice().cmp(other.as_slice())
            }
        }

        impl hash::Hash for $name {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.as_slice().hash(state)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.as_slice())
                    .finish()
            }
        }
    }
}

octets_array!(pub Octets32 => 32);
octets_array!(pub Octets64 => 64);
octets_array!(pub Octets128 => 128);
octets_array!(pub Octets256 => 256);
octets_array!(pub Octets512 => 512);
octets_array!(pub Octets1024 => 1024);
octets_array!(pub Octets2048 => 2048);
octets_array!(pub Octets4096 => 4096);

//------------ OctetsVec -----------------------------------------------------

/// A octets vector that doesn’t allocate for small sizes.
#[cfg(feature = "smallvec")]
pub type OctetsVec = SmallVec<[u8; 24]>;

//============ Error Types ===================================================

//------------ ShortBuf ------------------------------------------------------

/// An attempt was made to write beyond the end of a buffer.
///
/// This type is returned as an error by all functions and methods that append
/// data to an [octets builder] when the buffer size of the builder is not
/// sufficient to append the data.
///
/// [octets builder]: trait.OctetsBuilder.html
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortBuf;

//--- Display and Error

impl fmt::Display for ShortBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("buffer size exceeded")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShortBuf {}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pos_seek_remaining() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek(1).unwrap(), b"0");
        assert_eq!(parser.pos(), 0);
        assert_eq!(parser.remaining(), 10);
        assert_eq!(parser.seek(2), Ok(()));
        assert_eq!(parser.pos(), 2);
        assert_eq!(parser.remaining(), 8);
        assert_eq!(parser.peek(1).unwrap(), b"2");
        assert_eq!(parser.seek(10), Ok(()));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.remaining(), 0);
        assert_eq!(parser.peek_all(), b"");
        assert_eq!(parser.seek(11), Err(ParseError::ShortInput));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.remaining(), 0);
    }

    #[test]
    fn peek_check_len() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek(2), Ok(b"01".as_ref()));
        assert_eq!(parser.check_len(2), Ok(()));
        assert_eq!(parser.peek(10), Ok(b"0123456789".as_ref()));
        assert_eq!(parser.check_len(10), Ok(()));
        assert_eq!(parser.peek(11), Err(ParseError::ShortInput));
        assert_eq!(parser.check_len(11), Err(ParseError::ShortInput));
        parser.advance(2).unwrap();
        assert_eq!(parser.peek(2), Ok(b"23".as_ref()));
        assert_eq!(parser.check_len(2), Ok(()));
        assert_eq!(parser.peek(8), Ok(b"23456789".as_ref()));
        assert_eq!(parser.check_len(8), Ok(()));
        assert_eq!(parser.peek(9), Err(ParseError::ShortInput));
        assert_eq!(parser.check_len(9), Err(ParseError::ShortInput));
    }

    #[test]
    fn peek_all() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek_all(), b"0123456789");
        parser.advance(2).unwrap();
        assert_eq!(parser.peek_all(), b"23456789");
    }

    #[test]
    fn advance() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.pos(), 0);
        assert_eq!(parser.peek(1).unwrap(), b"0");
        assert_eq!(parser.advance(2), Ok(()));
        assert_eq!(parser.pos(), 2);
        assert_eq!(parser.peek(1).unwrap(), b"2");
        assert_eq!(parser.advance(9), Err(ParseError::ShortInput));
        assert_eq!(parser.advance(8), Ok(()));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.peek_all(), b"");
    }

    #[test]
    fn parse_octets() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.parse_octets(2).unwrap(), b"01");
        assert_eq!(parser.parse_octets(2).unwrap(), b"23");
        assert_eq!(parser.parse_octets(7), Err(ParseError::ShortInput));
        assert_eq!(parser.parse_octets(6).unwrap(), b"456789");
    }

    #[test]
    fn parse_buf() {
        let mut parser = Parser::from_static(b"0123456789");
        let mut buf = [0u8; 2];
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"01");
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"23");
        let mut buf = [0u8; 7];
        assert_eq!(parser.parse_buf(&mut buf), Err(ParseError::ShortInput));
        let mut buf = [0u8; 6];
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"456789");
    }

    #[test]
    fn parse_i8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_i8(), Ok(0x12));
        assert_eq!(parser.parse_i8(), Ok(-42));
        assert_eq!(parser.parse_i8(), Err(ParseError::ShortInput));
    }

    #[test]
    fn parse_u8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_u8(), Ok(0x12));
        assert_eq!(parser.parse_u8(), Ok(0xd6));
        assert_eq!(parser.parse_u8(), Err(ParseError::ShortInput));
    }

    #[test]
    fn parse_i16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_i16(), Ok(0x1234));
        assert_eq!(parser.parse_i16(), Ok(-4242));
        assert_eq!(parser.parse_i16(), Err(ParseError::ShortInput));
    }

    #[test]
    fn parse_u16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_u16(), Ok(0x1234));
        assert_eq!(parser.parse_u16(), Ok(0xef6e));
        assert_eq!(parser.parse_u16(), Err(ParseError::ShortInput));
    }

    #[test]
    fn parse_i32() {
        let mut parser =
            Parser::from_static(b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_i32(), Ok(0x12345678));
        assert_eq!(parser.parse_i32(), Ok(-42424242));
        assert_eq!(parser.parse_i32(), Err(ParseError::ShortInput));
    }

    #[test]
    fn parse_u32() {
        let mut parser =
            Parser::from_static(b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_u32(), Ok(0x12345678));
        assert_eq!(parser.parse_u32(), Ok(0xfd78a84e));
        assert_eq!(parser.parse_u32(), Err(ParseError::ShortInput));
    }
}

*/
