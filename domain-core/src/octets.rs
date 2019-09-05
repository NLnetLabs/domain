//! Helper types and traits for dealing with generic octet sequences.

use bytes::{Bytes, BytesMut};


//------------ OctetsBuilder -------------------------------------------------

pub trait OctetsBuilder: AsRef<[u8]> + AsMut<[u8]> + Sized {
    const MAX_CAPACITY: usize;
    type Octets: AsRef<[u8]>;

    fn empty() -> Self;
    fn with_capacity(capacity: usize) -> Self;

    fn append_slice(&mut self, slice: &[u8]);
    fn truncate(&mut self, len: usize);

    fn finish(self) -> Self::Octets;

    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

impl OctetsBuilder for Vec<u8> {
    const MAX_CAPACITY: usize = std::usize::MAX;
    type Octets = Self;

    fn empty() -> Self {
        Vec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        Vec::with_capacity(capacity)
    }

    fn append_slice(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len)
    }

    fn finish(self) -> Self::Octets {
        self
    }
}

impl OctetsBuilder for BytesMut {
    const MAX_CAPACITY: usize = std::usize::MAX;
    type Octets = Bytes;

    fn empty() -> Self {
        BytesMut::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        BytesMut::with_capacity(capacity)
    }

    fn append_slice(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len)
    }

    fn finish(self) -> Self::Octets {
        self.freeze()
    }
}


//------------ IntoBuilder ---------------------------------------------------

pub trait IntoBuilder {
    type Builder: OctetsBuilder;

    fn into_builder(self) -> Self::Builder;
}

impl IntoBuilder for Vec<u8> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}

impl<'a> IntoBuilder for &'a [u8] {
    type Builder = Vec<u8>;

    fn into_builder(self) -> Self::Builder {
        self.into()
    }
}

impl IntoBuilder for Bytes {
    type Builder = BytesMut;

    fn into_builder(self) -> Self::Builder {
        self.into()
    }
}


//------------ FromBuilder ---------------------------------------------------

pub trait FromBuilder: AsRef<[u8]> + Sized {
    type Builder: OctetsBuilder<Octets = Self>;

    fn from_builder(builder: Self::Builder) -> Self;
}

impl FromBuilder for Vec<u8> {
    type Builder = Self;

    fn from_builder(builder: Self) -> Self {
        builder
    }
}

impl FromBuilder for Bytes {
    type Builder = BytesMut;

    fn from_builder(builder: Self::Builder) -> Self {
        builder.into()
    }
}


//------------ IntoIter ------------------------------------------------------

pub struct IntoIter<T> {
    octets: T,
    len: usize,
    pos: usize,
}

impl<T: AsRef<[u8]>> IntoIter<T> {
    pub(crate) fn new(octets: T) -> Self {
        IntoIter {
            len: octets.as_ref().len(),
            octets,
            pos: 0
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for IntoIter<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.len {
            None
        }
        else {
            let res = self.octets.as_ref()[self.pos];
            self.pos += 1;
            Some(res)
        }
    }
}


//------------ Iter ----------------------------------------------------------

pub struct Iter<'a> {
    octets: &'a [u8],
}

impl<'a> Iter<'a> {
    pub(crate) fn new(octets: &'a [u8]) -> Self {
        Iter { octets }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, octets) = self.octets.split_first()?;
        self.octets = octets;
        Some(*res)
    }
}

