//! Creating and consuming data in wire format.

use super::name::ToDname;
use super::net::{Ipv4Addr, Ipv6Addr};
use octseq::builder::{OctetsBuilder, ShortBuf, Truncate};
use octseq::parse::{Parser, ShortInput};
use core::fmt;


//------------ compose functions ---------------------------------------------

/// Composes some data prefixed by its length.
///
/// # Panics
///
/// The function panics if the length of the composed data is greater than
/// 0xFFFF.
pub fn compose_len_prefixed_certain<Target, F>(
    target: &mut Target, op: F
) -> Result<(), Target::AppendError>
where
    Target: Composer + ?Sized,
    F: FnOnce(&mut Target) -> Result<(), Target::AppendError>
{
    target.append_slice(&[0; 2])?;
    let pos = target.as_ref().len();
    match op(target) {
        Ok(_) => {
            let len = u16::try_from(target.as_ref().len() - pos).expect(
                "long data"
            );
            target.as_mut()[pos - 2..pos].copy_from_slice(
                &(len).to_be_bytes()
            );
            Ok(())
        }
        Err(err) => {
            target.truncate(pos);
            Err(err)
        }
    }
}


//------------ Composer ------------------------------------------------------

pub trait Composer: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> + Truncate {
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
    fn append_compressed_dname<N: ToDname + ?Sized>(
        &mut self, name: &N,
    ) -> Result<(), Self::AppendError> {
        name.compose(self)
    }

    fn can_compress(&self) -> bool {
        false
    }
}

#[cfg(feature = "std")]
impl Composer for std::vec::Vec<u8> { }

impl<const N: usize> Composer for octseq::array::Array<N> { }

#[cfg(feature = "bytes")]
impl Composer for bytes::BytesMut { }

#[cfg(feature = "smallvec")]
impl<A: smallvec::Array<Item = u8>> Composer for smallvec::SmallVec<A> { }


//------------ Compose -------------------------------------------------------

pub trait Compose {
    const COMPOSE_LEN: u16 = 0;

    fn compose<Target: OctetsBuilder + ?Sized> (
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError>;
}

impl<'a, T: Compose + ?Sized> Compose for &'a T {
    const COMPOSE_LEN: u16 = T::COMPOSE_LEN;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        (*self).compose(target)
    }
}

impl Compose for i8 {
    const COMPOSE_LEN: u16 = 1;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&[*self as u8])
    }
}

impl Compose for u8 {
    const COMPOSE_LEN: u16 = 1;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&[*self])
    }
}

macro_rules! compose_to_be_bytes {
    ( $type:ident ) => {
        impl Compose for $type {
            const COMPOSE_LEN: u16 = ($type::BITS >> 2) as u16;

            fn compose<Target: OctetsBuilder + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                target.append_slice(&self.to_be_bytes())
            }
        }
    }
}

compose_to_be_bytes!(i16);
compose_to_be_bytes!(u16);
compose_to_be_bytes!(i32);
compose_to_be_bytes!(u32);
compose_to_be_bytes!(i64);
compose_to_be_bytes!(u64);
compose_to_be_bytes!(i128);
compose_to_be_bytes!(u128);

//------------ Parse ------------------------------------------------------

/// A type that can extract a value from a parser.
///
/// The trait is a companion to [`Parser<Ref>`]: it allows a type to use a
/// parser to create a value of itself. Because types may be generic over
/// octets types, the trait is generic over the octets reference of the
/// parser in question. Implementations should use minimal trait bounds
/// matching the parser methods they use.
///
/// For types that are generic over an octets sequence, the reference type
/// should be tied to the type’s own type argument. This will avoid having
/// to provide type annotations when simply calling `Parse::parse` for the
/// type. Typically this will happen via `OctetsRef::Range`. For instance,
/// a type `Foo<Octets>` should provide:
///
/// ```ignore
/// impl<Ref: OctetsRef> Parse<Ref> for Foo<Ref::Range> {
///     // etc.
/// }
/// ```
///
/// [`Parser<Ref>`]: struct.Parser.html
pub trait Parse<'a, Octs: ?Sized>: Sized {
    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it is supposed to be reused
    /// in this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError>;

    /// Skips over a value of this type at the beginning of `parser`.
    ///
    /// This function is the same as `parse` but doesn’t return the result.
    /// It can be used to check if the content of `parser` is correct or to
    /// skip over unneeded parts of the parser.
    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError>;
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i8 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i8().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(1).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u8 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u8().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(1).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i16 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i16().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(2).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u16 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u16().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(2).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i32 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i32().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u32 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u32().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for Ipv4Addr {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        Ok(Self::new(
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for Ipv6Addr {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(16).map_err(Into::into)
    }
}

//------------ LengthPrefixed ------------------------------------------------

pub struct LengthPrefixed<'a, Target: AsRef<[u8]> + AsMut<[u8]> + ?Sized> {
    target: &'a mut Target,
    start: usize,
    max_len: usize,
}

impl<'a, Target> LengthPrefixed<'a, Target>
where Target: Composer + ?Sized {
    pub fn try_new(
        target: &'a mut Target
    ) -> Result<Self, ShortBuf> {
        target.append_slice(b"\0\0").map_err(Into::into)?;
        let start = target.as_ref().len();
        let max_len = start.checked_add(0xFFFF).ok_or(ShortBuf)?;
        Ok(LengthPrefixed { target, start, max_len })
    }

    pub fn target_slice(&self) -> &[u8] {
        self.target.as_ref()
    }

    pub fn target_slice_mut(&mut self) -> &mut [u8] {
        self.target.as_mut()
    }

    fn _append(
        &mut self,
        op: impl FnOnce(&mut Target) -> Result<(), Target::AppendError>,
    ) -> Result<(), ShortBuf> {
        let curr = self.target.as_ref().len();
        op(self.target).map_err(Into::into)?;
        if self.target.as_ref().len() > self.max_len {
            self.target.truncate(curr);
            Err(ShortBuf)
        }
        else {
            Ok(())
        }
    }
}

impl<'a, Target> OctetsBuilder for LengthPrefixed<'a, Target>
where Target: Composer + ?Sized {
    type AppendError = ShortBuf;

    fn append_slice(
        &mut self, slice: &[u8]
    ) -> Result<(), Self::AppendError> {
        self._append(|target| target.append_slice(slice))
    }
}

impl<'a, Target: Composer + ?Sized> Composer for LengthPrefixed<'a, Target> {
    fn append_compressed_dname<N: ToDname + ?Sized>(
        &mut self, name: &N,
    ) -> Result<(), Self::AppendError> {
        self._append(|target| target.append_compressed_dname(name))
    }
}

impl<'a, Target> AsRef<[u8]> for LengthPrefixed<'a, Target>
where Target: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
    fn as_ref(&self) -> &[u8] {
        &self.target.as_ref()[self.start..]
    }
}

impl<'a, Target> AsMut<[u8]> for LengthPrefixed<'a, Target>
where Target: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.target.as_mut()[self.start..]
    }
}

impl<'a, Target> Truncate for LengthPrefixed<'a, Target>
where Target: Truncate + AsRef<[u8]> + AsMut<[u8]> + ?Sized {
    fn truncate(&mut self, len: usize) {
        if let Some(len) = self.start.checked_add(len) {
            self.target.truncate(len)
        }
    }
}

impl<'a, Target> Drop for LengthPrefixed<'a, Target>
where Target: AsRef<[u8]> + AsMut<[u8]> + ?Sized {
    fn drop(&mut self) {
        // XXX We should really do checked subtraction and conversion here.
        //     However, we don’t really want to panic in drop. We’ve made
        //     sure that the target can only grow or shrink by way of our own
        //     methods, so this should be safe -- provided those methods are
        //     correct.
        let len = (self.target.as_ref().len() - self.start) as u16;
        self.target.as_mut()[self.start - 2..self.start].copy_from_slice(
            &len.to_be_bytes()
        );
    }
}

//============ Error Types ===================================================

//------------ ComposeError --------------------------------------------------

/// An error happened while composing data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposeError {
    LongData,
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for ComposeError {
    fn from(_: T) -> Self {
        ComposeError::ShortBuf
    }
}


//------------ ParseError ----------------------------------------------------

/// An error happened while parsing data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    /// An attempt was made to go beyond the end of the parser.
    ShortInput,

    /// A formatting error occurred.
    Form(FormError),
}

impl ParseError {
    /// Creates a new parse error as a form error with the given message.
    pub fn form_error(msg: &'static str) -> Self {
        FormError::new(msg).into()
    }
}

//--- From

impl From<ShortInput> for ParseError {
    fn from(_: ShortInput) -> Self {
        ParseError::ShortInput
    }
}

impl From<FormError> for ParseError {
    fn from(err: FormError) -> Self {
        ParseError::Form(err)
    }
}

//--- Display and Error

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseError::ShortInput => f.write_str("unexpected end of input"),
            ParseError::Form(ref err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

//------------ FormError -----------------------------------------------------

/// A formatting error occured.
///
/// This is a generic error for all kinds of error cases that result in data
/// not being accepted. For diagnostics, the error is being given a static
/// string describing the error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormError(&'static str);

impl FormError {
    /// Creates a new form error value with the given diagnostics string.
    pub fn new(msg: &'static str) -> Self {
        FormError(msg)
    }
}

//--- Display and Error

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FormError {}

