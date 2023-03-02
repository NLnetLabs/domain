//! Creating and consuming data in wire format.

use super::name::ToDname;
use super::net::{Ipv4Addr, Ipv6Addr};
use core::fmt;
use octseq::builder::{OctetsBuilder, Truncate};
use octseq::parse::{Parser, ShortInput};

//------------ Composer ------------------------------------------------------

pub trait Composer:
    OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> + Truncate
{
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
        &mut self,
        name: &N,
    ) -> Result<(), Self::AppendError> {
        name.compose(self)
    }

    fn can_compress(&self) -> bool {
        false
    }
}

#[cfg(feature = "std")]
impl Composer for std::vec::Vec<u8> {}

impl<const N: usize> Composer for octseq::array::Array<N> {}

#[cfg(feature = "bytes")]
impl Composer for bytes::BytesMut {}

#[cfg(feature = "smallvec")]
impl<A: smallvec::Array<Item = u8>> Composer for smallvec::SmallVec<A> {}

//------------ Compose -------------------------------------------------------

/// An extension trait to add composing to foreign types.
///
/// This trait can be used to add the `compose` method to a foreign type. For
/// local types, the method should be added directly to the type instead.
///
/// The trait can only be used for types that have a fixed-size wire
/// representation.
pub trait Compose {
    /// The length in octets of the wire representation of a value.
    ///
    /// Because all wire format lengths are limited to 16 bit, this is a
    /// `u16` rather than a `usize`.
    const COMPOSE_LEN: u16 = 0;

    /// Appends the wire format representation of the value to the target.
    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

impl<'a, T: Compose + ?Sized> Compose for &'a T {
    const COMPOSE_LEN: u16 = T::COMPOSE_LEN;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        (*self).compose(target)
    }
}

impl Compose for i8 {
    const COMPOSE_LEN: u16 = 1;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&[*self as u8])
    }
}

impl Compose for u8 {
    const COMPOSE_LEN: u16 = 1;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&[*self])
    }
}

macro_rules! compose_to_be_bytes {
    ( $type:ident ) => {
        impl Compose for $type {
            const COMPOSE_LEN: u16 = ($type::BITS >> 3) as u16;

            fn compose<Target: OctetsBuilder + ?Sized>(
                &self,
                target: &mut Target,
            ) -> Result<(), Target::AppendError> {
                target.append_slice(&self.to_be_bytes())
            }
        }
    };
}

compose_to_be_bytes!(i16);
compose_to_be_bytes!(u16);
compose_to_be_bytes!(i32);
compose_to_be_bytes!(u32);
compose_to_be_bytes!(i64);
compose_to_be_bytes!(u64);
compose_to_be_bytes!(i128);
compose_to_be_bytes!(u128);

impl Compose for Ipv4Addr {
    const COMPOSE_LEN: u16 = 4;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.octets())
    }
}

impl Compose for Ipv6Addr {
    const COMPOSE_LEN: u16 = 16;

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.octets())
    }
}

// No impl for [u8; const N: usize] because we can’t guarantee a correct
// COMPOSE_LEN -- it may be longer than a u16 can hold.

//------------ Parse ------------------------------------------------------

/// An extension trait to add parsing to foreign types.
///
/// This trait can be used to add the `parse` method to a foreign type. For
/// local types, the method should be added directly to the type instead.
pub trait Parse<'a, Octs: ?Sized>: Sized {
    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it is supposed to be reused
    /// in this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError>;
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i8 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i8().map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u8 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u8().map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i16 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i16().map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u16 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u16().map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for i32 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_i32().map_err(Into::into)
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for u32 {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        parser.parse_u32().map_err(Into::into)
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
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> Parse<'a, Octs> for Ipv6Addr {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized, const N: usize> Parse<'a, Octs>
    for [u8; N]
{
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let mut res = [0u8; N];
        parser.parse_buf(&mut res)?;
        Ok(res)
    }
}

//============ Error Types ===================================================

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
