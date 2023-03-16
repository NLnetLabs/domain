//! EDNS options for signaling cryptographic algorithm understanding.
//!
//! The options in this module allow a validating resolver to signal which
//! signature and hash algorithms they support when making queries.  These
//! options are defined in [RFC 6975].
//!
//! There are three options for three different purposes. However, the data
//! for each of them is a sequence of security algorithms. The module only
//! defines one type [`Understood<Variant, Octs>`][Understood] which carries
//! the specific variant as its first type parameter. Marker types and
//! type aliases are defined for the three options [Dau], [Dhu], and [N3u]
//! which specific the DNSSEC signature algorithms, DS hash algorithm, and
//! NSEC3 hash algorithms understood by the client, respectively.
//!
//! [RFC 6975]: https://tools.ietf.org/html/rfc6975

use super::super::iana::{OptionCode, SecAlg};
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, ParseError};
use super::{
    BuildDataError, OptData, ComposeOptData, LongOptData, Opt, ParseOptData
};
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use core::{borrow, fmt, hash, slice};
use core::marker::PhantomData;


//------------ Understood ----------------------------------------------------

/// Option data for understood DNSSEC algorithms.
///
/// This type provides the option data for the three options DAU, DHU, and
/// N3U which allow a client to specify the cryptographic algorithms it
/// supports for DNSSEC signatures, DS hashes, and NSEC3 hashes respectively.
/// Each of them contains a sequence of [`SecAlg`] values in wire format.
///
/// Which exact option is to be used is specified via the `Variant` type
/// argument. Three marker types `DauVariant`, `DhuVariant` and `N3uVariant`
/// are defined with accompanying type aliases [`Dau`], [`Dhu`], and [`N3u`].
///
/// You can create a new value from anything that can be turned into an
/// iterator over [`SecAlg`] via the
/// [`from_sec_algs`][Understood::from_sec_algs] associated function.
/// Once you have a value, you can iterate over the algorithms via the
/// [`iter`][Understood::iter] method or use the `IntoIterator` implementation
/// for a reference.
#[derive(Clone, Copy, Debug)]
pub struct Understood<Variant, Octs: ?Sized> {
    /// A marker for the variant.
    marker: PhantomData<Variant>,

    /// The octets with the data.
    ///
    /// These octets contain a sequence of composed [`SecAlg`] values.
    octets: Octs,
}

/// The marker type for the DAU option.
///
/// Use this as the `Variant` type argument of the
/// [`Understood<..>`][Understood] type to select a DAU option.
#[derive(Clone, Copy, Debug)]
pub struct DauVariant;

/// The marker type for the DHU option.
///
/// Use this as the `Variant` type argument of the
/// [`Understood<..>`][Understood] type to select a DHU option.
#[derive(Clone, Copy, Debug)]
pub struct DhuVariant;

/// The marker type for the N3U option.
///
/// Use this as the `Variant` type argument of the
/// [`Understood<..>`][Understood] type to select a N3U option.
#[derive(Clone, Copy, Debug)]
pub struct N3uVariant;

/// A type alias for the DAU option.
pub type Dau<Octs> = Understood<DauVariant, Octs>;

/// A type alias for the DHU option.
pub type Dhu<Octs> = Understood<DhuVariant, Octs>;

/// A type alias for the N3U option.
pub type N3u<Octs> = Understood<N3uVariant, Octs>;

impl<Variant, Octs> Understood<Variant, Octs> {
    /// Creates a new value from an octets sequence.
    ///
    /// Returns an error if the slice does not contain a value in wire
    /// format or is longer than 65,535 octets.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError>
    where
        Octs: AsRef<[u8]>,
    {
        Understood::<Variant, _>::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from an octets sequence without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that the slice contains a sequence of
    /// 16 bit values that is no longer than 65,535 octets.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Understood {
            marker: PhantomData,
            octets
        }
    }

    /// Creates a new value from a sequence of algorithms.
    ///
    /// The operation will fail if the iterator returns more than 32,767
    /// algorithms.
    pub fn from_sec_algs(
        sec_algs: impl IntoIterator<Item = SecAlg>
    ) -> Result<Self, BuildDataError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
    {
        let mut octets = EmptyBuilder::empty();
        for item in sec_algs {
            item.compose(&mut octets)?;
        }
        let octets = Octs::from_builder(octets);
        LongOptData::check_len(octets.as_ref().len())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl<Variant> Understood<Variant, [u8]> {
    /// Creates a new value from an octets slice.
    ///
    /// Returns an error if the slice does not contain a value in wire
    /// format or is longer than 65,535 octets.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Understood::<Variant, _>::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a new value from an octets slice without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that the slice contains a sequence of
    /// 16 bit values that is no longer than 65,535 octets.
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    /// Checks that a slice contains a correctly encoded value.
    fn check_slice(slice: &[u8]) -> Result<(), ParseError> {
        LongOptData::check_len(slice.len())?;
        if slice.len() % usize::from(u16::COMPOSE_LEN) != 0 {
            return Err(ParseError::form_error("invalid understood data"))
        }
        Ok(())
    }
}

impl<Variant, Octs: AsRef<[u8]>> Understood<Variant, Octs> {
    /// Parses a value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::from_octets(parser.parse_octets(parser.remaining())?)
    }
}

impl<Variant, Octs: ?Sized> Understood<Variant, Octs> {
    /// Returns a reference to the underlying octets.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    /// Converts a value into its underlying octets.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    /// Returns the data as an octets slice.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    /// Returns a reference to a value over an octets slice.
    pub fn for_slice(&self) -> &Understood<Variant, [u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe {
            Understood::<Variant, _>::from_slice_unchecked(
                self.octets.as_ref()
            )
        }
    }

    /// Returns an iterator over the algorithms in the data.
    pub fn iter(&self) -> SecAlgsIter
    where
        Octs: AsRef<[u8]>,
    {
        SecAlgsIter::new(self.octets.as_ref())
    }
}

//--- OctetsFrom

impl<Variant, O, OO> OctetsFrom<Understood<Variant, O>>
for Understood<Variant, OO>
where
    OO: OctetsFrom<O>,
{
    type Error = OO::Error;

    fn try_octets_from(
        source: Understood<Variant, O>
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Self::from_octets_unchecked(
                OO::try_octets_from(source.octets)?
            )
        })
    }
}

//--- AsRef, AsMut, Borrow, BorrowMut

impl<Variant, Octs> AsRef<[u8]> for Understood<Variant, Octs>
where Octs: AsRef<[u8]> + ?Sized {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Variant, Octs> borrow::Borrow<[u8]> for Understood<Variant, Octs>
where Octs: AsRef<[u8]> + ?Sized {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

//--- PartialEq and Eq

impl<Var, OtherVar, Octs, OtherOcts> PartialEq<Understood<OtherVar, OtherOcts>>
for Understood<Var, Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Understood<OtherVar, OtherOcts>) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<Variant, Octs: AsRef<[u8]> + ?Sized> Eq for Understood<Variant, Octs> { }

//--- Hash

impl<Variant, Octs: AsRef<[u8]>> hash::Hash for Understood<Variant, Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- OptData etc.

impl<Octs: ?Sized> OptData for Understood<DauVariant, Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::Dau
    }
}

impl<Octs: ?Sized> OptData for Understood<DhuVariant, Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::Dhu
    }
}

impl<Octs: ?Sized> OptData for Understood<N3uVariant, Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::N3u
    }
}

impl<'a, Octs: Octets + ?Sized> ParseOptData<'a, Octs>
for Understood<DauVariant, Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Dau {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<'a, Octs: Octets + ?Sized> ParseOptData<'a, Octs>
for Understood<DhuVariant, Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Dhu {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<'a, Octs: Octets + ?Sized> ParseOptData<'a, Octs>
for Understood<N3uVariant, Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::N3u {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Variant, Octs> ComposeOptData for Understood<Variant, Octs>
where
    Self: OptData,
    Octs: AsRef<[u8]> + ?Sized, 
{
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}

//--- IntoIter

impl<'a, Variant, Octs> IntoIterator for &'a Understood<Variant, Octs>
where
    Octs: AsRef<[u8]> + ?Sized
{
    type Item = SecAlg;
    type IntoIter = SecAlgsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- Display

impl<Variant, Octs> fmt::Display for Understood<Variant, Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;

        for v in self.octets.as_ref() {
            if first {
                write!(f, "{}", *v)?;
                first = false;
            } else {
                write!(f, ", {}", *v)?
            }
        }
        Ok(())
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first DAU option if present.
    ///
    /// This option lists the DNSSEC signature algorithms the requester
    /// supports.
    pub fn dau(&self) -> Option<Dau<Octs::Range<'_>>> {
        self.first()
    }

    /// Returns the first DHU option if present.
    ///
    /// This option lists the DS hash algorithms the requester supports.
    pub fn dhu(&self) -> Option<Dhu<Octs::Range<'_>>> {
        self.first()
    }

    /// Returns the first N3U option if present.
    ///
    /// This option lists the NSEC3 hash algorithms the requester supports.
    pub fn n3u(&self) -> Option<N3u<Octs::Range<'_>>> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends a DAU option.
    ///
    /// The DAU option lists the DNSSEC signature algorithms the requester
    /// supports.
    pub fn dau(
        &mut self, algs: &impl AsRef<[SecAlg]>,
    ) -> Result<(), BuildDataError> {
        Ok(self.push_raw_option(
            OptionCode::Dau,
            u16::try_from(
                algs.as_ref().len() * usize::from(SecAlg::COMPOSE_LEN)
            ).map_err(|_| BuildDataError::LongOptData)?,
            |octs| {
                algs.as_ref().iter().try_for_each(|item| item.compose(octs))
            },
        )?)
    }

    /// Appends a DHU option.
    ///
    /// The DHU option lists the DS hash algorithms the requester supports.
    pub fn dhu(
        &mut self, algs: &impl AsRef<[SecAlg]>,
    ) -> Result<(), BuildDataError> {
        Ok(self.push_raw_option(
            OptionCode::Dhu,
            u16::try_from(
                algs.as_ref().len() * usize::from(SecAlg::COMPOSE_LEN)
            ).map_err(|_| BuildDataError::LongOptData)?,
            |octs| {
                algs.as_ref().iter().try_for_each(|item| item.compose(octs))
            },
        )?)
    }

    /// Appends a N3U option.
    ///
    /// The N3U option lists the NSEC3 hash algorithms the requester supports.
    pub fn n3u(
        &mut self, algs: &impl AsRef<[SecAlg]>,
    ) -> Result<(), BuildDataError> {
        Ok(self.push_raw_option(
            OptionCode::N3u,
            u16::try_from(
                algs.as_ref().len() * usize::from(SecAlg::COMPOSE_LEN)
            ).map_err(|_| BuildDataError::LongOptData)?,
            |octs| {
                algs.as_ref().iter().try_for_each(|item| item.compose(octs))
            },
        )?)
    }
}

//------------ SecAlgsIter ---------------------------------------------------

pub struct SecAlgsIter<'a>(slice::Iter<'a, u8>);

impl<'a> SecAlgsIter<'a> {
    fn new(slice: &'a [u8]) -> Self {
        SecAlgsIter(slice.iter())
    }
}

impl<'a> Iterator for SecAlgsIter<'a> {
    type Item = SecAlg;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| SecAlg::from_int(*x))
    }
}

//============ Tests ========================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;

    #[test]
    fn dau_compose_parse() {
        test_option_compose_parse(
            &Dau::from_octets("foo").unwrap(),
            |parser| Dau::parse(parser)
        );
    }
}
