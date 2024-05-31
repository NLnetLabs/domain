//! Handling of service binding parameters.
//!
//! This is a private module. It’s public types are re-exported by the
//! parent.
use super::value::AllValues;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::SvcParamKey;
use crate::base::scan::Symbol;
use crate::base::wire::{Compose, Parse, ParseError};
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, ShortBuf};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::{Parser, ShortInput};
use core::{cmp, fmt, hash};
use core::cmp::Ordering;
use core::marker::PhantomData;

//------------ SvcParams -----------------------------------------------------

/// A sequence of service binding parameters.
///
/// These parameters provide information helpful when trying to connect to an
/// endpoint offering a service. They consist of a sequence of parameter
/// values. Each value has a type and some data specific to that type. The
/// type is provided through a `u16` key with values assigned via an IANA
/// registry. The key and registry are available through
/// [`SvcParamKey`]. Each key is only allowed to appear at most once in the
/// parameter sequence. Values need to be ordered by their key’s integer value.
///
/// A value of the `SvcParams` type contains a sequence of values in their
/// wire-format encoded form. It guarantees that this content is correctly
/// encoded. It does not guarantee that the content of the individual
/// parameter value is correct. It also does not guarantee any size limit
/// to the octets sequence.
///
/// You can create a value of this type through parsing or manually via
/// [`from_octets`][Self::from_octets] or [`from_slice`][Self::from_slice].
/// You can also build a new value from scratch via the [`SvcParamsBuilder`].
/// The [`from_values`][Self::from_values] function provides a shortcut that
/// crates the builder, passes it to a closure, and returns the finished
/// parameter sequence.
///
/// Access to the values of the parameter sequence happens through a mechanism
/// similar to record data: Various types exist that implement either a
/// specific value type or a group of types. These types need to implement the
/// [`SvcParamValue`] and [`ParseSvcParamValue`] traits to be used to access
/// values. They can be used as a type parameter to the [`iter`][Self::iter]
/// method to acquire an iterator over all the values that they understand.
/// Since every concrete value can only be present once, the
/// [`first`][Self::first] method can be used together with a value type
/// implementing that concrete value to get the value if present. As a
/// convenience, methods exist for every currently defined value type which
/// return a value of that type if present.
///
/// The type [`UnknownSvcParam`] can be used to represent any value type with
/// the value as a octets sequence. The [`AllValues`] enum provides typed
/// access to all known value types.
///
/// # Wire Format
///
/// The wire format of a parameter sequence consists of a sequence of
/// values. Each value is encoded as a 16 bit parameter key – represented
/// by [`SvcParamKey`] in this crate –, followed by an unsigned 16 bit length
/// value, followed by this many octets. Since the sequence is the last element
/// in the record data, it is limited by the length of the record data only.
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct SvcParams<Octs: ?Sized> {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with =
                "octseq::serde::SerializeOctets::serialize_octets",
            deserialize_with =
                "octseq::serde::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octs: octseq::serde::SerializeOctets",
                deserialize =
                    "Octs: octseq::serde::DeserializeOctets<'de> + Sized",
            )
        )
    )]
    octets: Octs,
}

impl<Octs> SvcParams<Octs> {
    /// Creates a parameter sequence from an octets sequence.
    ///
    /// The method checks that `octets` contains a parameter sequence that is
    /// correctly encoded in wire format. It does not check that the
    /// individual values are correctly encoded. It also does not check for
    /// any length limit.
    pub fn from_octets(octets: Octs) -> Result<Self, SvcParamsError>
    where Octs: AsRef<[u8]> {
        SvcParams::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from an octets sequence without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `octets` contains a properly formatted
    /// parameter sequence.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        SvcParams { octets }
    }
}

impl SvcParams<[u8]> {
    /// Creates a parameter sequence from an octets slice.
    ///
    /// The method checks that `slice` contains a parameter sequence that is
    /// correctly encoded in wire format. It does not check that the
    /// individual values are correctly encoded. It also does not check for
    /// any length limit.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, SvcParamsError> {
        SvcParams::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a new value from a slice without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `slice` contains a properly formatted
    /// parameter sequence.
    #[must_use]
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: SvcParams has repr(transparent)
        core::mem::transmute(slice)
    }

    /// Checks that a slice contains a correctly encoded parameters sequence.
    fn check_slice(slice: &[u8]) -> Result<(), SvcParamsError> {
        let mut parser = Parser::from_ref(slice);
        let mut last_key = None;
        while parser.remaining() > 0 {
            let key = u16::parse(&mut parser)?;
            if let Some(last_key) = last_key {
                if key <= last_key {
                    Err(ParseError::form_error("unordered SVCB params"))?;
                }
            }
            last_key = Some(key);
            let len = u16::parse(&mut parser)?;
            parser.advance(len.into())?;
        }
        Ok(())
    }
}

impl<Octs> SvcParams<Octs> {
    /// Creates a parameter sequence by constructing it from values.
    ///
    /// The method expects a closure that receives an [`SvcParamsBuilder`]
    /// which it should push all the required values to. Once it returns,
    /// this builder is frozen into an `SvcParams` value and returned.
    pub fn from_values<F>(op: F) -> Result<Self, PushError>
    where
        Octs: FromBuilder,
        <Octs  as FromBuilder>::Builder:
            AsRef<[u8]> + OctetsBuilder + EmptyBuilder,
        F: FnOnce(
            &mut SvcParamsBuilder<<Octs  as FromBuilder>::Builder>
        ) -> Result<(), PushError>,
    {
        let mut res = SvcParamsBuilder::empty();
        op(&mut res)?;
        res.freeze().map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]>> SvcParams<Octs> {
    /// Parses a parameter sequence from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        Self::from_octets(
            parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }
}

impl<Octs: ?Sized> SvcParams<Octs> {
    /// Returns a reference to the underlying octets sequence.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> SvcParams<Octs> {
    /// Returns a slice of the underlying octets sequence.
    pub fn as_slice(&self) -> &[u8] {
        self.octets.as_ref()
    }

    /// Returns a parameter sequence atop a slice of this value’s octets.
    pub fn for_slice(&self) -> &SvcParams<[u8]> {
        unsafe { SvcParams::from_slice_unchecked(self.octets.as_ref()) }
    }

    /// Returns the length of the parameter sequence in octets.
    pub fn len(&self) -> usize {
        self.octets.as_ref().len()
    }

    /// Returns whether the parameters sequences is empty.
    pub fn is_empty(&self) -> bool {
        self.octets.as_ref().is_empty()
    }

    /// Returns the first value of type `Value`.
    ///
    /// This method is intended to be used with value types implementing a
    /// specific type. Since only one instance is allowed to be present,
    /// this method also returns `None` if the first value fails parsing,
    /// assuming that the value is unusable and should be ignored.
    ///
    /// This may not be the correct behaviour in all cases. Please use
    /// `self.iter::<Value>().next()` to get an optional parsing result.
    pub fn first<'s, Value>(&'s self) -> Option<Value>
    where
        Octs: Octets,
        Value: ParseSvcParamValue<'s, Octs>,
    {
        self.iter::<Value>().next().and_then(Result::ok)
    }

    /// Returns an iterator over all values accepted by `Value`.
    pub fn iter<Value>(&self) -> ValueIter<Octs, Value> {
        ValueIter::new(self.as_octets())
    }

    /// Returns an iterator over all values.
    pub fn iter_all(&self) -> ValueIter<Octs, AllValues<Octs>>
    where Octs: Sized {
        self.iter()
    }

    /// Returns an iterator over all values in their raw form.
    pub fn iter_raw(
        &self
    ) -> impl Iterator<Item = UnknownSvcParam<Octs::Range<'_>>>
    where Octs: Octets + Sized {
        self.iter().map(|item| item.expect("parsing cannot have failed"))
    }

    /// Composes the wire-format of the parameter sequence.
    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}

//--- OctetsFrom

impl<SrcOcts, Octs> OctetsFrom<SvcParams<SrcOcts>> for SvcParams<Octs>
where Octs: OctetsFrom<SrcOcts> {
    type Error = Octs::Error;

    fn try_octets_from(
        src: SvcParams<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            SvcParams::from_octets_unchecked(src.octets.try_octets_into()?)
        })
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts> PartialEq<SvcParams<OtherOcts>> for SvcParams<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &SvcParams<OtherOcts>) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for SvcParams<Octs> { }

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for SvcParams<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- PartialOrd Ord, and CanonicalOrd

impl<Octs, OtherOcts> PartialOrd<SvcParams<OtherOcts>> for SvcParams<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(
        &self, other: &SvcParams<OtherOcts>
    ) -> Option<cmp::Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for SvcParams<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl<Octs, OtherOcts> CanonicalOrd<SvcParams<OtherOcts>> for SvcParams<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(
        &self, other: &SvcParams<OtherOcts>
    ) -> cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Display and Debug

impl<Octs: Octets + ?Sized> fmt::Display for SvcParams<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parser = Parser::from_ref(self.as_slice());
        let mut first = true;
        while parser.remaining() > 0 {
            let key = SvcParamKey::parse(
                &mut parser
            ).expect("invalid SvcbParam");
            let len = usize::from(
                u16::parse(&mut parser).expect("invalid SvcParam")
            );
            let mut parser = parser.parse_parser(
                len
            ).expect("invalid SvcParam");
            if first {
                first = false;
            }
            else {
                f.write_str(" ")?;
            }
            write!(
                f, "{}", super::value::AllValues::parse_any(key, &mut parser)
            )?;
        };
        Ok(())
    }
}

impl<Octs: Octets + ?Sized> fmt::Debug for SvcParams<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SvcParams").field(
            &format_args!("{}", self)
        ).finish()
    }
}


//------------ ValueIter -----------------------------------------------------

/// An iterator over the values in a parameter sequence.
///
/// The iterator skips over those values that `Value` does not accept. It
/// returns the result of trying to parse the value into `Value`.
#[derive(Clone, Debug)]
pub struct ValueIter<'a, Octs: ?Sized, Value> {
    parser: Parser<'a, Octs>,
    marker: PhantomData<Value>,
}

impl<'a, Octs: AsRef<[u8]> + ?Sized, Value> ValueIter<'a, Octs, Value> {
    fn new(octets: &'a Octs) -> Self {
        ValueIter {
            parser: Parser::from_ref(octets),
            marker: PhantomData,
        }
    }

    fn next_step(&mut self) -> Result<Option<Value>, ParseError>
    where
        Octs: Octets,
        Value: ParseSvcParamValue<'a, Octs>,
    {
        let key = SvcParamKey::parse(&mut self.parser)?;
        let len = usize::from(u16::parse(&mut self.parser)?);
        let mut parser = self.parser.parse_parser(len)?;
        let res = Value::parse_value(key, &mut parser)?;
        if res.is_some() && parser.remaining() > 0 {
            return Err(ParseError::form_error(
                "trailing data in SVCB parameter",
            ));
        }
        Ok(res)
    }
}

impl<'a, Octs, Value> Iterator for ValueIter<'a, Octs, Value>
where
    Octs: Octets + ?Sized,
    Value: ParseSvcParamValue<'a, Octs>,
{
    type Item = Result<Value, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => { }
                Err(err) => {
                    // Advance to end so we’ll return None from now on.
                    self.parser.advance_to_end();
                    return Some(Err(err));
                }
            }
        }
        None
    }
}

//------------ SvcParamValue, ParseSvcParamValue, ComposeSvcParamValue -------

/// A type representing a service binding parameter value.
pub trait SvcParamValue {
    /// Returns the parameter key of the value.
    fn key(&self) -> SvcParamKey;
}

/// A service binding parameter value that can be parse from wire format.
pub trait ParseSvcParamValue<'a, Octs: ?Sized>: SvcParamValue + Sized {
    /// Parse a parameter value from wire format.
    ///
    /// The method should return `Ok(None)` if the type cannot parse values
    /// with `key`. It should return an error if parsing fails.
    fn parse_value(
        key: SvcParamKey, parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError>;
}

/// A service binding parameter value that can be composed into wire format.
///
/// All value types need to be able to calculate the length of their
/// wire format. This length needs to fit into a `u16`. It is the
/// responsibility of the value type to ensure that it will not grow too
/// large.
pub trait ComposeSvcParamValue: SvcParamValue {
    /// Returns the length of the composed value.
    fn compose_len(&self) -> u16;

    /// Appends the wire format of the value to the end of `target`.
    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

//------------ UnknownSvcParam -----------------------------------------------

/// A service binding parameter value in its raw form.
///
/// This type can be used for any value type. It keeps the value’s data in
/// its raw wire format.
#[derive(Clone, Debug)]
pub struct UnknownSvcParam<Octs> {
    /// The key of the value.
    key: SvcParamKey,

    /// The octets of the value.
    value: Octs,
}

impl<Octs> UnknownSvcParam<Octs> {
    /// Creates a new parameter value from the given key and data.
    ///
    /// The function returns an error if `value` is longer than 65,535 octets.
    pub fn new(key: SvcParamKey, value: Octs) -> Result<Self, LongSvcParam>
    where Octs: AsRef<[u8]> {
        LongSvcParam::check_len(value.as_ref().len())?;
        Ok(unsafe { Self::new_unchecked(key, value) })
    }

    /// Creates a new SVCB parameter value without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to make sure that `value` is not longer than
    /// 65,535 octets.
    pub unsafe fn new_unchecked(key: SvcParamKey, value: Octs) -> Self {
        Self { key, value }
    }
}

impl<Octs: AsRef<[u8]>> UnknownSvcParam<Octs> {
    /// Parses a parameter value’s data from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        key: SvcParamKey,
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::new(
            key, parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }

    /// Parses a full parameter from the wire format.
    ///
    /// This function parses the key, length, and data of the parameter.
    pub fn parse_param<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let key = SvcParamKey::parse(parser)?;
        let len = usize::from(u16::parse(parser)?);
        let value = parser.parse_octets(len)?;
        Ok(unsafe { Self::new_unchecked(key, value) })
    }

    /// Appends the wire format of the full parameter to the target.
    ///
    /// This includes the key and length of the parameter.
    pub fn compose_param<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.key.compose(target)?;
        self.compose_len().compose(target)?;
        self.compose_value(target)
    }
}

impl<Octs> UnknownSvcParam<Octs> {
    /// Returns the key of the value.
    pub fn key(&self) -> SvcParamKey {
        self.key
    }

    /// Returns a reference to the value octets.
    pub fn value(&self) -> &Octs {
        &self.value
    }
 
    /// Returns a slice of the value.
    pub fn as_slice(&self) -> &[u8]
    where Octs: AsRef<[u8]> {
        self.value.as_ref()
    }
 
    /// Returns a mutable slice of the value.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where Octs: AsMut<[u8]> {
        self.value.as_mut()
    }
}

//--- AsRef and AsMut

impl<Octs> AsRef<Octs> for UnknownSvcParam<Octs> {
    fn as_ref(&self) -> &Octs {
        self.value()
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for UnknownSvcParam<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]>> AsMut<[u8]> for UnknownSvcParam<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts> PartialEq<UnknownSvcParam<OtherOcts>>
for UnknownSvcParam<Octs>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
{
    fn eq(&self, other: &UnknownSvcParam<OtherOcts>) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]>> Eq for UnknownSvcParam<Octs> { }

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for UnknownSvcParam<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- SvcParamValue et al.

impl<Octs> SvcParamValue for UnknownSvcParam<Octs> {
    fn key(&self) -> SvcParamKey {
        self.key
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcParamValue<'a, Octs>
for UnknownSvcParam<Octs::Range<'a>> {
    fn parse_value(
        key: SvcParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        Self::new(
            key, parser.parse_octets(parser.remaining())?
        ).map(Some).map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]>> ComposeSvcParamValue for UnknownSvcParam<Octs> {
    fn compose_len(&self) -> u16 {
        u16::try_from(self.as_slice().len()).expect("long value")
    }

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.as_slice())
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for UnknownSvcParam<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.key)?;
        let slice = self.value.as_ref();
        if !slice.is_empty() {
            f.write_str("=")?;
            for &ch in slice {
                Symbol::from_octet(ch).fmt(f)?;
            }
        }
        Ok(())
    }
}


//------------ SvcParamsBuilder ----------------------------------------------

/// A builder for a service parameter sequence.
///
/// This type wraps an octets builder and allows appending parameter values.
/// You can create a new empty builder using the [`empty`][Self::empty]
/// function or copy an existing value through
/// [`from_params`][Self::from_params].
///
/// You can add additional values using the [`push`][Self::push] method.
/// There are also dedicated methods for all known value types. The builder
/// will make sure that each parameter key can only appear once. Thus,
/// pushing values may fail if a value is already present.
///
/// The builder also takes care of sorting the values into their correct
/// order. So you can push them in any order.
///
/// It only sorts the items when producing a frozen value via the
/// [`freeze`][Self::freeze] method.
#[derive(Clone, Debug)]
pub struct SvcParamsBuilder<Octs> {
    /// The octets builder.
    octets: Octs,
}

impl<Octs> SvcParamsBuilder<Octs> {
    /// Creates an empty parameter builder.
    #[must_use]
    pub fn empty() -> Self
    where Octs: EmptyBuilder {
        Self { octets: Octs::empty() }
    }

    /// Creates a parameter builder from an existing parameter sequence.
    ///
    /// The function creates a new empty builder and copies over the content
    /// of `params`. It can fail if the octets builder is not capable of
    /// providing enough space to hold the content of `params`.
    pub fn from_params<Src: Octets + ?Sized>(
        params: &SvcParams<Src>
    ) -> Result<Self, ShortBuf>
    where Octs: AsRef<[u8]> + OctetsBuilder + EmptyBuilder {
        let mut octets = Octs::empty();
        for item in params.iter::<UnknownSvcParam<_>>() {
            let item = item.expect("invalid SvcParams");
            let start = u32::try_from(
                octets.as_ref().len()
            ).map_err(|_| ShortBuf)?.checked_add(
                u32::from(u32::COMPOSE_LEN)
            ).ok_or(ShortBuf)?;
            octets.append_slice(
                start.to_ne_bytes().as_ref()
            ).map_err(Into::into)?;
            item.compose_param(&mut octets).map_err(Into::into)?;
        }
        octets.append_slice(
            u32::MAX.to_be_bytes().as_ref()
        ).map_err(Into::into)?;
        Ok(Self { octets })
    }

    /// Adds a new value to the builder.
    ///
    /// The method will return an error if a value with this key is already
    /// present or if there isn’t enough space left in the builder’s buffer.
    pub fn push<Value: ComposeSvcParamValue + ?Sized>(
        &mut self, value: &Value
    ) -> Result<(), PushError>
    where Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> {
        self.push_raw(
            value.key(), value.compose_len(), |octs| value.compose_value(octs)
        )
    }

    pub(super) fn push_raw(
        &mut self,
        key: SvcParamKey,
        value_len: u16,
        value: impl FnOnce(&mut Octs) -> Result<(), Octs::AppendError>
    ) -> Result<(), PushError>
    where Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> {
        // If octets is emtpy, we can just append ourselves and be done.
        if self.octets.as_ref().is_empty() {
            self.octets.append_slice(
                &u32::from(u32::COMPOSE_LEN).to_ne_bytes()
            )?;
            key.compose(&mut self.octets)?;
            value_len.compose(&mut self.octets)?;
            (value)(&mut self.octets)?;
            u32::MAX.compose(&mut self.octets)?;
            return Ok(())
        }

        // Where will this value start? This also serves as a check whether
        // we have become too long.
        let start = u32::try_from(self.octets.as_ref().len()).map_err(|_|
            PushError::ShortBuf
        )?;

        // Go over the values and find the predecessor and successor.
        let mut pre = None;
        let mut next = None;
        let mut parser = Parser::from_ref(self.octets.as_ref());

        // Skip the first pointer.
        parser.advance(u32::COMPOSE_LEN.into()).unwrap();

        while parser.remaining() > 0 {
            let tmp_start = u32::try_from(parser.pos()).unwrap();
            let tmp = UnknownSvcParam::parse_param(&mut parser).unwrap();
            let tmp_end = u32::try_from(parser.pos()).unwrap();
            let tmp_key = tmp.key();
            match tmp_key.cmp(&key) {
                Ordering::Equal => return Err(PushError::DuplicateKey),
                Ordering::Less => {
                    match pre {
                        Some((key, _)) => {
                            if tmp_key > key {
                                pre = Some((tmp_key, tmp_end));
                            }
                        }
                        None => {
                            pre = Some((tmp_key, tmp_end))
                        }
                    }
                }
                Ordering::Greater => {
                    match next {
                        Some((key, _)) => {
                            if tmp_key < key {
                                next = Some((tmp_key, tmp_start));
                            }
                         }
                        None => {
                            next = Some((tmp_key, tmp_start))
                        }
                    }
                }
            }
            parser.advance(u32::COMPOSE_LEN.into()).unwrap();
        }

        // Append the value.
        key.compose(&mut self.octets)?;
        value_len.compose(&mut self.octets)?;
        (value)(&mut self.octets)?;

        // Append the pointer to the next value. MAX means none.
        self.octets.append_slice(
            &next.map(|(_, pos)| pos).unwrap_or(u32::MAX).to_ne_bytes()
        )?;

        // Replace the predecessor’s point with our start. If there is no
        // predecessor, we are the first item.
        let pos = pre.map(|(_, pos)| {
            // The u32 here was made from a usize so converting it back has to
            // work.
            usize::try_from(pos).unwrap()
        }).unwrap_or(0);
        self.octets.as_mut()[
            pos..pos + usize::from(u32::COMPOSE_LEN)
        ].copy_from_slice(
            &start.to_ne_bytes()
        );

        Ok(())
    }

    /// Freezes the builder to a parameter sequence.
    ///
    /// Because the values may need to be resorted, this method actually
    /// produces a new octets sequence. This is why it doesn’t consume the
    /// builder and may fail if the target octet’s builder can’t provide
    /// enough space.
    pub fn freeze<Target>(
        &self
    ) -> Result<
        SvcParams<Target>,
        <<Target as FromBuilder>::Builder as OctetsBuilder>::AppendError
    >
    where
        Octs: AsRef<[u8]>,
        Target: FromBuilder,
        <Target as FromBuilder>::Builder: OctetsBuilder + EmptyBuilder
    {
        let mut target = <Target as FromBuilder>::Builder::empty();
        if !self.octets.as_ref().is_empty() {
            let mut parser = Parser::from_ref(self.octets.as_ref());
            loop {
                let pos = u32::from_ne_bytes(
                    Parse::parse(&mut parser).unwrap()
                );
                if pos == u32::MAX {
                    break;
                }
                let pos = usize::try_from(pos).unwrap();
                parser.seek(pos).unwrap();
                let param = UnknownSvcParam::parse_param(&mut parser).unwrap();
                param.compose_param(&mut target)?;
            }
        }
        Ok(unsafe {
            SvcParams::from_octets_unchecked(
                Target::from_builder(target)
            )
        })
    }
}

//============ Error Types ===================================================

//------------ SvcParamsError -----------------------------------------------

/// An octets sequence was not a valid service bindings parameter sequence.
pub struct SvcParamsError(ParseError);

impl From<ShortInput> for SvcParamsError {
    fn from(err: ShortInput) -> Self {
        ParseError::from(err).into()
    }
}
    
impl From<ParseError> for SvcParamsError {
    fn from(err: ParseError) -> Self {
        SvcParamsError(err)
    }
}

impl From<SvcParamsError> for ParseError {
    fn from(err: SvcParamsError) -> Self {
        err.0
    }
}

//------------ LongSvcParam --------------------------------------------------

/// The octets sequence to be used for record data is too long.
#[derive(Clone, Copy, Debug)]
pub struct LongSvcParam(());

impl LongSvcParam {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        "service parameter too long"
    }

    pub fn check_len(len: usize) -> Result<(), Self> {
        if len > usize::from(u16::MAX) {
            Err(LongSvcParam(()))
        } else {
            Ok(())
        }
    }
}

impl From<LongSvcParam> for ParseError {
    fn from(src: LongSvcParam) -> Self {
        ParseError::form_error(src.as_str())
    }
}

impl fmt::Display for LongSvcParam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongSvcParam {}


//------------ PushError -----------------------------------------------------

/// An error happened when pushing values to a parameters builder.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum PushError {
    /// A value with this key is already present.
    DuplicateKey,

    /// The octets builder does not have enough space to append the value.
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for PushError {
    fn from(_: T) -> Self {
        PushError::ShortBuf
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PushError::DuplicateKey => f.write_str("duplicate key"),
            PushError::ShortBuf => ShortBuf.fmt(f)
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushError {}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::value;
    use octseq::array::Array;

    type Octets512 = Array<512>;
    type Params512 = SvcParams<Array<512>>;
    type Builder512 = SvcParamsBuilder<Array<512>>;

    fn octets512(slice: impl AsRef<[u8]>) -> Octets512 {
        Octets512::try_from(slice.as_ref()).unwrap()
    }


    //--- Test vectors from the draft.
    //
    // We’re only testing the parameter portion here.

    macro_rules! parse_compose {
        ( $rdata:expr, [ $( $value:expr )* ] ) => {
            // parse test
            let mut parser = Parser::from_ref($rdata.as_ref());
            let params = SvcParams::parse(&mut parser).unwrap();

            let mut param_iter = params.iter_all();
            $(
                assert_eq!(
                    param_iter.next().unwrap().unwrap(),
                    AllValues::<Octets512>::from($value)
                );
            )*
            assert_eq!(None, param_iter.next());

            // compose test
            let built = Params512::from_values(|_builder| {
                $(
                    _builder.push(&$value).unwrap();
                )*
                Ok(())
            }).unwrap();
            let mut buf = Octets512::new();
            built.compose(&mut buf).unwrap();
            assert_eq!($rdata.as_ref(), buf.as_ref());
        }
    }

    #[test]
    fn test_vectors_alias() {
        parse_compose!(b"", []);
    }

    #[test]
    fn test_vectors_port_only() {
        parse_compose!(
            b"\x00\x03\
              \x00\x02\
              \x00\x35",
            [ value::Port::new(53) ]
        );
    }

    #[test]
    fn test_vectors_unknown_param() {
        parse_compose!(
            b"\x02\x9b\
              \x00\x05\
              \x68\x65\x6c\x6c\x6f",
            [
                UnknownSvcParam::new(
                    0x029b.into(),
                    octets512(b"hello")
                ).unwrap()
            ]
        );
    }

    #[test]
    fn test_vectors_unknown_param_quote() {
        parse_compose!(
            b"\x02\x9b\
              \x00\x09\
              \x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f",
            [
                UnknownSvcParam::new(
                    0x029b.into(),
                    octets512(b"\x68\x65\x6c\x6c\x6f\xd2\x71\x6f\x6f"),
                ).unwrap()
            ]
        );
    }

    #[test]
    fn test_vectors_ipv6hint() {
        use crate::base::net::Ipv6Addr;
        use core::str::FromStr;

        parse_compose!(
            b"\x00\x06\
              \x00\x20\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x00\x00\x01\
              \x20\x01\x0d\xb8\x00\x00\x00\x00\
              \x00\x00\x00\x00\x00\x53\x00\x01",
            [
                value::Ipv6Hint::<Octets512>::from_addrs([
                    Ipv6Addr::from_str("2001:db8::1").unwrap(),
                    Ipv6Addr::from_str("2001:db8::53:1").unwrap(),
                ]).unwrap()
            ]
        );
    }

    #[test]
    fn test_vectors_ipv6hint_v4mapped() {
        use crate::base::net::Ipv6Addr;
        use core::str::FromStr;

        parse_compose!(
            b"\x00\x06\
              \x00\x10\
              \x00\x00\x00\x00\x00\x00\x00\x00\
              \x00\x00\xff\xff\xc6\x33\x64\x64",
            [
                value::Ipv6Hint::<Octets512>::from_addrs([
                    Ipv6Addr::from_str("::ffff:198.51.100.100").unwrap(),
                ]).unwrap()
            ]
        );
    }

    // test vector key_sorting: see builder tests below
    // test vector alpn_escape: see super::value::test

    #[cfg(feature = "std")]
    #[test]
    fn test_representation() {
        let mandatory = value::Mandatory::<Octets512>::from_keys(
            [
                SvcParamKey::ALPN,
                SvcParamKey::IPV4HINT,
                SvcParamKey::PRIVATE_RANGE_BEGIN.into()
            ].into_iter()
        ).unwrap();
        assert_eq!(
            "mandatory=alpn,ipv4hint,key65280",
            format!("{}", mandatory)
        );

        let mut alpn_builder = value::AlpnBuilder::<Octets512>::empty();
        alpn_builder.push("h2").unwrap();
        alpn_builder.push("h3-19").unwrap();
        assert_eq!(
            "alpn=h2,h3-19",
            format!("{}", alpn_builder.freeze())
        );

        assert_eq!("nodefaultalpn", format!("{}", value::NoDefaultAlpn));

        assert_eq!(
            "ech",
            format!(
                "{}",
                value::Ech::from_octets(Octets512::new()).unwrap()
            )
        );

        assert_eq!(
            "ipv4hint=192.0.2.1,192.0.2.2",
            format!(
                "{}",
                value::Ipv4Hint::<Octets512>::from_addrs(
                    [
                        [192, 0, 2, 1].into(), [192, 0, 2, 2].into()
                    ]
                ).unwrap()
            )
        );
    }


    //--- Builder

    #[test]
    fn empty_builder() {
        assert_eq!(
            Builder512::empty().freeze::<Octets512>().unwrap().as_slice(),
            b""
        );
    }

    #[test]
    fn one_value() {
        let mut builder = Builder512::empty();
        builder.push(&value::Port::new(53)).unwrap();
        assert_eq!(
            builder.freeze::<Octets512>().unwrap().as_slice(),
            b"\x00\x03\x00\x02\x00\x35"
        );
    }

    #[test]
    fn three_values_in_order() {
        let mut builder = Builder512::empty();
        builder.push(
            &UnknownSvcParam::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcParam::new(2.into(), b"224").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcParam::new(8.into(), b"225").unwrap()
        ).unwrap();
        assert_eq!(
            builder.freeze::<Octets512>().unwrap().as_slice(),
            b"\x00\x01\x00\x03223\
              \x00\x02\x00\x03224\
              \x00\x08\x00\x03225"
        );
    }

    #[test]
    fn three_values_out_of_order() {
        let mut builder = Builder512::empty();
        builder.push(
            &UnknownSvcParam::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcParam::new(8.into(), b"225").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcParam::new(2.into(), b"224").unwrap()
        ).unwrap();
        assert_eq!(
            builder.freeze::<Octets512>().unwrap().as_slice(),
            b"\x00\x01\x00\x03223\
              \x00\x02\x00\x03224\
              \x00\x08\x00\x03225"
        );
    }

    #[test]
    fn three_values_with_collision() {
        let mut builder = Builder512::empty();
        builder.push(
            &UnknownSvcParam::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcParam::new(8.into(), b"225").unwrap()
        ).unwrap();
        assert!(
            builder.push(
                &UnknownSvcParam::new(8.into(), b"224").unwrap()
            ).is_err()
        );
    }
}

