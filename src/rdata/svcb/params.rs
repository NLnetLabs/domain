use super::value::AllValues;
use crate::base::iana::SvcbParamKey;
use crate::base::scan::Symbol;
use crate::base::wire::{Compose, Parse, ParseError};
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, ShortBuf};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::{Parser, ShortInput};
use core::{cmp, fmt, hash};
use core::cmp::Ordering;
use core::marker::PhantomData;

//------------ SvcbParams ----------------------------------------------------

#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SvcbParams<Octs: ?Sized> {
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

impl<Octs> SvcbParams<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, SvcbParamsError>
    where Octs: AsRef<[u8]> {
        SvcbParams::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a new value from an octets sequence without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `octets` contains a properly formatted
    /// SVCB params value.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        SvcbParams { octets }
    }
}

impl SvcbParams<[u8]> {
    pub fn from_slice(slice: &[u8]) -> Result<&Self, SvcbParamsError> {
        SvcbParams::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a new value from a slice without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `slice` contains a properly formatted
    /// SVCB params value.
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Self)
    }

    fn check_slice(slice: &[u8]) -> Result<(), SvcbParamsError> {
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

impl<Octs> SvcbParams<Octs> {
    pub fn from_values<F>(op: F) -> Result<Self, PushError>
    where
        Octs: FromBuilder,
        <Octs  as FromBuilder>::Builder:
            AsRef<[u8]> + OctetsBuilder + EmptyBuilder,
        F: FnOnce(
            &mut SvcbParamsBuilder<<Octs  as FromBuilder>::Builder>
        ) -> Result<(), PushError>,
    {
        let mut res = SvcbParamsBuilder::empty();
        op(&mut res)?;
        res.freeze().map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]>> SvcbParams<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        Self::from_octets(
            parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }
}

impl<Octs: ?Sized> SvcbParams<Octs> {
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> SvcbParams<Octs> {
    pub fn as_slice(&self) -> &[u8] {
        self.octets.as_ref()
    }

    pub fn for_slice(&self) -> &SvcbParams<[u8]> {
        unsafe { SvcbParams::from_slice_unchecked(self.octets.as_ref()) }
    }

    pub fn len(&self) -> usize {
        self.octets.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.octets.as_ref().is_empty()
    }

    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }

    pub fn iter<Value>(&self) -> ValueIter<Octs, Value> {
        ValueIter::new(self.as_octets())
    }

    pub fn iter_all(&self) -> ValueIter<Octs, AllValues<Octs>>
    where Octs: Sized {
        self.iter()
    }
}

//--- OctetsFrom

impl<SrcOcts, Octs> OctetsFrom<SvcbParams<SrcOcts>> for SvcbParams<Octs>
where Octs: OctetsFrom<SrcOcts> {
    type Error = Octs::Error;

    fn try_octets_from(
        src: SvcbParams<SrcOcts>
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            SvcbParams::from_octets_unchecked(src.octets.try_octets_into()?)
        })
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts> PartialEq<SvcbParams<OtherOcts>> for SvcbParams<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &SvcbParams<OtherOcts>) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for SvcbParams<Octs> { }

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for SvcbParams<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- PartialOrd and Ord

impl<Octs, OtherOcts> PartialOrd<SvcbParams<OtherOcts>> for SvcbParams<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    OtherOcts: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(
        &self, other: &SvcbParams<OtherOcts>
    ) -> Option<cmp::Ordering> {
        self.as_slice().partial_cmp(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for SvcbParams<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Display and Debug

impl<Octs: Octets + ?Sized> fmt::Display for SvcbParams<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parser = Parser::from_ref(self.as_slice());
        while parser.remaining() > 0 {
            let key = SvcbParamKey::parse(
                &mut parser
            ).expect("invalid SvcbParam");
            let len = usize::from(
                u16::parse(&mut parser).expect("invalid SvcbParam")
            );
            let mut parser = parser.parse_parser(
                len
            ).expect("invalid SvcbParam");
            write!(
                f, "{}", super::value::AllValues::parse_any(key, &mut parser)
            )?;
        };
        Ok(())
    }
}

impl<Octs: Octets + ?Sized> fmt::Debug for SvcbParams<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SvcbParams").field(
            &format_args!("{}", self)
        ).finish()
    }
}


//------------ ValueIter -----------------------------------------------------

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
        Value: ParseSvcbValue<'a, Octs>,
    {
        let key = SvcbParamKey::parse(&mut self.parser)?;
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
    Value: ParseSvcbValue<'a, Octs>,
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

//------------ SvcbValue, ParseSvcbValue, ComposeSvcbValue -------------------

pub trait SvcbValue {
    fn key(&self) -> SvcbParamKey;
}

pub trait ParseSvcbValue<'a, Octs: ?Sized>: SvcbValue + Sized {
    fn parse_value(
        key: SvcbParamKey, parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError>;
}

pub trait ComposeSvcbValue: SvcbValue {
    fn compose_len(&self) -> u16;

    fn compose_value<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target,
    ) -> Result<(), Target::AppendError>;
}

//------------ UnknownSvcbValue ----------------------------------------------

#[derive(Clone, Debug)]
pub struct UnknownSvcbValue<Octs> {
    /// The key of the value.
    key: SvcbParamKey,

    /// The octets of the value.
    value: Octs,
}

impl<Octs> UnknownSvcbValue<Octs> {
    /// Creates a new SVCB parameter value from the given key and data.
    pub fn new(key: SvcbParamKey, value: Octs) -> Result<Self, LongSvcbValue>
    where Octs: AsRef<[u8]> {
        LongSvcbValue::check_len(value.as_ref().len())?;
        Ok(unsafe { Self::new_unchecked(key, value) })
    }

    /// Creates a new SVCB parameter value without checking.
    ///
    /// # Safety
    ///
    /// The called needs to make sure that `value` is not longer than
    /// 65,535 octets.
    pub unsafe fn new_unchecked(key: SvcbParamKey, value: Octs) -> Self {
        UnknownSvcbValue { key, value }
    }
}

impl<Octs: AsRef<[u8]>> UnknownSvcbValue<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        key: SvcbParamKey,
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Self::new(
            key, parser.parse_octets(parser.remaining())?
        ).map_err(Into::into)
    }

    pub fn parse_param<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let key = SvcbParamKey::parse(parser)?;
        let len = usize::from(u16::parse(parser)?);
        let value = parser.parse_octets(len)?;
        Ok(unsafe { Self::new_unchecked(key, value) })
    }

    pub fn compose_param<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.key.compose(target)?;
        self.compose_len().compose(target)?;
        self.compose_value(target)
    }
}

impl<Octs> UnknownSvcbValue<Octs> {
    /// Returns the key of the value.
    pub fn key(&self) -> SvcbParamKey {
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

impl<Octs> AsRef<Octs> for UnknownSvcbValue<Octs> {
    fn as_ref(&self) -> &Octs {
        self.value()
    }
}

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for UnknownSvcbValue<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]>> AsMut<[u8]> for UnknownSvcbValue<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts> PartialEq<UnknownSvcbValue<OtherOcts>>
for UnknownSvcbValue<Octs>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
{
    fn eq(&self, other: &UnknownSvcbValue<OtherOcts>) -> bool {
        self.as_slice().eq(other.as_slice())
    }
}

impl<Octs: AsRef<[u8]>> Eq for UnknownSvcbValue<Octs> { }

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for UnknownSvcbValue<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- SvcbValue et al.

impl<Octs> SvcbValue for UnknownSvcbValue<Octs> {
    fn key(&self) -> SvcbParamKey {
        self.key
    }
}

impl<'a, Octs: Octets + ?Sized> ParseSvcbValue<'a, Octs>
for UnknownSvcbValue<Octs::Range<'a>> {
    fn parse_value(
        key: SvcbParamKey,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        Self::new(
            key, parser.parse_octets(parser.remaining())?
        ).map(Some).map_err(Into::into)
    }
}

impl<Octs: AsRef<[u8]>> ComposeSvcbValue for UnknownSvcbValue<Octs> {
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

impl<Octs: AsRef<[u8]>> fmt::Display for UnknownSvcbValue<Octs> {
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


//------------ SvcbParamsBuilder ---------------------------------------------

#[derive(Clone, Debug)]
pub struct SvcbParamsBuilder<Octs> {
    octets: Octs,
}

impl<Octs> SvcbParamsBuilder<Octs> {
    pub fn empty() -> Self
    where Octs: EmptyBuilder {
        Self { octets: Octs::empty() }
    }

    pub fn from_params<Src: Octets + ?Sized>(
        params: &SvcbParams<Src>
    ) -> Result<Self, ShortBuf>
    where Octs: AsRef<[u8]> + OctetsBuilder + EmptyBuilder {
        let mut octets = Octs::empty();
        for item in params.iter::<UnknownSvcbValue<_>>() {
            let item = item.expect("invalid SvcbParams");
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

    pub fn push(
        &mut self, value: &impl ComposeSvcbValue
    ) -> Result<(), PushError>
    where Octs: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> {
        // If octets is emtpy, we can just append ourselves and be done.
        if self.octets.as_ref().is_empty() {
            self.octets.append_slice(
                &u32::from(u32::COMPOSE_LEN).to_ne_bytes()
            )?;
            value.key().compose(&mut self.octets)?;
            value.compose_len().compose(&mut self.octets)?;
            value.compose_value(&mut self.octets)?;
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
            let tmp = UnknownSvcbValue::parse_param(&mut parser).unwrap();
            let tmp_end = u32::try_from(parser.pos()).unwrap();
            let tmp_key = tmp.key();
            match tmp_key.cmp(&value.key()) {
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
        value.key().compose(&mut self.octets)?;
        value.compose_len().compose(&mut self.octets)?;
        value.compose_value(&mut self.octets)?;

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

    pub fn freeze<Target>(
        &self
    ) -> Result<
        SvcbParams<Target>,
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
                let param = UnknownSvcbValue::parse_param(&mut parser).unwrap();
                param.compose_param(&mut target)?;
            }
        }
        Ok(unsafe {
            SvcbParams::from_octets_unchecked(
                Target::from_builder(target)
            )
        })
    }
}

//============ Error Types ===================================================

//------------ SvcbParamsError -----------------------------------------------

pub struct SvcbParamsError(ParseError);

impl From<ShortInput> for SvcbParamsError {
    fn from(err: ShortInput) -> Self {
        ParseError::from(err).into()
    }
}
    
impl From<ParseError> for SvcbParamsError {
    fn from(err: ParseError) -> Self {
        SvcbParamsError(err)
    }
}

impl From<SvcbParamsError> for ParseError {
    fn from(err: SvcbParamsError) -> Self {
        err.0
    }
}

//------------ LongSvcbValue -------------------------------------------------

/// The octets sequence to be used for record data is too long.
#[derive(Clone, Copy, Debug)]
pub struct LongSvcbValue();

impl LongSvcbValue {
    pub fn as_str(self) -> &'static str {
        "SVCB parameter too long"
    }

    pub fn check_len(len: usize) -> Result<(), Self> {
        if len > usize::from(u16::MAX) {
            Err(LongSvcbValue())
        } else {
            Ok(())
        }
    }
}

impl From<LongSvcbValue> for ParseError {
    fn from(src: LongSvcbValue) -> Self {
        ParseError::form_error(src.as_str())
    }
}

impl fmt::Display for LongSvcbValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongSvcbValue {}


//------------ PushError -----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum PushError {
    DuplicateKey,
    ShortBuf,
}

impl<T: Into<ShortBuf>> From<T> for PushError {
    fn from(_: T) -> Self {
        PushError::ShortBuf
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::value;
    use octseq::array::Array;

    type Octets512 = Array<512>;
    type Params512 = SvcbParams<Array<512>>;
    type Builder512 = SvcbParamsBuilder<Array<512>>;

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
            let params = SvcbParams::parse(&mut parser).unwrap();

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
                UnknownSvcbValue::new(
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
                UnknownSvcbValue::new(
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
        use crate::base::iana::svcb::SVCB_PARAM_KEY_PRIVATE_RANGE_BEGIN;

        let mandatory = value::Mandatory::<Octets512>::from_keys(
            [
                SvcbParamKey::Alpn,
                SvcbParamKey::Ipv4Hint,
                SVCB_PARAM_KEY_PRIVATE_RANGE_BEGIN.into()
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
                    ].into_iter()
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
            &UnknownSvcbValue::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcbValue::new(2.into(), b"224").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcbValue::new(8.into(), b"225").unwrap()
        ).unwrap();
        eprintln!("{:?}", builder.octets);
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
            &UnknownSvcbValue::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcbValue::new(8.into(), b"225").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcbValue::new(2.into(), b"224").unwrap()
        ).unwrap();
        eprintln!("{:?}", builder.octets);
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
            &UnknownSvcbValue::new(1.into(), b"223").unwrap()
        ).unwrap();
        builder.push(
            &UnknownSvcbValue::new(8.into(), b"225").unwrap()
        ).unwrap();
        assert!(
            builder.push(
                &UnknownSvcbValue::new(8.into(), b"224").unwrap()
            ).is_err()
        );
    }
}

