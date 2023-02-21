use super::SvcParams;
use crate::base::iana::Rtype;
use crate::base::name::{
    Dname, ParsedDname, PushError as PushNameError, ToDname
};
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use octseq::builder::{EmptyBuilder, FromBuilder};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
use core::{cmp, fmt, hash};
use core::marker::PhantomData;

//------------ Svcb and Https ------------------------------------------------

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        bound(
            serialize = "
                Name: serde::Serialize,
                Octs: octseq::serde::SerializeOctets
            ",
            deserialize = "
                Name: serde::Deserialize<'de>,
                Octs: octseq::serde::DeserializeOctets<'de>
            ",
        )
    )
)]
pub struct SvcbRdata<Variant, Octs, Name> {
    priority: u16,
    target: Name,
    params: SvcParams<Octs>,
    marker: PhantomData<Variant>,
}

#[derive(Clone, Copy, Debug)]
pub struct SvcbVariant;

#[derive(Clone, Copy, Debug)]
pub struct HttpsVariant;

pub type Svcb<Octs, Name> = SvcbRdata<SvcbVariant, Octs, Name>;
pub type Https<Octs, Name> = SvcbRdata<HttpsVariant, Octs, Name>;

impl<Variant, Octs, Name> SvcbRdata<Variant, Octs, Name> {
    /// Create a new value from its components.
    ///
    /// Returns an error if the wire format of the record data would exceed
    /// the length of 65,535 octets.
    pub fn new(
        priority: u16, target: Name, params: SvcParams<Octs>
    ) -> Result<Self, LongRecordData>
    where Octs: AsRef<[u8]>, Name: ToDname {
        LongRecordData::check_len(
            usize::from(
                u16::COMPOSE_LEN + target.compose_len()
            ).checked_add(params.len()).expect("long params")
        )?;
        Ok( unsafe { Self::new_unchecked(priority, target, params) })
    }

    /// Creates a new value from its components without checking.
    ///
    /// # Safety
    ///
    /// The called must ensure that the wire format of the record data does
    /// not exceed a length of 65,535 octets.
    pub unsafe fn new_unchecked(
        priority: u16, target: Name, params: SvcParams<Octs>
    ) -> Self {
        SvcbRdata { priority, target, params, marker: PhantomData }
    }

    /// Returns the priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }
}

impl<Variant, Octs: AsRef<[u8]>> SvcbRdata<Variant, Octs, ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let priority = u16::parse(parser)?;
        let target = ParsedDname::parse(parser)?;
        let params = SvcParams::parse(parser)?;
        Ok(unsafe {
            Self::new_unchecked(priority, target, params)
        })
    }
}

impl<Variant, Octs, Name> SvcbRdata<Variant, Octs, Name> {
    /// Returns the target name.
    ///
    /// Note the target name won't be translated to the owner automatically
    /// in service mode if it equals the root name.
    pub fn target(&self) -> &Name {
        &self.target
    }

    /// Returns the parameters.
    pub fn params(&self) -> &SvcParams<Octs> {
        &self.params
    }

    /// Returns an identical value using different octets sequence types.
    pub(crate) fn convert_octets<TOcts, TName>(
        self
    ) -> Result<SvcbRdata<Variant, TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        TName: OctetsFrom<Name, Error = TOcts::Error>,
    {
        Ok(unsafe {
            SvcbRdata::new_unchecked(
                self.priority,
                self.target.try_octets_into()?,
                self.params.try_octets_into()?,
            )
        })
    }
}

impl<Variant, Octs, NOcts> SvcbRdata<Variant, Octs, ParsedDname<NOcts>> {
    /// Flattens a value using a parsed name into a flat name.
    pub fn flatten_into<Target>(
        self
    ) -> Result<SvcbRdata<Variant, Target, Dname<Target>>, PushNameError>
    where
        NOcts: Octets,
        Target: OctetsFrom<Octs>
            + for<'a> OctetsFrom<NOcts::Range<'a>>
            + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
    {
        Ok(unsafe {
            SvcbRdata::new_unchecked(
                self.priority,
                self.target.flatten_into()?,
                self.params.try_octets_into().map_err(Into::into)?,
            )
        })
    }
}

//--- OctetsFrom

impl<Variant, Octs, SrcOctets, Name, SrcName>
    OctetsFrom<SvcbRdata<Variant, SrcOctets, SrcName>>
    for SvcbRdata<Variant, Octs, Name>
where
    Octs: OctetsFrom<SrcOctets>,
    Name: OctetsFrom<SrcName, Error = Octs::Error>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: SvcbRdata<Variant, SrcOctets, SrcName>,
    ) -> Result<Self, Self::Error> {
        source.convert_octets()
    }
}

//--- PartialEq and Eq

impl<Variant, OtherVariant, Octs, OtherOcts, Name, OtherName>
    PartialEq<SvcbRdata<OtherVariant, OtherOcts, OtherName>>
for SvcbRdata<Variant, Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToDname,
    OtherName: ToDname,
{
    fn eq(
        &self, other: &SvcbRdata<OtherVariant, OtherOcts, OtherName>
    ) -> bool {
        self.priority == other.priority
            && self.target.name_eq(&other.target)
            && self.params == other.params
    }
}

impl<Variant, Octs: AsRef<[u8]>, Name: ToDname> Eq
for SvcbRdata<Variant, Octs, Name> { }

//--- Hash

impl<Variant, Octs: AsRef<[u8]>, Name: hash::Hash> hash::Hash
for SvcbRdata<Variant, Octs, Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.priority.hash(state);
        self.target.hash(state);
        self.params.hash(state);
    }
}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Variant, OtherVariant, Octs, OtherOcts, Name, OtherName>
    PartialOrd<SvcbRdata<OtherVariant, OtherOcts, OtherName>>
for SvcbRdata<Variant, Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToDname,
    OtherName: ToDname,
{
    fn partial_cmp(
        &self, other: &SvcbRdata<OtherVariant, OtherOcts, OtherName>
    ) -> Option<cmp::Ordering> {
        match self.priority.partial_cmp(&other.priority) {
            Some(cmp::Ordering::Equal) => { }
            other => return other
        }
        match self.target.name_cmp(&other.target) {
            cmp::Ordering::Equal => { }
            other => return Some(other)
        }
        self.params.partial_cmp(&other.params)
    }
}

impl<Variant, Octs: AsRef<[u8]>, Name: ToDname> Ord
for SvcbRdata<Variant, Octs, Name> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.priority.cmp(&other.priority) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        match self.target.name_cmp(&other.target) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        self.params.cmp(&other.params)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs, Name> RecordData for SvcbRdata<SvcbVariant, Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::Svcb
    }
}

impl<Octs, Name> RecordData for SvcbRdata<HttpsVariant, Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::Https
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
for SvcbRdata<SvcbVariant, Octs::Range<'a>, ParsedDname<Octs::Range<'a>>> {
    fn parse_rdata(
        rtype: Rtype, parser: &mut Parser<'a, Octs>
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Svcb {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
for SvcbRdata<HttpsVariant, Octs::Range<'a>, ParsedDname<Octs::Range<'a>>> {
    fn parse_rdata(
        rtype: Rtype, parser: &mut Parser<'a, Octs>
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Https{
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Variant, Octs, Name> ComposeRecordData for SvcbRdata<Variant, Octs, Name>
where Self: RecordData, Octs: AsRef<[u8]>, Name: ToDname {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::checked_add(
                u16::COMPOSE_LEN + self.target.compose_len(),
                self.params.len().try_into().expect("long params"),
            ).expect("long record data")
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.priority.compose(target)?;
        self.target.compose(target)?;
        self.params.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display and Debug

impl<Variant, Octs, Name> fmt::Display for SvcbRdata<Variant, Octs, Name>
where
    Octs: Octets,
    Name: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {}", self.priority, self.target, self.params)
    }
}

impl<Variant, Octs, Name> fmt::Debug for SvcbRdata<Variant, Octs, Name>
where
    Octs: Octets,
    Name: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SvcbRdata")
            .field("priority", &self.priority)
            .field("target", &self.target)
            .field("params", &self.params)
            .finish()
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::UnknownSvcParam;
    use super::super::value::AllValues;
    use crate::base::Dname;
    use octseq::array::Array;
    use core::str::FromStr;

    type Octets512 = Array<512>;
    type Dname512 = Dname<Array<512>>;
    type Params512 = SvcParams<Array<512>>;

    // We only do two tests here to see if the SvcbRdata type itself is
    // working properly. Tests for all the value types live in
    // super::params::test.

    #[test]
    fn test_vectors_alias() {
        let rdata =
            b"\x00\x00\
              \x03\x66\x6f\x6f\
                \x07\x65\x78\x61\x6d\x70\x6c\x65\
                \x03\x63\x6f\x6d\
                \x00\
            ";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(0, svcb.priority);
        assert_eq!(
            Dname512::from_str("foo.example.com").unwrap(),
            svcb.target
        );
        assert_eq!(0, svcb.params.len());

        // compose test
        let svcb_builder = Svcb::new(
            svcb.priority, svcb.target, Params512::default()
        ).unwrap();

        let mut buf = Octets512::new();
        svcb_builder.compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }

    #[test]
    fn test_vectors_unknown_param() {
        let rdata =
            b"\x00\x01\
              \x03\x66\x6f\x6f\
                \x07\x65\x78\x61\x6d\x70\x6c\x65\
                \x03\x63\x6f\x6d\
                \x00\
              \x02\x9b\
              \x00\x05\
              \x68\x65\x6c\x6c\x6f\
            ";

        // parse test
        let mut parser = Parser::from_ref(rdata.as_ref());
        let svcb = Svcb::parse(&mut parser).unwrap();
        assert_eq!(1, svcb.priority);
        assert_eq!(
            Dname512::from_str("foo.example.com").unwrap(),
            svcb.target
        );

        let mut param_iter = svcb.params().iter();
        match param_iter.next() {
            Some(Ok(AllValues::Unknown(param))) => {
                assert_eq!(0x029b, param.key());
                assert_eq!(b"\x68\x65\x6c\x6c\x6f".as_ref(), *param.value(),);
            }
            r => panic!("{:?}", r),
        }
        assert_eq!(None, param_iter.next());

        // compose test
        let svcb_builder = Svcb::new(
            svcb.priority, svcb.target,
            Params512::from_values(|builder| {
                builder.push(
                    &UnknownSvcParam::new(0x029b.into(), b"hello").unwrap()
                )
            }).unwrap()
        ).unwrap();
        let mut buf = Octets512::new();
        svcb_builder.compose_rdata(&mut buf).unwrap();
        assert_eq!(rdata.as_ref(), buf.as_ref());
    }
}

