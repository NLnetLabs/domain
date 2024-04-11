//! The SCVB/HTTPS record data.
//!
//! This is a private module. It’s public types are re-exported by the
//! parent.
use super::SvcParams;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedDname, ToDname};
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
use core::{cmp, fmt, hash};
use core::marker::PhantomData;

//------------ Svcb and Https ------------------------------------------------

/// Service binding record data.
///
/// This type provides the record data for the various service binding record
/// types. The particular record type is encoded via the `Variant` type
/// argument with marker types representing the concrete types. Currently
/// these are `ScvbVariant` for the SVCB record type and `HttpsVariant` for
/// HTTPS. The aliases `Svcb<..>` and `Https<..>` are available for less
/// typing.
///
/// The service binding record data contains three fields: a integer
/// priority, a target name – the type of which is determined by the `Name`
/// type argument –, and a sequence of service parameters. A separate type
/// [`SvcParams`] has been defined for those which is generic over an
/// octets sequence determined by the `Octs` type argument.
///
/// The record can be used in one of two modes, ‘alias mode’ or ‘service
/// mode.’
///
/// In alias mode, there should only be one record with its priority set to
/// 0 and no service parameters. In this case, the target name indicates the
/// name that actually provides the service and should be resolved further.
/// The root name can be used as the target name to indicate that the
/// particular service is not being provided.
///
/// In ‘service mode,’ one or more records can exist and used in the order
/// provided by the priority field with lower priority looked at first. Each
/// record describes an alternative endpoint for the service and parameters
/// for its use. What exactly this means depends on the protocol in question.
///
/// The owner name of service binding records determines which service the
/// records apply to. The domain name for which the service is provided is
/// prefixed by first the port and protocol of the service, both as
/// underscore labels. So, for HTTPS on port 443, the prefix would be
/// `_443._https`. However, the HTTPS record type allows to drop the prefix
/// in that particular case.
///
/// Note that the above is a wholy inadequate summary of service bindings
/// records. For accurate details, see
/// [draft-ietf-dnsop-svcb-https](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https/).
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
    /// The priority field of the service binding record.
    priority: u16,

    /// The target field of the service binding record.
    target: Name,

    /// The parameters field of the service binding record.
    params: SvcParams<Octs>,

    /// A marker for the variant.
    marker: PhantomData<Variant>,
}

/// The marker type for the SVCB record type.
///
/// Use this as the `Variant` type argument of the
/// [`SvcbRdata<..>`][SvcbRdata] type to select an SVCB record.
#[derive(Clone, Copy, Debug)]
pub struct SvcbVariant;

/// The marker type for the HTTPS record type.
///
/// Use this as the `Variant` type argument of the
/// [`SvcbRdata<..>`][SvcbRdata] type to select an HTTPS record.
#[derive(Clone, Copy, Debug)]
pub struct HttpsVariant;

/// A type alias for record data of the SVCB record type.
///
/// The SVCB record type is the generic type for service bindings of any
/// service for which no special record type exists.
///
/// See [`SvcbRdata<..>`][SvcbRdata] for details.
pub type Svcb<Octs, Name> = SvcbRdata<SvcbVariant, Octs, Name>;

/// A type alias for record data of the HTTPS record type.
///
/// The HTTPS record type is the service binding type for the HTTPS service.
///
/// See [`SvcbRdata<..>`][SvcbRdata] for details.
pub type Https<Octs, Name> = SvcbRdata<HttpsVariant, Octs, Name>;

impl SvcbRdata<SvcbVariant, (), ()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::SVCB;
}

impl SvcbRdata<HttpsVariant, (), ()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::HTTPS;
}

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
}

impl<Variant, Octs: AsRef<[u8]>> SvcbRdata<Variant, Octs, ParsedDname<Octs>> {
    /// Parses service bindings record data from its wire format.
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
    /// Returns the priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns whether this service binding is in alias mode.
    ///
    /// This is identical to `self.priority() == 0`.
    pub fn is_alias(&self) -> bool {
        self.priority == 0
    }

    /// Returns whether this service binding is in service mode.
    ///
    /// This is identical to `self.priority() != 0`.
    pub fn is_service(&self) -> bool {
        self.priority != 0
    }

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

    pub(crate) fn flatten<TOcts, TName>(
        self,
    ) -> Result<SvcbRdata<Variant, TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        Name: FlattenInto<TName, AppendError = TOcts::Error>,
    {
        Ok(unsafe {
            SvcbRdata::new_unchecked(
                self.priority,
                self.target.try_flatten_into()?,
                self.params.try_octets_into()?,
            )
        })
    }
}

//--- OctetsFrom and FlattenInto

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

impl<Variant, Octs, TOcts, Name, TName>
    FlattenInto<SvcbRdata<Variant, TOcts, TName>>
    for SvcbRdata<Variant, Octs, Name>
where
    TOcts: OctetsFrom<Octs>,
    Name: FlattenInto<TName, AppendError = TOcts::Error>
{
    type AppendError = TOcts::Error;

    fn try_flatten_into(
        self
    ) -> Result<SvcbRdata<Variant, TOcts, TName>, TOcts::Error> {
        self.flatten()
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

impl<Variant, OtherVariant, Octs, OtherOcts, Name, OtherName>
    CanonicalOrd<SvcbRdata<OtherVariant, OtherOcts, OtherName>>
for SvcbRdata<Variant, Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToDname,
    OtherName: ToDname,
{
    fn canonical_cmp(
        &self, other: &SvcbRdata<OtherVariant, OtherOcts, OtherName>
    ) -> cmp::Ordering {
        match self.priority.cmp(&other.priority) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        match self.target.name_cmp(&other.target) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        self.params.canonical_cmp(&other.params)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs, Name> RecordData for SvcbRdata<SvcbVariant, Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::SVCB
    }
}

impl<Octs, Name> RecordData for SvcbRdata<HttpsVariant, Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::HTTPS
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
for SvcbRdata<SvcbVariant, Octs::Range<'a>, ParsedDname<Octs::Range<'a>>> {
    fn parse_rdata(
        rtype: Rtype, parser: &mut Parser<'a, Octs>
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::SVCB {
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
        if rtype == Rtype::HTTPS {
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
                assert_eq!(0x029b, param.key().to_int());
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

