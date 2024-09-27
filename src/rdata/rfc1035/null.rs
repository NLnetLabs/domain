//! Record data for the NULL record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::zonefile_fmt::{self, Presenter, ZonefileFmt};
use crate::base::wire::{Composer, ParseError};
use core::{fmt, hash, mem};
use core::cmp::Ordering;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Null ---------------------------------------------------------

/// Null record data.
///
/// Null records can contain whatever data. They are experimental and not
/// allowed in zone files.
///
/// The Null record type is defined in [RFC 1035, section 3.3.10][1].
/// 
/// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.10
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Null<Octs: ?Sized> {
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "octseq::serde::SerializeOctets::serialize_octets",
            deserialize_with = "octseq::serde::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octs: octseq::serde::SerializeOctets",
                deserialize = "Octs: octseq::serde::DeserializeOctets<'de>",
            )
        )
    )]
    data: Octs,
}

impl Null<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::NULL;
}

impl<Octs> Null<Octs> {
    /// Creates new NULL record data from the given octets.
    ///
    /// The function will fail if `data` is longer than 65,535 octets.
    pub fn from_octets(data: Octs) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
    {
        Null::check_slice(data.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(data) })
    }

    /// Creates new NULL record data without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `data` is at most 65,535 octets long.
    pub unsafe fn from_octets_unchecked(data: Octs) -> Self {
        Null { data }
    }
}

impl Null<[u8]> {
    /// Creates new NULL record data from an octets slice.
    ///
    /// The function will fail if `data` is longer than 65,535 octets.
    pub fn from_slice(data: &[u8]) -> Result<&Self, LongRecordData> {
        Self::check_slice(data)?;
        Ok(unsafe { Self::from_slice_unchecked(data) })
    }

    /// Creates new NULL record from an octets slice data without checking.
    ///
    /// # Safety
    ///
    /// The caller has to ensure that `data` is at most 65,535 octets long.
    #[must_use]
    pub unsafe fn from_slice_unchecked(data: &[u8]) -> &Self {
        // SAFETY: Null has repr(transparent)
        mem::transmute(data)
    }

    /// Checks that a slice can be used for NULL record data.
    fn check_slice(slice: &[u8]) -> Result<(), LongRecordData> {
        LongRecordData::check_len(slice.len())
    }
}

impl<Octs: ?Sized> Null<Octs> {
    /// The raw content of the record.
    pub fn data(&self) -> &Octs {
        &self.data
    }
}

impl<Octs: AsRef<[u8]>> Null<Octs> {
    pub fn len(&self) -> usize {
        self.data.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.as_ref().is_empty()
    }
}

impl<Octs> Null<Octs> {
    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Null<Target>, Target::Error> {
        Ok(unsafe {
            Null::from_octets_unchecked(self.data.try_octets_into()?)
        })
    }

    pub(in crate::rdata) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Null<Target>, Target::Error> {
        self.convert_octets()
    }
}

impl<Octs> Null<Octs> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser
            .parse_octets(len)
            .map(|res| unsafe { Self::from_octets_unchecked(res) })
            .map_err(Into::into)
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Null<SrcOcts>> for Null<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Null<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.data)
            .map(|res| unsafe { Self::from_octets_unchecked(res) })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Null<Other>) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Null<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &Null<Other>) -> Option<Ordering> {
        self.data.as_ref().partial_cmp(other.data.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Null<Other>> for Null<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &Null<Other>) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for Null<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for Null<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.data.as_ref().hash(state)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs: ?Sized> RecordData for Null<Octs> {
    fn rtype(&self) -> Rtype {
        Null::RTYPE
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Null<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Null::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ComposeRecordData for Null<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::try_from(self.data.as_ref().len()).expect("long NULL rdata"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.data.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- AsRef

impl<Octs: AsRef<Other>, Other> AsRef<Other> for Null<Octs> {
    fn as_ref(&self) -> &Other {
        self.data.as_ref()
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for Null<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.as_ref().len())?;
        for ch in self.data.as_ref().iter() {
            write!(f, " {:02x}", ch)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for Null<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Null(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//--- ZonefileFmt

impl<Octs: AsRef<[u8]>> ZonefileFmt for Null<Octs> {
    fn show(&self, p: &mut Presenter) -> zonefile_fmt::Result {
        struct Data<'a>(&'a [u8]);

        impl fmt::Display for Data<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "\\# {}", self.0.len())?;
                for ch in self.0 {
                    write!(f, " {:02x}", *ch)?
                }
                Ok(())
            }
        }

        p.write_token(Data(self.data.as_ref()))
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{test_compose_parse, test_rdlen};

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn null_compose_parse_scan() {
        let rdata = Null::from_octets("foo").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Null::parse(parser));
    }
}

