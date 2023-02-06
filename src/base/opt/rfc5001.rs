/// EDNS0 Options from RFC 5001.

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;
use core::{borrow, fmt, hash, str};
use core::cmp::Ordering;


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Copy, Debug)]
pub struct Nsid<Octs: ?Sized> {
    octets: Octs,
}

impl<Octs> Nsid<Octs> {
    pub fn from_octets(octets: Octs) -> Self {
        Nsid { octets }
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len).map(Nsid::from_octets).map_err(Into::into)
    }
}

impl Nsid<[u8]> {
    pub fn from_slice(slice: &[u8]) -> &Self {
        unsafe { &*(slice as *const [u8] as *const Self) }
    }

    pub fn from_slice_mut(slice: &mut [u8]) -> &mut Self {
        unsafe { &mut *(slice as *mut [u8] as *mut Self) }
    }
}

impl<Octs: ?Sized> Nsid<Octs> {
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octs: AsMut<[u8]>,
    {
        self.octets.as_mut()
    }

    pub fn for_slice(&self) -> &Nsid<[u8]>
    where
        Octs: AsRef<[u8]>
    {
        Nsid::from_slice(self.octets.as_ref())
    }

    pub fn for_slice_mut(&mut self) -> &mut Nsid<[u8]>
    where
        Octs: AsMut<[u8]>
    {
        Nsid::from_slice_mut(self.octets.as_mut())
    }
}

//--- AsRef, AsMut, Borrow, BorrowMut

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for Nsid<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]> + ?Sized> AsMut<[u8]> for Nsid<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> borrow::Borrow<[u8]> for Nsid<Octs> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs> borrow::BorrowMut<[u8]> for Nsid<Octs>
where
    Octs: AsMut<[u8]> + AsRef<[u8]> + ?Sized
{
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- OptData etc.

impl<Octs: ?Sized> OptData for Nsid<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::Nsid
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for Nsid<Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Nsid {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ComposeOptData for Nsid<Octs> {
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Nsid<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5001 § 2.4:
        // | User interfaces MUST read and write the contents of the NSID
        // | option as a sequence of hexadecimal digits, two digits per
        // | payload octet.
        for v in self.octets.as_ref() {
            write!(f, "{:X} ", *v)?;
        }
        if let Ok(s) = str::from_utf8(self.octets.as_ref()) {
            write!(f, "({})", s)?;
        }
        Ok(())
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Other> for Nsid<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Other) -> bool {
        self.as_slice().eq(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Nsid<Octs> { }

//--- PartialOrd and Ord

impl<Octs, Other> PartialOrd<Other> for Nsid<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &Other) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for Nsid<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for Nsid<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn nsid(
        &mut self, data: &(impl AsRef<[u8]> + ?Sized)
    ) -> Result<(), Target::AppendError> {
        self.push(Nsid::from_slice(data.as_ref()))
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    fn nsid_compose_parse() {
        test_option_compose_parse(
            &Nsid::from_octets("foo"),
            |parser| Nsid::parse(parser)
        );
    }
}
