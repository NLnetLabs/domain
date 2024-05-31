//! ENDS option to provide a Name Server Identifer.
//!
//! The option in this module – [`Nsid<Octs>`] – allows a resolver to query
//! for and a server to provide an identifier for the particular server that
//! answered the query. This can be helpful when debugging a scenario where
//! multiple servers serve a common address.
//!
//! The option is defined in [RFC 5001](https://tools.ietf.org/html/rfc5001).

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{
    BuildDataError, LongOptData, Opt, OptData, ComposeOptData, ParseOptData
};
use octseq::builder::OctetsBuilder;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use core::{borrow, fmt, hash, str};
use core::cmp::Ordering;


//------------ Nsid ---------------------------------------------------------/

/// Option data for the Name Server Identifier (NSID) Option.
///
/// This option allows identifying a particular name server that has answered
/// a query. If a client is interested in this information, it includes an
/// empty NSID option in its query. If the server supports the option, it
/// includes it in its response with byte string identifying the server.
///
/// The option and details about its use are defined in
/// [RFC 5001](https://tools.ietf.org/html/rfc5001).
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Nsid<Octs: ?Sized> {
    /// The octets of the identifier.
    octets: Octs,
}

impl Nsid<()> {
    /// The option code for this option.
    pub(super) const CODE: OptionCode = OptionCode::NSID;
}
    
impl<Octs> Nsid<Octs> {
    /// Creates a value from the ocets of the name server identifier.
    ///
    /// The function returns an error if `octets` is longer than 65,535
    /// octets.
    pub fn from_octets(octets: Octs) -> Result<Self, LongOptData>
    where Octs: AsRef<[u8]> {
        LongOptData::check_len(octets.as_ref().len())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a value from the name server identifier without checking.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is no longer than 65,535
    /// octets.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Nsid { octets }
    }

    /// Parses a value from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        LongOptData::check_len(len)?;
        Ok(unsafe { Self::from_octets_unchecked(
            parser.parse_octets(len)?
        )})
    }
}

impl Nsid<[u8]> {
    /// Creates a value for a slice of the name server identifer.
    ///
    /// The function returns an error if `slice` is longer than 65,535
    /// octets.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, LongOptData> {
        LongOptData::check_len(slice.len())?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a value for a slice without checking.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is no longer than 65,535
    /// octets.
    #[must_use]
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: Nsid has repr(transparent)
        core::mem::transmute(slice)
    }

    /// Creates an empty NSID option value.
    #[must_use]
    pub fn empty() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"") }
    }
}

impl<Octs: ?Sized> Nsid<Octs> {
    /// Returns a reference to the octets with the server identifier.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    /// Converts the value into the octets with the server identifier.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    /// Returns a slice of the server identifier.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    /// Returns a value over an octets slice.
    pub fn for_slice(&self) -> &Nsid<[u8]>
    where
        Octs: AsRef<[u8]>
    {
        unsafe { Nsid::from_slice_unchecked(self.octets.as_ref()) }
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Nsid<SrcOcts>> for Nsid<Octs>
where Octs: OctetsFrom<SrcOcts> {
    type Error = Octs::Error;

    fn try_octets_from(src: Nsid<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(src.octets).map(|octets| unsafe {
            Self::from_octets_unchecked(octets)
        })
    }
}

//--- AsRef and Borrow

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for Nsid<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> borrow::Borrow<[u8]> for Nsid<Octs> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

//--- OptData etc.

impl<Octs: ?Sized> OptData for Nsid<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::NSID
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for Nsid<Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::NSID {
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

//--- Display and Debug

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

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Nsid<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Nsid({})", self)
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

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first NSID option present.
    ///
    /// In a response, the NSID option contains an identifier of the name
    /// server that answered the query. In a query, the option is empty and
    /// signals a request for inclusion in a response.
    pub fn nsid(&self) -> Option<Nsid<Octs::Range<'_>>> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends an NSID option with the given server identifier.
    ///
    /// The NSID option contains an identifier for the name server that
    /// processed a query.
    ///
    /// In a request, the option can be included to request the server to
    /// include its server identifier. In this case, the data should be
    /// empty. You can use [`client_nsid`][Self::client_nsid] to easily
    /// append this version of the option.
    pub fn nsid(
        &mut self, data: &(impl AsRef<[u8]> + ?Sized)
    ) -> Result<(), BuildDataError> {
        Ok(self.push(Nsid::from_slice(data.as_ref())?)?)
    }

    /// Appends the client version of an NSID option.
    ///
    /// If included by a client, the NSID option requests that the server
    /// returns its name server identifier via the NSID option in a response.
    /// In this case, the option must be empty. This method creates such an
    /// empty NSID option.
    pub fn client_nsid(&mut self) -> Result<(), Target::AppendError> {
        self.push(Nsid::empty())
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn nsid_compose_parse() {
        test_option_compose_parse(
            &Nsid::from_octets("foo").unwrap(),
            |parser| Nsid::parse(parser)
        );
    }
}
