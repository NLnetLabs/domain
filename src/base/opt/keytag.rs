//! EDNS options to signal the trust anchor key used in DNSSEC validation.
//!
//! The option in this module – [`KeyTag`] – is used by validating resolvers
//! when querying for DNSKEY records to indicate the key tags of the trust
//! anchor keys they will be using when validating responses. This is intended
//! as a means to monitor key uses during root key rollovers.
//!
//! The option is defined in [RFC 8145](https://tools.ietf.org/html/rfc8145)
//! along with detailed rules for who includes this option when.

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{Opt, OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use core::{borrow, fmt, hash, mem};
use core::cmp::Ordering;
use core::convert::TryInto;


//------------ KeyTag -------------------------------------------------------

/// Option data for the edns-key-tag option.
///
/// This option allows a client to indicate the key tags of the trust anchor
/// keys they are using to validate responses. The option contains a sequence
/// of key tags.
#[derive(Clone)]
#[repr(transparent)]
pub struct KeyTag<Octs: ?Sized> {
    octets: Octs,
}

impl KeyTag<()> {
    /// The option code for this option.
    pub(super) const CODE: OptionCode = OptionCode::KEY_TAG;
}
    
impl<Octs> KeyTag<Octs> {
    /// Creates a new value from its content in wire format.
    ///
    /// The function returns an error if the octets do not encode a valid
    /// edns-key-tag option: the length needs to be an even number of
    /// octets and no longer than 65,536 octets.
    pub fn from_octets(octets: Octs) -> Result<Self, ParseError>
    where Octs: AsRef<[u8]> {
        KeyTag::check_len(octets.as_ref().len())?;
        Ok(unsafe { Self::from_octets_unchecked(octets ) })
    }

    /// Creates a new value from its wire-format content without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that `octets` is a valid key tag. The
    /// length needs to be an even number of octets and no longer than
    /// 65,536 octets.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Self { octets }
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        KeyTag::check_len(len)?;
        let octets = parser.parse_octets(len)?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }
}

impl KeyTag<[u8]> {
    /// Creates a key tag value from a slice.
    ///
    /// Returns an error if `slice` does not contain a valid key tag.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ParseError> {
        Self::check_len(slice.len())?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a key tag value from a slice without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that `slice` contains a valid key tag. The
    /// length needs to be an even number of octets and no longer than
    /// 65,536 octets.
    #[must_use]
    pub unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: KeyTag has repr(transparent)
        mem::transmute(slice)
    }

    /// Checkes that the length of an octets sequence is valid.
    fn check_len(len: usize) -> Result<(), ParseError> {
        if len > usize::from(u16::MAX) {
            Err(ParseError::form_error("long edns-key-tag option"))
        }
        else if len % 2 == 1 {
            Err(ParseError::form_error("invalid edns-key-tag option length"))
        }
        else {
            Ok(())
        }
    }
}

impl<Octs: ?Sized> KeyTag<Octs> {
    /// Returns a reference to the underlying octets.
    ///
    /// The octets contain the key tag value in its wire format: a sequence
    /// of `u16` in network byte order.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    /// Converts the value to the underlying octets.
    ///
    /// The octets contain the key tag value in its wire format: a sequence
    /// of `u16` in network byte order.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    /// Returns a slice of the underlying octets.
    ///
    /// The slice will contain the key tag value in its wire format: a
    /// sequence of `u16` in network byte order.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    /// Returns a mutable slice of the underlying octets.
    ///
    /// The slice will contain the key tag value in its wire format: a
    /// sequence of `u16` in network byte order.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octs: AsMut<[u8]>,
    {
        self.octets.as_mut()
    }

    /// Returns an iterator over the individual key tags.
    pub fn iter(&self) -> KeyTagIter
    where Octs: AsRef<[u8]> {
        KeyTagIter(self.octets.as_ref())
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<KeyTag<SrcOcts>> for KeyTag<Octs>
where Octs: OctetsFrom<SrcOcts> {
    type Error = Octs::Error;

    fn try_octets_from(src: KeyTag<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(src.octets).map(|octets| unsafe {
            Self::from_octets_unchecked(octets)
        })
    }
}

//--- AsRef, AsMut, Borrow, BorrowMut

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for KeyTag<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]> + ?Sized> AsMut<[u8]> for KeyTag<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> borrow::Borrow<[u8]> for KeyTag<Octs> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs> borrow::BorrowMut<[u8]> for KeyTag<Octs>
where
    Octs: AsMut<[u8]> + AsRef<[u8]> + ?Sized
{
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

//--- OptData

impl<Octs: ?Sized> OptData for KeyTag<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::KEY_TAG
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for KeyTag<Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::KEY_TAG {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ComposeOptData for KeyTag<Octs> {
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}


//--- IntoIterator

impl<'a, Octs: AsRef<[u8]> + ?Sized> IntoIterator for &'a KeyTag<Octs> {
    type Item = u16;
    type IntoIter = KeyTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- Display and Debug

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display  for KeyTag<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        
        for v in self.octets.as_ref() {
            if first {
                write!(f, "{:X}", ((*v as u16) << 8) | *v as u16)?;
                first = false;
            } else {
                write!(f, ", {:X}", ((*v as u16) << 8) | *v as u16)?;
            }
        }

        Ok(())
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Debug  for KeyTag<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyTag([{}])", self)
    }
}


//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Other> for KeyTag<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &Other) -> bool {
        self.as_slice().eq(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for KeyTag<Octs> { }

//--- PartialOrd and Ord

impl<Octs, Other> PartialOrd<Other> for KeyTag<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    Other: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &Other) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for KeyTag<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for KeyTag<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first edns-key-tags option if present.
    ///
    /// The option contains a list of the key tags of the trust anchor keys
    /// a validating resolver is using for DNSSEC validation.
    pub fn key_tag(&self) -> Option<KeyTag<Octs::Range<'_>>> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends a edns-key-tag option.
    ///
    /// The option contains a list of the key tags of the trust anchor keys
    /// a validating resolver is using for DNSSEC validation.
    pub fn key_tag(
        &mut self, key_tag: &KeyTag<impl AsRef<[u8]> + ?Sized>,
    ) -> Result<(), Target::AppendError> {
        self.push(key_tag)
    }
}


//------------ KeyTagIter ----------------------------------------------------

/// An iterator over the key tags in an edns-key-tags value.
///
/// You can get a value of this type via [`KeyTag::iter`] or its
/// `IntoIterator` implementation.
#[derive(Clone, Copy, Debug)]
pub struct KeyTagIter<'a>(&'a [u8]);

impl<'a> Iterator for KeyTagIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            None
        }
        else {
            let (item, tail) = self.0.split_at(2);
            self.0 = tail;
            Some(u16::from_be_bytes(item.try_into().unwrap()))
        }
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
            &KeyTag::from_octets("fooo").unwrap(),
            |parser| KeyTag::parse(parser)
        );
    }
}

