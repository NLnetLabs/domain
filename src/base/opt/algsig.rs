//! EDNS Options from RFC 6975.

use super::super::iana::{OptionCode, SecAlg};
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;
use core::{borrow, fmt, hash, slice};
use core::cmp::Ordering;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident, $fn:ident ) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name<Octs: ?Sized> {
            octets: Octs,
        }

        impl<Octs> $name<Octs> {
            pub fn from_octets(octets: Octs) -> Self {
                $name { octets }
            }

            pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
                parser: &mut Parser<'a, Src>
            ) -> Result<Self, ParseError> {
                let len = parser.remaining();
                parser.parse_octets(len).map(
                    Self::from_octets
                ).map_err(Into::into)
            }
        }

        impl $name<[u8]> {
            pub fn from_slice(slice: &[u8]) -> &Self {
                unsafe { &*(slice as *const [u8] as *const Self) }
            }

            pub fn from_slice_mut(slice: &mut [u8]) -> &mut Self {
                unsafe { &mut *(slice as *mut [u8] as *mut Self) }
            }
        }

        impl<Octs: ?Sized> $name<Octs> {
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

            pub fn for_slice(&self) -> &$name<[u8]>
            where
                Octs: AsRef<[u8]>,
            {
                $name::from_slice(self.octets.as_ref())
            }

            pub fn for_slice_mut(&mut self) -> &mut $name<[u8]>
            where
                Octs: AsMut<[u8]>,
            {
                $name::from_slice_mut(self.octets.as_mut())
            }

            pub fn iter(&self) -> SecAlgsIter
            where
                Octs: AsRef<[u8]>,
            {
                SecAlgsIter::new(self.octets.as_ref())
            }
        }

        //--- AsRef, AsMut, Borrow, BorrowMut

        impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for $name<Octs> {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl<Octs: AsMut<[u8]> + ?Sized> AsMut<[u8]> for $name<Octs> {
            fn as_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> borrow::Borrow<[u8]> for $name<Octs> {
            fn borrow(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl<Octs> borrow::BorrowMut<[u8]> for $name<Octs>
        where
            Octs: AsMut<[u8]> + AsRef<[u8]> + ?Sized,
        {
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        //--- OptData etc.
        
        impl<Octs: ?Sized> OptData for $name<Octs> {
            fn code(&self) -> OptionCode {
                OptionCode::$name
            }
        }

        impl<'a, Octs> ParseOptData<'a, Octs> for $name<Octs::Range<'a>>
        where Octs: Octets {
            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                if code == OptionCode::$name {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> ComposeOptData for $name<Octs> {
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

        impl<'a, Octs: AsRef<[u8]> + ?Sized> IntoIterator for &'a $name<Octs> {
            type Item = SecAlg;
            type IntoIter = SecAlgsIter<'a>;

            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }

        //--- Display

        impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display for $name<Octets> {
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

        //--- PartialEq and Eq

        impl<Octs, Other> PartialEq<Other> for $name<Octs>
        where
            Octs: AsRef<[u8]> + ?Sized,
            Other: AsRef<[u8]> + ?Sized,
        {
            fn eq(&self, other: &Other) -> bool {
                self.as_slice().eq(other.as_ref())
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> Eq for $name<Octs> { }

        //--- PartialOrd and Ord

        impl<Octs, Other> PartialOrd<Other> for $name<Octs>
        where
            Octs: AsRef<[u8]> + ?Sized,
            Other: AsRef<[u8]> + ?Sized,
        {
            fn partial_cmp(&self, other: &Other) -> Option<Ordering> {
                self.as_slice().partial_cmp(other.as_ref())
            }
        }

        impl<Octs: AsRef<[u8]> + ?Sized> Ord for $name<Octs> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.as_slice().cmp(other.as_slice())
            }
        }

        //--- Hash

        impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for $name<Octs> {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.as_slice().hash(state)
            }
        }

        //------------ OptBuilder --------------------------------------------

        impl<'a, Target: Composer> OptBuilder<'a, Target> {
            pub fn $fn(
                &mut self, octets: &(impl AsRef<[u8]> + ?Sized)
            ) -> Result<(), Target::AppendError> {
                self.push(&$name::from_octets(octets.as_ref()))
            }
        }
    }
}

option_type!(Dau, dau);
option_type!(Dhu, dhu);
option_type!(N3u, n3u);


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

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    fn dau_compose_parse() {
        test_option_compose_parse(
            &Dau::from_octets("foo"),
            |parser| Dau::parse(parser)
        );
    }
}
