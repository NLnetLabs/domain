//! EDNS Options for signalling zone expire times.
//!
//! The option in this module, [`Expire`], allows a authoritative server to
//! signal when a zone expires independently of the SOA’s expire field. This
//! allows to determine the expire time when a secondary server is updating
//! a zone from another secondary server rather than directly from the
//! primary.
//!
//! This option is defined in [RFC 7314](https://tools.ietf.org/html/rfc7314).

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, Parse, ParseError};
use super::{Opt, OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;


//------------ Expire --------------------------------------------------------

/// Option data for the Expire EDNS option.
///
/// The option’s data consists of an optional `u32`. The value is omitted if
/// the option is added to a query to request it being included by the server
/// in an answer. In this answer the value should be present and indicates the
/// expire time of the zone on the server.
///
/// See [RFC 7314](https://tools.ietf.org/html/rfc7314) for details.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    /// The option code for this option.
    pub(super) const CODE: OptionCode = OptionCode::EXPIRE;
    
    /// Creates a new expire option with the given optional expire value.
    #[must_use]
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    /// Returns the content of the optional expire value.
    #[must_use]
    pub fn expire(self) -> Option<u32> {
        self.0
    }

    /// Parses a value from its wire format.
    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        if parser.remaining() == 0 {
            Ok(Expire::new(None))
        }
        else {
            u32::parse(parser).map(|res| Expire::new(Some(res)))
        }
    }

    /// Placeholder for unnecessary octets conversion.
    ///
    /// This method only exists for the `AllOptData` macro.
    pub(super) fn try_octets_from<E>(src: Self) -> Result<Self, E> {
        Ok(src)
    }
}

//--- OptData

impl OptData for Expire {
    fn code(&self) -> OptionCode {
        OptionCode::EXPIRE
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for Expire {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::EXPIRE {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for Expire {
    fn compose_len(&self) -> u16 {
        match self.0 {
            Some(_) => u32::COMPOSE_LEN,
            None => 0,
        }
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        if let Some(value) = self.0 {
            value.compose(target)?;
        }
        Ok(())
    }
}

//--- Display

impl fmt::Display for Expire {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Some(expire) => expire.fmt(f),
            None => Ok(())
        }
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the content of the Expire option if present.
    ///
    /// The Expire option allows an authoritative server to signal its own
    /// expiry time of a zone.
    pub fn expire(&self) -> Option<Expire> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends the Expire option.
    ///
    /// The Expire option allows an authoritative server to signal its own
    /// expiry time of a zone.
    pub fn expire(
        &mut self, expire: Option<u32>
    ) -> Result<(), Target::AppendError> {
        self.push(&Expire::new(expire))
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
    fn expire_compose_parse() {
        test_option_compose_parse(
            &Expire::new(None),
            |parser| Expire::parse(parser)
        );
        test_option_compose_parse(
            &Expire::new(Some(12)),
            |parser| Expire::parse(parser)
        );
    }
}

