//! Extended DNS Error from RFC 8914

use super::super::iana::exterr::{ExtendedErrorCode, EDE_PRIVATE_RANGE_BEGIN};
use super::super::iana::OptionCode;
use super::super::octets::{
    Octets, Parser, ParseError
};
use super::super::wire::Compose;
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use core::convert::TryFrom;
use core::{fmt, str};

//------------ ExtendedError -------------------------------------------------

/// Extended Error data structure
#[derive(Debug, Clone)]
pub struct ExtendedError<Octs> {
    /// Info code provides the additional context for the
    /// RESPONSE-CODE of the DNS message.
    code: ExtendedErrorCode,

    /// Extra UTF-8 encoded text, which may hold additional textual
    /// information(optional).
    text: Option<Octs>,
}

impl<Octs: AsRef<[u8]>> ExtendedError<Octs> {
    /// Get INFO-CODE field.
    pub fn code(&self) -> ExtendedErrorCode {
        self.code
    }

    /// Get EXTRA-TEXT field.
    pub fn text(&self) -> Option<&Octs> {
        self.text.as_ref()
    }

    /// Set EXTRA-TEXT field. `text` must be UTF-8 encoded.
    pub fn set_text(&mut self, text: Octs) -> Result<(), str::Utf8Error> {
        // validate encoding
        let _ = str::from_utf8(text.as_ref())?;
        self.text = Some(text);
        Ok(())
    }

    /// Returns true if the code is in the private range.
    pub fn is_private(&self) -> bool {
        self.code().to_int() >= EDE_PRIVATE_RANGE_BEGIN
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let mut ede: Self = parser.parse_u16()?.into();
        let n = parser.remaining();
        if n > 0 {
            ede.set_text(parser.parse_octets(n)?).map_err(|_| {
                ParseError::form_error(
                    "invalid extended error text encoding"
                )
            })?;
        }
        Ok(ede)
    }
}

//--- From and TryFrom

impl<Octs> From<ExtendedErrorCode> for ExtendedError<Octs> {
    fn from(code: ExtendedErrorCode) -> Self {
        Self { code, text: None }
    }
}

impl<Octs> From<u16> for ExtendedError<Octs> {
    fn from(code: u16) -> Self {
        Self {
            code: ExtendedErrorCode::from_int(code),
            text: None,
        }
    }
}

impl<Octs> TryFrom<(ExtendedErrorCode, Octs)> for ExtendedError<Octs>
where Octs: AsRef<[u8]> {
    type Error = str::Utf8Error;

    fn try_from(v: (ExtendedErrorCode, Octs)) -> Result<Self, Self::Error> {
        let mut ede: Self = v.0.into();
        ede.set_text(v.1)?;
        Ok(ede)
    }
}

//--- OptData, ParseOptData, and ComposeOptData

impl<Octs> OptData for ExtendedError<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::ExtendedError
    }
}

impl<'a, Octs> ParseOptData<'a, Octs> for ExtendedError<Octs::Range<'a>> 
where Octs: Octets + ?Sized {
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

impl<Octs: AsRef<[u8]>> ComposeOptData for ExtendedError<Octs> {
    fn compose_len(&self) -> u16 {
        if let Some(text) = &self.text {
            text.as_ref().len().checked_add(
                ExtendedErrorCode::COMPOSE_LEN.into()
            ).expect("long option data").try_into().expect("long option data")
        }
        else {
            ExtendedErrorCode::COMPOSE_LEN
        }
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.code.to_int().compose(target)?;
        if let Some(text) = &self.text {
            target.append_slice(text.as_ref())?;
        }
        Ok(())
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for ExtendedError<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.code.fmt(f)?;

        if let Some(text) = &self.text {
            let text = str::from_utf8(text.as_ref()).map_err(|_| fmt::Error)?;
            write!(f, " ({})", text)?;
        }
        Ok(())
    }
}

//============ Tests =========================================================

#[cfg(all(test, feature="std"))]
mod tests {
    use super::*;
    use octseq::builder::infallible;
    use core::convert::TryInto;
    use std::vec::Vec;

    #[test]
    fn compose() {
        let ede: ExtendedError<&[u8]> = (
            ExtendedErrorCode::StaleAnswer, "some text".as_ref()
        ).try_into().unwrap();

        let mut buf = Vec::new();
        infallible(ede.compose_option(&mut buf));

        let parsed = ExtendedError::parse(
            &mut Parser::from_ref(buf.as_slice())
        ).unwrap();
        assert_eq!(ede.code, parsed.code);
        assert_eq!(ede.text, parsed.text);
    }

    #[test]
    fn private() {
        let ede: ExtendedError<&[u8]> = ExtendedErrorCode::DnssecBogus.into();
        assert!(!ede.is_private());

        let ede: ExtendedError<&[u8]> = EDE_PRIVATE_RANGE_BEGIN.into();
        assert!(ede.is_private());
    }

    #[test]
    fn encoding() {
        assert!(
            ExtendedError::try_from(
                (ExtendedErrorCode::Other, b"\x30".as_ref())
            ).is_ok()
        );
        assert!(
            ExtendedError::try_from(
                (ExtendedErrorCode::Other, b"\xff".as_ref())
            ).is_err()
        );
    }
}
