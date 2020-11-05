//! Extended DNS Error from RFC 8914

use super::super::{
    iana::{
        exterr::{ExtendedErrorCode, EDE_PRIVATE_RANGE_BEGIN},
        OptionCode,
    },
    octets::{OctetsBuilder, OctetsRef, Parse, ParseError},
    opt::CodeOptData,
    Compose, Parser, ShortBuf,
};
use core::{convert::TryFrom, fmt, str};

/// Extended Error data structure
#[derive(Debug, Clone)]
pub struct ExtendedError<Octets> {
    /// Info code provides the additional context for the
    /// RESPONSE-CODE of the DNS message.
    code: ExtendedErrorCode,
    /// Extra UTF-8 encoded text, which may hold additional textual
    /// information(optional).
    text: Option<Octets>,
}

impl<Octets: AsRef<[u8]>> ExtendedError<Octets> {
    /// Get INFO-CODE field.
    pub fn code(&self) -> ExtendedErrorCode {
        self.code
    }

    /// Get EXTRA-TEXT field.
    pub fn text(&self) -> Option<&Octets> {
        self.text.as_ref()
    }

    /// Set EXTRA-TEXT field. `text` must be UTF-8 encoded.
    pub fn set_text(&mut self, text: Octets) -> Result<(), str::Utf8Error> {
        // validate encoding
        let _ = str::from_utf8(text.as_ref())?;
        self.text = Some(text);
        Ok(())
    }

    /// Returns true if the code is in the private range.
    pub fn is_private(&self) -> bool {
        self.code().to_int() >= EDE_PRIVATE_RANGE_BEGIN
    }
}

impl<Octets> From<ExtendedErrorCode> for ExtendedError<Octets> {
    fn from(code: ExtendedErrorCode) -> Self {
        Self { code, text: None }
    }
}

impl<Octets: AsRef<[u8]>> TryFrom<(ExtendedErrorCode, Octets)> for ExtendedError<Octets> {
    type Error = str::Utf8Error;

    fn try_from(v: (ExtendedErrorCode, Octets)) -> Result<Self, Self::Error> {
        let mut ede: Self = v.0.into();
        ede.set_text(v.1)?;
        Ok(ede)
    }
}

impl<Octets> From<u16> for ExtendedError<Octets> {
    fn from(code: u16) -> Self {
        Self {
            code: ExtendedErrorCode::from_int(code),
            text: None,
        }
    }
}

impl<Ref: OctetsRef> Parse<Ref> for ExtendedError<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let mut ede: Self = parser.parse_u16()?.into();
        let n = parser.remaining();
        if n > 0 {
            ede.set_text(parser.parse_octets(n)?)
                .map_err(|_| ParseError::form_error("invalid extended error text encoding"))?;
        }
        Ok(ede)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets> CodeOptData for ExtendedError<Octets> {
    const CODE: OptionCode = OptionCode::ExtendedError;
}

impl<Octets: AsRef<[u8]>> Compose for ExtendedError<Octets> {
    fn compose<T: OctetsBuilder>(&self, target: &mut T) -> Result<(), ShortBuf> {
        target.append_slice(&self.code.to_int().to_be_bytes())?;
        if let Some(text) = &self.text {
            target.append_slice(text.as_ref())?;
        }
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for ExtendedError<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.code.fmt(f)?;

        if let Some(text) = &self.text {
            let text = str::from_utf8(text.as_ref()).map_err(|_| fmt::Error)?;
            write!(f, " ({})", text)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::super::octets::Octets512, *};
    use core::convert::TryInto;

    #[test]
    fn compose() {
        let ede: ExtendedError<&[u8]> = (ExtendedErrorCode::StaleAnswer, "some text".as_ref())
            .try_into()
            .unwrap();

        let mut buf = Octets512::new();
        ede.compose(&mut buf).unwrap();

        let parsed = ExtendedError::parse(&mut Parser::from_ref(buf.as_ref())).unwrap();
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
        assert!(ExtendedError::try_from((ExtendedErrorCode::Other, b"\x30".as_ref())).is_ok());
        assert!(ExtendedError::try_from((ExtendedErrorCode::Other, b"\xff".as_ref())).is_err());
    }
}
