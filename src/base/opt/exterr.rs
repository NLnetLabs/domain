//! EDNS option for extended DNS errors.
//!
//! The option in this module – [`ExtendedError<Octs>`] – allows a server to
//! provide more detailed information why a query has failed.
//!
//! The option is defined in [RFC 8914](https://tools.ietf.org/html/rfc8914).

use super::super::iana::exterr::{ExtendedErrorCode, EDE_PRIVATE_RANGE_BEGIN};
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::ParseError;
use super::super::wire::{Compose, Composer};
use super::{
    BuildDataError, LongOptData, Opt, OptData, ComposeOptData, ParseOptData
};
use octseq::builder::OctetsBuilder;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use octseq::str::Str;
use octseq::{EmptyBuilder, FromBuilder};
use core::{fmt, hash, str};
use core::convert::Infallible;

//------------ ExtendedError -------------------------------------------------

/// Option data for an extended DNS error.
///
/// The Extended DNS Error option allows a server to include more detailed
/// information in a response to a failed query why it did. It contains a
/// standardized [`ExtendedErrorCode`] for machines and an optional UTF-8
/// error text for humans.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(bound(
        serialize = "Octs: AsRef<[u8]>"
    ))
)]
pub struct ExtendedError<Octs> {
    /// The extended error code.
    code: ExtendedErrorCode,

    /// Optional human-readable error information.
    ///
    /// See `text` for the interpretation of the result.
    #[cfg_attr(feature = "serde", serde(serialize_with = "lossy_text"))]
    text: Option<Result<Str<Octs>, LossyOctets<Octs>>>,
}

#[cfg(feature = "serde")]
fn lossy_text<S, Octs: AsRef<[u8]>>(
    text: &Option<Result<Str<Octs>, LossyOctets<Octs>>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match text {
        Some(Ok(text)) => serializer.serialize_str(text),
        Some(Err(text)) => serializer.collect_str(text),
        None => serializer.serialize_none(),
    }
}

impl ExtendedError<()> {
    /// The option code for this option.
    pub(super) const CODE: OptionCode = OptionCode::EXTENDED_ERROR;
}

impl<Octs> ExtendedError<Octs> {
    /// Creates a new value from a code and optional text.
    ///
    /// Returns an error if `text` is present but is too long to fit into
    /// an option.
    pub fn new(
        code: ExtendedErrorCode, text: Option<Str<Octs>>
    ) -> Result<Self, LongOptData>
    where Octs: AsRef<[u8]> {
        if let Some(ref text) = text {
            LongOptData::check_len(
                text.len() + usize::from(ExtendedErrorCode::COMPOSE_LEN)
            )?
        }
        Ok(unsafe { Self::new_unchecked(code, text.map(Ok)) })
    }

    pub fn new_with_str(code: ExtendedErrorCode, text: &str) ->
	Result<Self, LongOptData>
	where Octs: AsRef<[u8]> + FromBuilder,
	<Octs as FromBuilder>::Builder: EmptyBuilder,
	<<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Into<Infallible>,
    {
	Self::new(code, Some(Str::copy_from_str(text)))
    }

    /// Creates a new value without checking for the option length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the length of the wire format of the
    /// value does not exceed 65,535 octets.
    pub unsafe fn new_unchecked(
        code: ExtendedErrorCode, text: Option<Result<Str<Octs>, Octs>>
    ) -> Self {
        Self {
            code,
            text: text.map(|res| res.map_err(LossyOctets))
        }
    }

    /// Returns the error code.
    pub fn code(&self) -> ExtendedErrorCode {
        self.code
    }

    /// Returns the text.
    ///
    /// If there is no text, returns `None`. If there is text and it is
    /// correctly encoded UTF-8, returns `Some(Ok(_))`. If there is text but
    /// it is not UTF-8, returns `Some(Err(_))`.
    pub fn text(&self) -> Option<Result<&Str<Octs>, &Octs>> {
        self.text.as_ref().map(|res| res.as_ref().map_err(|err| err.as_ref()))
    }

    /// Returns the text as an octets slice.
    pub fn text_slice(&self) -> Option<&[u8]>
    where Octs: AsRef<[u8]> {
        match self.text {
            Some(Ok(ref text)) => Some(text.as_slice()),
            Some(Err(ref text)) => Some(text.as_slice()),
            None => None
        }
    }

    /// Sets the text field.
    pub fn set_text(&mut self, text: Str<Octs>) {
        self.text = Some(Ok(text));
    }

    /// Returns true if the code is in the private range.
    pub fn is_private(&self) -> bool {
        self.code().to_int() >= EDE_PRIVATE_RANGE_BEGIN
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError>
    where Octs: AsRef<[u8]> {
        let code = ExtendedErrorCode::parse(parser)?;
        let text = match parser.remaining() {
            0 => None,
            n => {
                Some(Str::from_utf8(parser.parse_octets(n)?).map_err(|err| {
                    err.into_octets()
                }))
            }
        };
        Ok(unsafe { Self::new_unchecked(code, text) })
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

impl<Octs> TryFrom<(ExtendedErrorCode, Str<Octs>)> for ExtendedError<Octs> 
where Octs: AsRef<[u8]> {
    type Error = LongOptData;

    fn try_from(
        (code, text): (ExtendedErrorCode, Str<Octs>)
    ) -> Result<Self, Self::Error> {
        Self::new(code, Some(text))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<ExtendedError<SrcOcts>> for ExtendedError<Octs>
where
    Octs: OctetsFrom<SrcOcts>
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: ExtendedError<SrcOcts>
    ) -> Result<Self, Self::Error> {
        let text = match source.text {
            Some(Ok(text)) => Some(Ok(Str::try_octets_from(text)?)),
            Some(Err(octs)) => {
                Some(Err(LossyOctets(Octs::try_octets_from(octs.0)?)))
            }
            None => None,
        };
        Ok(Self { code: source.code, text })
    }
}
//--- OptData, ParseOptData, and ComposeOptData

impl<Octs> OptData for ExtendedError<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::EXTENDED_ERROR
    }
}

impl<'a, Octs> ParseOptData<'a, Octs> for ExtendedError<Octs::Range<'a>> 
where Octs: Octets + ?Sized {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::EXTENDED_ERROR {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeOptData for ExtendedError<Octs> {
    fn compose_len(&self) -> u16 {
        if let Some(text) = self.text_slice() {
            text.len().checked_add(
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
        if let Some(text) = self.text_slice() {
            target.append_slice(text)?;
        }
        Ok(())
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]>> fmt::Display for ExtendedError<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.code.fmt(f)?;
        match self.text {
            Some(Ok(ref text)) => write!(f, " {}", text)?,
            Some(Err(ref text)) => write!(f, " {}", text)?,
            None => { }
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Debug for ExtendedError<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ExtendedError")
            .field("code", &self.code)
            .field("text", &self.text.as_ref().map(|text| {
                text.as_ref().map_err(|err| err.0.as_ref())
            }))
            .finish()
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<ExtendedError<Other>> for ExtendedError<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{ 
    fn eq(&self, other: &ExtendedError<Other>) -> bool {
       self.code.eq(&other.code) && self.text_slice().eq(&other.text_slice())
    }
}

impl<Octs: AsRef<[u8]>> Eq for ExtendedError<Octs> { }

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for ExtendedError<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.code.hash(state);
        self.text_slice().hash(state);
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first extended DNS error option if present.
    ///
    /// The extended DNS error option carries additional error information in
    /// a failed answer.
    pub fn extended_error(&self) -> Option<ExtendedError<Octs::Range<'_>>> {
        self.first()
    }
}

impl<Target: Composer> OptBuilder<'_, Target> {
    /// Appends an extended DNS error option.
    ///
    /// The extended DNS error option carries additional error information in
    /// a failed answer. The `code` argument is a standardized error code
    /// while the optional `text` carries human-readable information.
    ///
    /// The method fails if `text` is too long to be part of an option or if
    /// target runs out of space.
    pub fn extended_error<Octs: AsRef<[u8]>>(
        &mut self, code: ExtendedErrorCode, text: Option<&Str<Octs>>
    ) -> Result<(), BuildDataError> {
        self.push(
            &ExtendedError::new(
                code,
                text.map(|text| {
                    unsafe { Str::from_utf8_unchecked(text.as_slice()) }
                })
            )?
        )?;
        Ok(())
    }
}


//------------ LossyOctets ---------------------------------------------------

/// An octets wrapper that displays its content as a lossy UTF-8 sequence.
#[derive(Clone)]
struct LossyOctets<Octs>(Octs);

impl<Octs: AsRef<[u8]>> LossyOctets<Octs> {
    fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Octs> From<Octs> for LossyOctets<Octs> {
    fn from(src: Octs) -> Self {
        Self(src)
    }
}

impl<Octs> AsRef<Octs> for LossyOctets<Octs> {
    fn as_ref(&self) -> &Octs {
        &self.0
    }
}

impl<Octs: AsRef<[u8]>> fmt::Display for LossyOctets<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut source = self.0.as_ref();
        loop {
            match str::from_utf8(source) {
                Ok(s) => {
                    f.write_str(s)?;
                    break;
                }
                Err(err) => {
                    let (good, mut tail) = source.split_at(err.valid_up_to());
                    f.write_str(
                        // Safety: valid UTF8 for this part was confirmed
                        // above.
                        unsafe {
                            str::from_utf8_unchecked(good)
                        }
                    )?;
                    f.write_str("\u{fffd}")?;
                    match err.error_len() {
                        None => break,
                        Some(len) => {
                            tail = &tail[len..];
                        }
                    }
                    source = tail;
                }
            }
        }
        Ok(())
    }
}


//============ Tests =========================================================

#[cfg(all(test, feature="std", feature = "bytes"))]
mod tests {
    use super::*;
    use super::super::test::test_option_compose_parse;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn nsid_compose_parse() {
        let ede = ExtendedError::new(
            ExtendedErrorCode::STALE_ANSWER,
            Some(Str::from_string("some text".into()))
        ).unwrap();
        test_option_compose_parse(
            &ede,
            |parser| ExtendedError::parse(parser)
        );
    }

    #[test]
    fn private() {
        let ede: ExtendedError<&[u8]> = ExtendedErrorCode::DNSSEC_BOGUS.into();
        assert!(!ede.is_private());

        let ede: ExtendedError<&[u8]> = EDE_PRIVATE_RANGE_BEGIN.into();
        assert!(ede.is_private());
    }

    #[test]
    fn display_lossy_octets() {
        use std::string::ToString;

        assert_eq!(
            LossyOctets(b"foo").to_string(),
            "foo"
        );
        assert_eq!(
            LossyOctets(b"foo\xe7").to_string(),
            "foo\u{fffd}"
        );
        assert_eq!(
            LossyOctets(b"foo\xe7foo").to_string(),
            "foo\u{fffd}foo"
        );
    }
}
