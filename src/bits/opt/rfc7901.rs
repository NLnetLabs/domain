//! EDNS Options from RFC 7901

use ::bits::{Composer, ComposeError, ComposeResult, DName, ParsedDName,
             Parser, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ Chain --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Chain<N: DName>(N);

impl<N: DName> Chain<N> {
    pub fn new(name: N) -> Self {
        Chain(name)
    }

    pub fn name(&self) -> &N {
        &self.0
    }
}

impl<N: DName> OptData for Chain<N> {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::Chain.into())?;
        let pos = target.pos();
        target.compose_u16(0)?;
        target.compose_dname(&self.0)?;
        let len = target.pos() - pos;
        if len > ::std::u16::MAX as usize {
            return Err(ComposeError::SizeExceeded)
        }
        target.update_u16(pos, len as u16);
        Ok(())
    }
}

impl<'a> ParsedOptData<'a> for Chain<ParsedDName<'a>> {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::Chain {
            return Ok(None)
        }
        let name = ParsedDName::parse(parser)?;
        parser.exhausted()?;
        Ok(Some(Chain::new(name)))
    }
}

