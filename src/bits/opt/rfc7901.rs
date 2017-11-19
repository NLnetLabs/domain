//! EDNS Options from RFC 7901

use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::name::{Dname, DnameError, ToDname};
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::OptData;


//------------ Chain --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Chain {
    start: Dname,
}

impl Chain {
    pub fn new(start: Dname) -> Self {
        Chain { start }
    }

    pub fn push<N: ToDname>(builder: &mut OptBuilder, start: &N)
                            -> Result<(), ShortBuf> {
        let len = start.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Chain, len as u16, |buf| {
            buf.compose(start)
        })
    }

    pub fn start(&self) -> &Dname {
        &self.start
    }
}


//--- Composable and OptData

impl Composable for Chain {
    fn compose_len(&self) -> usize {
        self.start.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.start.compose(buf)
    }
}

impl OptData for Chain {
    type ParseErr = ChainParseError;

    fn code(&self) -> OptionCode {
        OptionCode::Chain
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, ChainParseError> {
        if code != OptionCode::Chain {
            return Ok(None)
        }
        Ok(Some(Chain::new(Dname::from_bytes(parser.parse_bytes(len)?)?)))
    }
}


//------------ ChainParseError -----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ChainParseError {
    #[fail(display="{}", _0)]
    Name(DnameError),

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl From<DnameError> for ChainParseError {
    fn from(err: DnameError) -> ChainParseError {
        ChainParseError::Name(err)
    }
}

impl From<ShortBuf> for ChainParseError {
    fn from(_: ShortBuf) -> ChainParseError {
        ChainParseError::ShortBuf
    }
}

