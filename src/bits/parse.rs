use std::{error, fmt};
use bytes::{BigEndian, ByteOrder, Bytes};


//------------ Parser --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Parser {
    bytes: Bytes,
    pos: usize
}

impl Parser {
    pub fn from_bytes(bytes: Bytes) -> Self {
        Parser { bytes, pos: 0 }
    }
}

impl Parser {
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn peek(&self) -> &[u8] {
        &self.bytes.as_ref()[self.pos..]
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), ShortParser> {
        if pos > self.bytes.len() {
            Err(ShortParser)
        }
        else {
            self.pos = pos;
            Ok(())
        }
    }

    pub fn advance(&mut self, cnt: usize) -> Result<(), ShortParser> {
        if cnt > self.remaining() {
            Err(ShortParser)
        }
        else {
            self.pos += cnt;
            Ok(())
        }
    }

    pub fn advance_unchecked(&mut self, cnt: usize) {
        self.pos += cnt;
        assert!(self.pos <= self.bytes.len())
    }

    pub fn check_len(&self, len: usize) -> Result<(), ShortParser> {
        if self.remaining() < len {
            Err(ShortParser)
        }
        else {
            Ok(())
        }
    }

    pub fn parse_bytes(&mut self, len: usize) -> Result<Bytes, ShortParser> {
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(ShortParser.into())
        }
        let res = self.bytes.slice(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    pub fn parse_u8(&mut self) -> Result<u8, ShortParser> {
        self.check_len(1)?;
        let res = self.peek()[0];
        self.advance_unchecked(1);
        Ok(res)
    }

    pub fn parse_i8(&mut self) -> Result<i8, ShortParser> {
        self.check_len(1)?;
        let res = self.peek()[0] as i8;
        self.advance_unchecked(1);
        Ok(res)
    }

    pub fn parse_i16(&mut self) -> Result<i16, ShortParser> {
        self.check_len(2)?;
        let res = BigEndian::read_i16(self.peek());
        self.advance_unchecked(2);
        Ok(res)
    }

    pub fn parse_u16(&mut self) -> Result<u16, ShortParser> {
        self.check_len(2)?;
        let res = BigEndian::read_u16(self.peek());
        self.advance_unchecked(2);
        Ok(res)
    }

    pub fn parse_i32(&mut self) -> Result<i32, ShortParser> {
        self.check_len(4)?;
        let res = BigEndian::read_i32(self.peek());
        self.advance_unchecked(4);
        Ok(res)
    }

    pub fn parse_u32(&mut self) -> Result<u32, ShortParser> {
        self.check_len(4)?;
        let res = BigEndian::read_u32(self.peek());
        self.advance_unchecked(4);
        Ok(res)
    }
}


//------------ ParseExt ------------------------------------------------------

pub trait ParseExt: Sized {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser>;
}

impl ParseExt for i8 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i8()
    }
}

impl ParseExt for u8 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u8()
    }
}

impl ParseExt for i16 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i16()
    }
}

impl ParseExt for u16 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u16()
    }
}

impl ParseExt for i32 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i32()
    }
}

impl ParseExt for u32 {
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u32()
    }
}


//------------ ShortParser ---------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortParser;

impl error::Error for ShortParser {
    fn description(&self) -> &str {
        "unexpected end of data"
    }
}

impl fmt::Display for ShortParser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}

