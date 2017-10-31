use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::parse::{Parseable, Parser, ShortParser};
use super::label::{Label, LabelTypeError};
use super::traits::{ToLabelIter, ToDname, ToFqdn};


//------------ ParsedFqdn ----------------------------------------------------

pub struct ParsedFqdn {
    parser: Parser,
    len: usize,
    compressed: bool,
}

impl ParsedFqdn {
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    pub fn iter(&self) -> ParsedFqdnIter {
        ParsedFqdnIter::new(&self.parser, self.len)
    }
}

//--- Parseable and Composable

impl Parseable for ParsedFqdn {
    type Err = ParsedFqdnError;

    fn parse(parser: &mut Parser) -> Result<Self, ParsedFqdnError> {
        let start = parser.pos();
        let mut len = 0;

        // Phase 1: Take labels from the parser until the root label or the
        //          first compressed label. In the latter case, remember where
        //          the actual name ended.
        let end = loop {
            match LabelType::parse(parser) {
                Ok(LabelType::Normal(0)) => {
                    len += 1;
                    if len > 255 {
                        parser.seek(start).unwrap();
                        return Err(ParsedFqdnError::LongName)
                    }
                    let mut res = parser.clone();
                    res.seek(start).unwrap();
                    return Ok(ParsedFqdn { parser: res, len,
                                           compressed: false })
                }
                Ok(LabelType::Normal(label_len)) => {
                    if let Err(err) = parser.advance(label_len) {
                        parser.seek(start).unwrap();
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        parser.seek(start).unwrap();
                        return Err(ParsedFqdnError::LongName)
                    }
                }
                Ok(LabelType::Compressed(pos)) => {
                    if let Err(err) = parser.seek(pos) {
                        parser.seek(start).unwrap();
                        return Err(err.into())
                    }
                    break parser.pos()
                }
                Err(err) => {
                    parser.seek(start).unwrap();
                    return Err(err)
                }
            }
        };

        // Phase 2: Follow offsets so we can get the length.
        loop {
            match LabelType::parse(parser)? {
                LabelType::Normal(0) => {
                    len += 1;
                    if len > 255 {
                        parser.seek(start).unwrap();
                        return Err(ParsedFqdnError::LongName)
                    }
                    break;
                }
                LabelType::Normal(label_len) => {
                    if let Err(err) = parser.advance(label_len) {
                        parser.seek(start).unwrap();
                        return Err(err.into())
                    }
                    len += label_len + 1;
                    if len > 255 {
                        parser.seek(start).unwrap();
                        return Err(ParsedFqdnError::LongName)
                    }
                }
                LabelType::Compressed(pos) => {
                    if let Err(err) = parser.seek(pos) {
                        parser.seek(start).unwrap();
                        return Err(err.into())
                    }
                }
            }
        }

        // Phase 3: Profit
        parser.seek(end).unwrap();
        let mut res = parser.clone();
        res.seek(start).unwrap();
        Ok(ParsedFqdn { parser: res, len, compressed: true })
    }
}

impl Composable for ParsedFqdn {
    fn compose_len(&self) -> usize {
        self.len
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        for label in self.iter() {
            label.compose(buf)
        }
    }
}

//--- ToLabelIter, ToDname, and ToFqdn

impl<'a> ToLabelIter<'a> for ParsedFqdn {
    type LabelIter = ParsedFqdnIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToDname for ParsedFqdn {
    fn is_absolute(&self) -> bool {
        true
    }
}

impl ToFqdn for ParsedFqdn { }


//------------ ParsedFqdnIter ------------------------------------------------

pub struct ParsedFqdnIter<'a> {
    slice: &'a [u8],
    pos: usize,
    len: usize,
}

impl<'a> ParsedFqdnIter<'a> {
    fn new(parser: &'a Parser, len: usize) -> Self {
        ParsedFqdnIter { slice: parser.as_slice(), pos: parser.pos(), len }
    }

    fn get_label(&mut self) -> &'a Label {
        let end = loop {
            let ltype = self.slice[self.pos];
            self.pos += 1;
            match ltype {
                0 ... 0x3F => break self.pos + (ltype as usize),
                0xC0 ... 0xFF => {
                    self.pos = (self.slice[self.pos] as usize)
                             | (((ltype as usize) & 0x3F) << 8);
                }
                _ => panic!("bad label")
            }
        };
        let res = unsafe {
            Label::from_slice_unchecked(&self.slice[self.pos..end])
        };
        self.pos = end;
        res
    }
}

impl<'a> Iterator for ParsedFqdnIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<&'a Label> {
        if self.len == 0 {
            return None
        }
        let res = self.get_label();
        self.len -= res.len() + 1;
        Some(res)
    }
}

impl<'a> DoubleEndedIterator for ParsedFqdnIter<'a> {
    fn next_back(&mut self) -> Option<&'a Label> {
        while self.len > 0 {
            let label = self.get_label();
            self.len -= label.len() +1;
            if self.len == 0 {
                return Some(label)
            }
        }
        None
    }
}


//------------ LabelType -----------------------------------------------------

/// The type of a label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LabelType {
    Normal(usize),
    Compressed(usize),
}

impl LabelType {
    pub fn parse(parser: &mut Parser) -> Result<Self, ParsedFqdnError> {
        let ltype = parser.parse_u8()?;
        match ltype {
            0 ... 0x3F => Ok(LabelType::Normal(ltype as usize)),
            0xC0 ... 0xFF => {
                let res = parser.parse_u8()? as usize;
                let res = res | (((ltype as usize) & 0x3F) << 8);
                Ok(LabelType::Compressed(res))
            }
            0x40 ... 0x4F => Err(LabelTypeError::Extended(ltype).into()),
            _ => Err(LabelTypeError::Undefined.into())
        }
    }
}


//------------ ParsedFqdnError -----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedFqdnError {
    ShortParser,
    BadLabel(LabelTypeError),
    LongName,
}

impl From<ShortParser> for ParsedFqdnError {
    fn from(_: ShortParser) -> ParsedFqdnError {
        ParsedFqdnError::ShortParser
    }
}

impl From<LabelTypeError> for ParsedFqdnError {
    fn from(err: LabelTypeError) -> ParsedFqdnError {
        ParsedFqdnError::BadLabel(err)
    }
}

