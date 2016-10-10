//! Parsed domain names.

use std::borrow::Cow;
use std::cmp;
use std::fmt;
use std::hash;
use super::super::{Parser, ParseError, ParseResult};
use super::{DName, DNameBuf, DNameSlice, Label, NameLabels};
use super::plain::slice_from_bytes_unsafe;


//------------ ParsedDName ---------------------------------------------------

#[derive(Clone)]
pub struct ParsedDName<'a> {
    message: &'a [u8],
    start: usize
}


/// # Creation and Conversion
///
impl<'a> ParsedDName<'a> {
    pub fn parse(parser: &mut Parser<'a>) -> ParseResult<Self> {
        let res = ParsedDName{message: parser.bytes(), start: parser.pos()};

        // Step 1: Walk over uncompressed labels to advance the parser.
        let pos;
        loop {
            match try!(Self::parse_label(parser)) {
                Ok(true) => return Ok(res),
                Ok(false) => { }
                Err(x) => {
                    pos = x;
                    break
                }
            }
        }

        // Step 2: Walk over the rest to see if the name is valid.
        let mut parser = parser.clone();
        parser.remove_limit();
        try!(parser.seek(pos));
        loop {
            let step = try!(Self::parse_label(&mut parser));
            match step {
                Ok(true) => return Ok(res),
                Ok(false) => { }
                Err(pos) => try!(parser.seek(pos))
            }
        }
    }

    pub fn unpack(&self) -> Cow<'a, DNameSlice> {
        match self.split_uncompressed() {
            (Some(slice), None) => Cow::Borrowed(slice),
            (None, Some(packed)) => packed.unpack(),
            (None, None) => Cow::Borrowed(DNameSlice::empty()),
            (Some(slice), Some(packed)) => {
                let mut res = slice.to_owned();
                for label in packed.labels() {
                    res.push(label).unwrap()
                }
                Cow::Owned(res)
            }
        }
    }
}


/// # Working with Labels
///
impl<'a> ParsedDName<'a> {
    pub fn split_first(&self) -> Option<(&'a Label, Option<Self>)> {
        let mut name = self.clone();
        loop {
            let new_name = match name.split_label() {
                Ok(x) => return Some(x),
                Err(Some(x)) => x,
                Err(None) => return None
            };
            name = new_name;
        }
    }

    /// Splits a label or goes to where a pointer points.
    ///
    /// Ok((label, tail)) -> a label and what is left.
    /// Err(Some(tail)) -> re-positioned tail.
    /// Err(None) -> broken
    fn split_label(&self) -> Result<(&'a Label, Option<Self>), Option<Self>> {
        if self.message[self.start] & 0xC0 == 0xC0 {
            // Pointer label.
            let start = ((self.message[self.start] & 0x3f) as usize) << 8
                      | match self.message.get(self.start + 1) {
                          Some(two) => *two as usize,
                          None => return Err(None)
                      };
            if start >= self.message.len() {
                Err(None)
            }
            else {
                Err(Some(ParsedDName{message: self.message, start: start}))
            }
        }
        else {
            // "Real" label.
            let (label, _) = match Label::split_from(
                                                &self.message[self.start..]) {
                Some(x) => x,
                None => return Err(None)
            };
            let start = self.start + label.len();
            if label.is_root() {
                Ok((label, None))
            }
            else {
                Ok((label, Some(ParsedDName{message: self.message,
                                            start: start})))
            }
        }
    }

    /// Splits off the part that is uncompressed.
    fn split_uncompressed(&self) -> (Option<&'a DNameSlice>, Option<Self>) {
        let mut name = self.clone();
        loop {
            name = match name.split_label() {
                Ok((_, Some(new_name))) => new_name,
                Ok((label, None)) => {
                    let end = name.start + label.len();
                    let bytes = &self.message[self.start..end];
                    return (Some(unsafe { slice_from_bytes_unsafe(bytes) }),
                            None)
                }
                Err(Some(new_name)) => {
                    let bytes = &self.message[self.start..name.start];
                    return (Some(unsafe { slice_from_bytes_unsafe(bytes) }),
                            Some(new_name))
                }
                Err(None) => unreachable!()
            };
        }
    }

    /// Parses a label.
    ///
    /// Returns `Ok(is_root)` if the label is a normal label. Returns
    /// `Err(pos)` with the position of the next label.
    fn parse_label(parser: &mut Parser<'a>)
                   -> ParseResult<Result<bool, usize>> {
        let head = try!(parser.parse_u8());
        match head {
            0 => Ok(Ok(true)),
            1 ... 0x3F => parser.skip(head as usize).map(|_| Ok(false)),
            0x41 => {
                let count = try!(parser.parse_u8());
                let len = if count == 0 { 32 }
                          else { ((count - 1) / 8 + 1) as usize };
                parser.skip(len).map(|_| Ok(false))
            }
            0xC0 ... 0xFF => {
                Ok(Err(try!(parser.parse_u8()) as usize
                       + (((head & 0x3F) as usize) << 8)))
            }
            _ => Err(ParseError::UnknownLabel)
        }
    }        
}


//--- DName

impl<'a> DName for ParsedDName<'a> {
    fn to_cow(&self) -> Cow<DNameSlice> {
        self.unpack()
    }

    fn labels(&self) -> NameLabels {
        NameLabels::from_packed(self.clone())
    }
}


//--- PartialEq and Eq

impl<'a, N: DName> PartialEq<N> for ParsedDName<'a> {
    fn eq(&self, other: &N) -> bool {
        let self_iter = self.labelettes();
        let other_iter = other.labelettes();
        self_iter.eq(other_iter)
    }
}

impl<'a> PartialEq<str> for ParsedDName<'a> {
    fn eq(&self, other: &str) -> bool {
        use std::str::FromStr;

        let other = match DNameBuf::from_str(other) {
            Ok(other) => other,
            Err(_) => return false
        };
        self.eq(&other)
    }
}

impl<'a> Eq for ParsedDName<'a> { }


//--- PartialOrd and Ord

impl<'a, N: DName> PartialOrd<N> for ParsedDName<'a> {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        let self_iter = self.rev_labelettes();
        let other_iter = other.rev_labelettes();
        self_iter.partial_cmp(other_iter)
    }
}

impl<'a> Ord for ParsedDName<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let self_iter = self.rev_labelettes();
        let other_iter = other.rev_labelettes();
        self_iter.cmp(other_iter)
    }
}


//--- Hash

impl<'a> hash::Hash for ParsedDName<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.labelettes() {
            item.hash(state)
        }
    }
}


//--- std::fmt traits

impl<'a> fmt::Display for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{}", label));
        }
        for label in labels {
            try!(write!(f, ".{}", label))
        }
        Ok(())
    }
}

impl<'a> fmt::Octal for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:o}", label));
        }
        for label in labels {
            try!(write!(f, ".{:o}", label))
        }
        Ok(())
    }
}

impl<'a> fmt::LowerHex for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:x}", label));
        }
        for label in labels {
            try!(write!(f, ".{:x}", label))
        }
        Ok(())
    }
}

impl<'a> fmt::UpperHex for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:X}", label));
        }
        for label in labels {
            try!(write!(f, ".{:X}", label))
        }
        Ok(())
    }
}

impl<'a> fmt::Binary for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.labels();
        if let Some(label) = labels.next() {
            try!(write!(f, "{:b}", label));
        }
        for label in labels {
            try!(write!(f, ".{:b}", label))
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for ParsedDName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(f.write_str("ParsedDName("));
        try!(fmt::Display::fmt(self, f));
        f.write_str(")")
    }
}
