
use std::{cmp, error, fmt, hash, ops};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::parse::{Parseable, Parser, ShortParser};
use super::label::{Label, SplitLabelError};
use super::dname::{Dname, DnameError, DnameIter};
use super::traits::{ToLabelIter, ToDname, ToFqdn};


//------------ Fqdn ----------------------------------------------------------

#[derive(Clone)]
pub struct Fqdn {
    bytes: Bytes
}


/// # Creation and Conversion
///
impl Fqdn {
    pub fn root() -> Self {
        Fqdn { bytes: Bytes::from_static(b"\0") }
    }

    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Fqdn { bytes }
    }

    pub fn from_bytes(bytes: Bytes) -> Result<Self, FqdnError> {
        Self::from_dname(Dname::from_bytes(bytes)?).map_err(Into::into)
    }

    pub fn from_dname(dname: Dname) -> Result<Self, RelativeDname> {
        if dname.is_absolute() {
            Ok(Fqdn { bytes: dname.into_bytes() })
        }
        else {
            Err(RelativeDname)
        }
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn into_dname(self) -> Dname {
        Dname::from_fqdn(self)
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
}


/// # Working with Labels
///
impl Fqdn {
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.bytes.as_ref())
    }

    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    pub fn last(&self) -> Option<&Label> {
        self.iter().next_back()
    }

    pub fn starts_with(&self, base: &Dname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let start = &self.bytes.as_ref()[..base.len()];
        base.as_slice().eq_ignore_ascii_case(start)
    }

    pub fn ends_with(&self, base: &Dname) -> bool {
        if base.len() > self.len() {
            return false
        }
        let (_, right) = match self.split_at(self.len() - base.len()) {
            Ok(res) => res,
            Err(_) => return false,
        };
        right.bytes.as_ref().eq_ignore_ascii_case(base.as_slice())
    }

    pub fn split_at(&self, mid: usize) -> Result<(Dname, Fqdn), DnameError> {
        assert!(mid <= self.len());
        let left = Dname::from_bytes(self.bytes.slice_to(mid))?;
        let right = Fqdn { 
            bytes: self.bytes.slice_from(mid),
        };
        Ok((left, right))
    }

    pub fn split_first(&self) -> (Dname, Option<Fqdn>) {
        let (left, right) = self.clone().into_dname().split_first().unwrap();
        (left, right.into_fqdn().ok())
    }

    pub fn parent(&self) -> Option<Fqdn> {
        self.split_first().1
    }

    /*
    pub fn strip_suffix(&self, base: &Fqdn)
                        -> Result<Dname, StripSuffixError> {
    }
    */
}

//--- Parseable and Composable

impl Parseable for Fqdn {
    type Err = ParseFqdnError;

    fn parse(parser: &mut Parser) -> Result<Self, ParseFqdnError> {
        let len = {
            let mut tmp = parser.peek();
            loop {
                if tmp.is_empty() {
                    return Err(ParseFqdnError::ShortParser)
                }
                let (label, tail) = Label::split_from(tmp)?;
                tmp = tail;
                if label.is_root() {
                    break;
                }
            }
            parser.remaining() - tmp.len()
        };
        if len > 255 {
            return Err(ParseFqdnError::BadDname(DnameError::TooLong));
        }
        Ok(Fqdn { bytes: parser.parse_bytes(len).unwrap() })
    }
}

impl Composable for Fqdn {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
}


//--- ToLabelIter, ToDname, and ToFqdn

impl<'a> ToLabelIter<'a> for Fqdn {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToDname for Fqdn {
    fn is_absolute(&self) -> bool {
        true
    }
}

impl ToFqdn for Fqdn { }


//--- Deref and AsRef

impl ops::Deref for Fqdn {
    type Target = Bytes;

    fn deref(&self) -> &Bytes {
        self.as_ref()
    }
}

impl AsRef<Bytes> for Fqdn {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl AsRef<[u8]> for Fqdn {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a Fqdn {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl PartialEq for Fqdn {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_slice())
    }
}

impl Eq for Fqdn { }


//--- PartialOrd and Ord

impl PartialOrd for Fqdn {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter())
    }
}

impl Ord for Fqdn {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


//--- Hash

impl hash::Hash for Fqdn {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Display and Debug

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        match iter.next() {
            Some(label) => label.fmt(f)?,
            None => return Ok(())
        }
        while let Some(label) = iter.next() {
            f.write_str(".")?;
            label.fmt(f)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Fqdn({})", self)
    }
}


//------------ FqdnError -----------------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FqdnError {
    /// A bad domain name was encountered.
    BadDname(DnameError),

    /// The name didn’t end with the root label.
    RelativeDname,
}

impl From<DnameError> for FqdnError {
    fn from(err: DnameError) -> Self {
        FqdnError::BadDname(err)
    }
}

impl From<SplitLabelError> for FqdnError {
    fn from(err: SplitLabelError) -> Self {
        FqdnError::BadDname(err.into())
    }
}

impl From<RelativeDname> for FqdnError {
    fn from(_: RelativeDname) -> Self {
        FqdnError::RelativeDname
    }
}

impl error::Error for FqdnError {
    fn description(&self) -> &str {
        use self::FqdnError::*;

        match *self {
            BadDname(ref err) => err.description(),
            RelativeDname => "relative domain name",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        use self::FqdnError::*;

        match *self {
            BadDname(ref err) => Some(err),
            _ => None
        }
    }
}

impl fmt::Display for FqdnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ ParseFqdnError ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseFqdnError {
    BadDname(DnameError),
    ShortParser,
}

impl From<DnameError> for ParseFqdnError {
    fn from(err: DnameError) -> ParseFqdnError {
        ParseFqdnError::BadDname(err)
    }
}

impl From<SplitLabelError> for ParseFqdnError {
    fn from(err: SplitLabelError) -> ParseFqdnError {
        ParseFqdnError::BadDname(err.into())
    }
}

impl From<ShortParser> for ParseFqdnError {
    fn from(_: ShortParser) -> ParseFqdnError {
        ParseFqdnError::ShortParser
    }
}

impl error::Error for ParseFqdnError {
    fn description(&self) -> &str {
        match *self {
            ParseFqdnError::BadDname(ref err) => err.description(),
            ParseFqdnError::ShortParser => ShortParser.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            ParseFqdnError::BadDname(ref err) => Some(err),
            ParseFqdnError::ShortParser => Some(&ShortParser),
        }
    }
}

impl fmt::Display for ParseFqdnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}


//------------ RelativeDname -------------------------------------------------

/// An attempt was made to convert a relative domain name into an FQDN.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelativeDname;

impl error::Error for RelativeDname {
    fn description(&self) -> &str {
        "relative domain name"
    }
}

impl fmt::Display for RelativeDname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(error::Error::description(self))
    }
}



