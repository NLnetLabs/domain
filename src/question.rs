//! A single question from a DNS message
//!

use std::borrow::Cow;
use std::convert;
use std::error;
use std::fmt;
use std::result;
use super::name::{self, BuildDomainName, DomainName, DomainNameBuf,
                  WireDomainName};
use super::bytes::{self, BytesSlice, BytesBuf};


//------------ QuestionBuf --------------------------------------------------

/// An owned question.
///
#[derive(Debug)]
pub struct QuestionBuf {
    qname: name::DomainNameBuf,
    qtype: u16,
    qclass: u16,
}

/// # Creation and Conversion
///
impl QuestionBuf {
    /// Creates a new empty question.
    ///
    /// The domain name will be empty, the type will be 0, and the class
    /// will be 1 (IN).
    ///
    pub fn new() -> QuestionBuf {
        QuestionBuf { qname: DomainNameBuf::new(), qtype: 0, qclass: 1 }
    }
}


impl BuildQuestion for QuestionBuf {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.qname.push_buf(buf));
        buf.push_u16(self.qtype);
        buf.push_u16(self.qclass);
        Ok(())
    }
}


//------------ WireQuestion -------------------------------------------------

#[derive(Debug)]
pub struct WireQuestion<'a> {
    qname: WireDomainName<'a>,
    qtype: u16,
    qclass: u16,
}

/// # Creation and Conversion
///
impl<'a> WireQuestion<'a> {
    /// Creates a new frail question.
    ///
    pub fn new(qname: WireDomainName<'a>, qtype: u16, qclass: u16)
               -> WireQuestion<'a> {
        WireQuestion { qname: qname, qtype: qtype, qclass: qclass }
    }

    /// Splits a questions from the front of a byte slice.
    ///
    pub fn split_from(slice: &'a[u8], context: &'a[u8])
                      -> Result<(WireQuestion<'a>, &'a[u8])> {
        let (qname, slice) = try!(WireDomainName::split_from(slice,
                                                              context));
        let (qtype, slice) = try!(slice.split_u16());
        let (qclass, slice) = try!(slice.split_u16());
        Ok((WireQuestion::new(qname, qtype, qclass), slice))
    }

    /// Converts `self` to an owned `QuestionBuf`.
    ///
    pub fn to_owned(&self) -> Result<QuestionBuf> {
        Ok(QuestionBuf { qname: try!(self.qname.to_owned()),
                         qtype: self.qtype, qclass: self.qclass })
    }
}

/// # Element access
///
impl<'a> WireQuestion<'a> {
    /// Returns the requested domain name.
    pub fn qname(&self) -> WireDomainName<'a> {
        self.qname.clone()
    }

    /// Returns the uncompressed requested domain name.
    pub fn decompressed_qname(&self) -> Result<Cow<DomainName>> {
        Ok(try!(self.qname.decompress()))
    }

    /// Returns the requested record type.
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    /// Returns the requested class.
    pub fn qclass(&self) -> u16 {
        self.qclass
    }
}


impl<'a> BuildQuestion for WireQuestion<'a> {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.qname.push_buf(buf));
        buf.push_u16(self.qtype);
        buf.push_u16(self.qclass);
        Ok(())
    }
}


//----------- BuildQuestion -------------------------------------------------

pub trait BuildQuestion {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

 
//------------ Error and Result ---------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    NameError(name::ErrorKind),
    OctetError(bytes::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::NameError(ref kind) => kind.description(),
            Error::OctetError(ref error) => {
                use std::error::Error;

                error.description()
            }
        }
    }
}

impl convert::From<bytes::Error> for Error {
    fn from(error: bytes::Error) -> Error {
        Error::OctetError(error)
    }
}

impl convert::From<name::Error> for Error {
    fn from(error: name::Error) -> Error {
        match error {
            name::Error::NameError(kind) => Error::NameError(kind),
            name::Error::OctetError(error) => Error::OctetError(error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}

pub type Result<T> = result::Result<T, Error>;

