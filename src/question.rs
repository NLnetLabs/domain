//! A single question from a DNS message
//!

use std::borrow::Cow;
use std::convert;
use std::error;
use std::fmt;
use std::result;
use super::iana::{Class, RRType};
use super::name::{self, BuildDomainName, DomainName, DomainNameBuf,
                  WireDomainName};
use super::bytes::{self, BytesSlice, BytesBuf};


//------------ QuestionBuf --------------------------------------------------

/// An owned question.
///
#[derive(Debug)]
pub struct QuestionBuf {
    qname: DomainNameBuf,
    qtype: RRType,
    qclass: Class,
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
        QuestionBuf { qname: DomainNameBuf::new(), qtype: RRType::Int(0),
                      qclass: Class::IN }
    }

    pub fn from_args(name: DomainNameBuf, qtype: RRType, qclass: Class)
                     -> QuestionBuf {
        QuestionBuf { qname: name, qtype: qtype, qclass: qclass }
    }
}


impl BuildQuestion for QuestionBuf {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.qname.push_buf(buf));
        self.qtype.push_buf(buf);
        self.qclass.push_buf(buf);
        Ok(())
    }
}


//------------ WireQuestion -------------------------------------------------

#[derive(Debug)]
pub struct WireQuestion<'a> {
    qname: WireDomainName<'a>,
    qtype: RRType,
    qclass: Class,
}

/// # Creation and Conversion
///
impl<'a> WireQuestion<'a> {
    /// Creates a new frail question.
    ///
    pub fn new(qname: WireDomainName<'a>, qtype: RRType, qclass: Class)
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
        Ok((WireQuestion::new(qname, qtype.into(), qclass.into()), slice))
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
    pub fn qtype(&self) -> RRType {
        self.qtype
    }

    /// Returns the requested class.
    pub fn qclass(&self) -> Class {
        self.qclass
    }
}


impl<'a> BuildQuestion for WireQuestion<'a> {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.qname.push_buf(buf));
        self.qtype.push_buf(buf);
        self.qclass.push_buf(buf);
        Ok(())
    }
}


//----------- BuildQuestion -------------------------------------------------

pub trait BuildQuestion {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

impl<'a> BuildQuestion for (&'a DomainName, u16, u16) {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.0.push_buf(buf));
        buf.push_u16(self.1);
        buf.push_u16(self.2);
        Ok(())
    }
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

