//! A single question from a DNS message
//!

use std::convert;
use std::error;
use std::fmt;
use std::result;
use super::iana::{Class, RRType};
use super::name::{self, DomainName, DomainNameBuf, DomainNameSlice,
                  CompactDomainName};
use super::bytes::{self, BytesSlice, BytesBuf};


//------------ Question -----------------------------------------------------

#[derive(Debug)]
pub struct Question<N: DomainName> {
    qname: N,
    qtype: RRType,
    qclass: Class,
}

type QuestionSlice<'a> = Question<&'a DomainNameSlice>;
type QuestionBuf = Question<DomainNameBuf>;
type CompactQuestion<'a> = Question<CompactDomainName<'a>>;


//--- Common functions and methods

impl<N: DomainName> Question<N> {
    pub fn new(qname: N, qtype: RRType, qclass: Class) -> Self {
        Question { qname: qname, qtype: qtype, qclass: qclass }
    }

    /// Returns the requested domain name.
    pub fn qname(&self) -> &N {
        &self.qname
    }

    /// Returns the requested record type.
    pub fn qtype(&self) -> RRType {
        self.qtype
    }

    /// Returns the requested class.
    pub fn qclass(&self) -> Class {
        self.qclass
    }

    pub fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.qname.push_buf_compressed(buf));
        self.qtype.push_buf(buf);
        self.qclass.push_buf(buf);
        Ok(())
    }
}


//--- Addtional functions and methods for owned questions

impl Default for Question<DomainNameBuf> {
    fn default() -> Self {
        Question { qname: DomainNameBuf::new(), qtype: RRType::A,
                   qclass: Class::IN }
    }
}


//--- Addtional functions and methods for compact questions

impl<'a> Question<CompactDomainName<'a>> {

    /// Splits a questions from the front of a byte slice.
    ///
    pub fn split_from(slice: &'a[u8], context: &'a[u8])
                      -> Result<(Self, &'a[u8])> {
        let (qname, slice) = try!(CompactDomainName::split_from(slice,
                                                                context));
        let (qtype, slice) = try!(slice.split_u16());
        let (qclass, slice) = try!(slice.split_u16());
        Ok((Question::new(qname, qtype.into(), qclass.into()), slice))
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

