//! Resource data handling.
//!
//! DNS resource records consist of some common data defining the domain
//! name they pertain to, their type and class, and finally record data
//! the format of which depends on the specific record type. As there are
//! currently more than eighty record types, having a giant enum for record
//! data seemed like a bad idea. Instead, resource records are generic over
//! two traits defined by this module. All concrete types implement
//! [`RecordData`]. Types that can be parsed out of messages also implement
//! [`ParsedRecordData`]. This distinction is only relevant for types that
//! contain and are generic over domain names: for these, parsing is only
//! available if the names use [`ParsedDName`].
//!
//! All concrete types shipped with this crate are implemented in the
//! [`domain::rdata`] module.
//!
//! In order to walk over all resource records in a message or work with
//! unknown record types, this module also defines the [`GenericRecordData`]
//! type that can deal with all record types but provides only a limited
//! functionality.
//!
//! [`RecordData`]: trait.RecordData.html
//! [`ParsedRecordData`]: trait.ParsedRecordData.html
//! [`domain::rdata`]: ../../rdata/index.html
//! [`GenericRecordData`]: struct.GenericRecordData.html

use std::{fmt, io};
use std::io::Write;
use bytes::{BufMut, Bytes, BytesMut};
use ::iana::Rtype;
use ::master::print::{Print, Printer};
use ::master::scan::{CharSource, Scan, Scanner, ScanError, SyntaxError};
use super::compose::{Compose, Compress, Compressor};
use super::parse::{ParseAll, Parser, ShortBuf};


//----------- RecordData -----------------------------------------------------

/// A trait for types representing record data.
pub trait RecordData: Compose + Compress + Sized {
    /// Returns the record type for this record data instance.
    ///
    /// This is a method rather than an associated function to allow one
    /// type to be used for several real record types.
    fn rtype(&self) -> Rtype;
}


//------------ ParseRecordData -----------------------------------------------

pub trait ParseRecordData: RecordData {
    /// The type of an error returned when parsing fails.
    type Err;

    /// Parses the record data.
    ///
    /// The record data is for a record of type `rtype`. The function may
    /// decide whether it wants to parse data for that type and return
    /// `Ok(None)` if it doesn’t. The data is `rdlen` bytes long and starts
    /// at the current position of `parser`. Their is no guarantee that the
    /// parser will have `rdlen` bytes left. If it doesn’t, the function
    /// should produce an error.
    ///
    /// If the function doesn’t want to process the data, it must not touch
    /// the parser. In particual, it must not advance it.
    fn parse_data(rtype: Rtype, parser: &mut Parser, rdlen: usize)
                  -> Result<Option<Self>, Self::Err>;
}


//------------ RtypeRecordData -----------------------------------------------

pub trait RtypeRecordData {
    const RTYPE: Rtype;
}

impl<T: RtypeRecordData + Compose + Compress + Sized> RecordData for T {
    fn rtype(&self) -> Rtype { Self::RTYPE }
}

impl<T: RtypeRecordData + ParseAll + Compose + Compress + Sized>
            ParseRecordData for T {
    type Err = <Self as ParseAll>::Err;

    fn parse_data(rtype: Rtype, parser: &mut Parser, rdlen: usize)
                  -> Result<Option<Self>, Self::Err> {
        if rtype == Self::RTYPE {
            Self::parse_all(parser, rdlen).map(Some)
        }
        else {
            Ok(None)
        }
    }
}


//------------ UnknownRecordData ---------------------------------------------

/// A type for parsing any type of record data.
///
/// This type accepts any record type and stores a reference to the plain
/// binary record data in the message. This way, it can later be converted
/// into concrete record data if necessary via the [`reparse()`] method.
///
/// Because the data referenced by a value may contain compressed domain
/// names, transitively building a new message from this data may lead to
/// corrupt messages. To avoid this sort of thing, 
/// [RFC 3597], ‘Handling of Unknown DNS Resource Record (RR) Types,’
/// restricted compressed domain names to record types defined in [RFC 1035].
/// Accordingly, this types [`RecordData::compose()`] implementation treats
/// these types specially and ensures that their names are handles correctly.
/// This may still lead to corrupt messages, however, if the generic record
/// data is obtained from a source not complying with RFC 3597. In general,
/// be wary when re-composing parsed messages unseen.
///
/// [`RecordData::compose()`]: trait.RecordData.html#tymethod.compose
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 3597]: https://tools.ietf.org/html/rfc3597
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnknownRecordData {
    /// The record type of this data.
    rtype: Rtype,

    /// The record data.
    data: Bytes,
}

impl UnknownRecordData {
    /// Creates generic record data from a bytes value contain the data.
    pub fn from_bytes(rtype: Rtype, data: Bytes) -> Self {
        UnknownRecordData { rtype, data }
    }

    /// Scans the record data.
    ///
    /// This isn’t implemented via `Scan`, because we need the record type.
    pub fn scan<C: CharSource>(rtype: Rtype, scanner: &mut Scanner<C>)
                               -> Result<Self, ScanError> {
        scanner.skip_literal("\\#")?;
        let mut len = u16::scan(scanner)? as usize;
        let mut res = BytesMut::with_capacity(len);
        while len > 0 {
            len = scanner.scan_word(
                (&mut res, len, None), // buffer and optional first char
                |&mut (ref mut res, ref mut len, ref mut first), symbol| {
                    if *len == 0 {
                        return Err(SyntaxError::LongGenericData)
                    }
                    let ch = symbol.into_digit(16)? as u8;
                    if let Some(ch1) = *first {
                        res.put_u8(ch1 << 4 | ch);
                        *len = *len - 1;
                    }
                    else {
                        *first = Some(ch)
                    }
                    Ok(())
                },
                |(_, len, first)| {
                    if let Some(_) = first {
                        Err(SyntaxError::UnevenHexString)
                    }
                    else {
                        Ok(len)
                    }
                }
            )?
        }
        Ok(UnknownRecordData::from_bytes(rtype, res.freeze()))
    }
}


//--- Compose, and Compress

impl Compose for UnknownRecordData {
    fn compose_len(&self) -> usize {
        self.data.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.data.as_ref())
    }
}

impl Compress for UnknownRecordData {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- RecordData and ParseRecordData

impl RecordData for UnknownRecordData {
    fn rtype(&self) -> Rtype {
        self.rtype
    }
}

impl ParseRecordData for UnknownRecordData {
    type Err = ShortBuf;

    fn parse_data(rtype: Rtype, parser: &mut Parser, rdlen: usize)
                  -> Result<Option<Self>, Self::Err> {
        parser.parse_bytes(rdlen)
              .map(|data| Some(Self::from_bytes(rtype, data)))
    }
}


//--- Print, and Display

impl Print for UnknownRecordData {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "\\# {}", self.data.len())?;
        for ch in self.data.as_ref() {
            write!(printer.item()?, " {:02x}", *ch)?
        }
        Ok(())
    }
}

impl fmt::Display for UnknownRecordData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.len())?;
        for ch in self.data.as_ref() {
            write!(f, " {:02x}", *ch)?
        }
        Ok(())
    }
}

