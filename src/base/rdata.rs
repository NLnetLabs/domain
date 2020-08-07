//! Resource record data.
//!
//! Each resource record type has it’s own definition of the content and
//! formatting of its data. This module provides the basics for implementing
//! specific types for this record data. The concrete implementations for
//! well-known record types live in the top-level [domain::rdata] module.
//!
//! There are three traits herein: Any type that represents record data 
//! implements [`RecordData`]. Such a type can be added to a message. If
//! the data can also be parsed from an existing message, the type in addition
//! implements [`ParseRecordData`]. Because most types are implementations
//! for exactly one record type, the [`RtypeRecordData`] trait simplifies
//! implementations for such types.
//!
//! The module also provides a type, [`UnknownRecordData`], that can be used
//! to deal with record types whose specification is not known (or has not
//! been implemented yet).
//!
//! [`RecordData`]: trait.RecordData.html
//! [`ParseRecordData`]: trait.ParseRecordData.html
//! [`RtypeRecordData`]: trait.RtypeRecordData.html
//! [`UnknownRecorddata`]: struct.UnknownRecordData.html
//! [domain::rdata]: ../../rdata/index.html

use core::fmt;
use core::cmp::Ordering;
#[cfg(feature="master")] use bytes::{BufMut, Bytes, BytesMut};
#[cfg(feature="master")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError, SyntaxError
};
use super::cmp::CanonicalOrd;
use super::iana::Rtype;
use super::octets::{
    Compose, Convert, OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};


//----------- RecordData -----------------------------------------------------

/// A type that represents record data.
///
/// The type needs to be able to encode the record data into a DNS message
/// via the [`Compose`] trait. In addition, it needs to be
/// able to provide the record type of a record with a value’s data via the
/// [`rtype`] method.
///
/// [`Compose`]: ../compose/trait.Compose.html
/// [`rtype`]: #method.rtype
pub trait RecordData: Compose + Sized {
    /// Returns the record type associated with this record data instance.
    ///
    /// This is a method rather than an associated function to allow one
    /// type to be used for several real record types.
    fn rtype(&self) -> Rtype;
}


//------------ ParseRecordData -----------------------------------------------

/// A record data type that can be parsed from a message.
///
/// When record data types are generic – typically over a domain name type –,
/// they may not in all cases be parseable. They may still represent record
/// data to be used when constructing the message.
///
/// To reflect this asymmetry, parsing of record data has its own trait.
pub trait ParseRecordData<Ref>: RecordData {
    /// Parses the record data.
    ///
    /// The record data is for a record of type `rtype`. The function may
    /// decide whether it wants to parse data for that type. It should return
    /// `Ok(None)` if it doesn’t.
    ///
    /// The `parser` is positioned at the beginning of the record data and is
    /// is limited to the length of the data. The method only needs to parse
    /// as much data as it needs. The caller has to make sure to deal with
    /// data remaining in the parser.
    ///
    /// If the function doesn’t want to process the data, it must not touch
    /// the parser. In particual, it must not advance it.
    fn parse_data(
        rtype: Rtype,
        parser: &mut Parser<Ref>,
    ) -> Result<Option<Self>, ParseError>;
}


//------------ RtypeRecordData -----------------------------------------------

/// A type for record data for a single specific record type.
///
/// If a record data type only ever processes one single record type, things
/// can be a lot simpler. The type can be given as an associated constant
/// which can be used to implement [`RecordData`]. In addition, parsing can
/// be done atop an implementation of the [`Parse`] trait.
///
/// This trait provides such a simplification by providing [`RecordData`]
/// for all types implementing it and the other requirements for
/// [`RecordData`]. If the type additionally implements [`Parse`], it will
/// also receive a [`ParseRecordData`] implementation.
///
/// [`RecordData`]: trait.RecordData.html
/// [`ParseRecordData`]: trait.ParseRecordData.html
/// [`Parse`]: ../parse/trait.Parse.html
pub trait RtypeRecordData {
    /// The record type of a value of this type.
    const RTYPE: Rtype;
}

impl<T: RtypeRecordData + Compose + Sized> RecordData for T {
    fn rtype(&self) -> Rtype { Self::RTYPE }
}

impl<Octets, T> ParseRecordData<Octets> for T
where T: RtypeRecordData + Parse<Octets> + Compose + Sized {
    fn parse_data(
        rtype: Rtype,
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Self::RTYPE {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}


//------------ UnknownRecordData ---------------------------------------------

/// A type for parsing any type of record data.
///
/// This type accepts any record type and stores the plain, unparsed record
/// data as an octets sequence.
///
/// Because some record types allow compressed domain names in their record
/// data, this type cannot be used safely with these record types. For these
/// record types, the structure of the content needs to be known.
///
/// [RFC 3597] limits the types for which compressed names are allowed in the
/// record data to those defined in [RFC 1035] itself. Specific types for all
/// these record types exist in [`domain::rdata::rfc1035`].
///
/// Ultimately, you should only use this type for record types for which there
/// is no implementation available in this crate. The two types
/// [`AllRecordData`] and [`MasterRecordData`] provide a convenient way to
/// always use the correct record data type.
///
/// [`AllRecordData`]: ../../rdata/enum.AllRecordData.html
/// [`MasterRecordData`]: ../../rdata/enum.MasterRecordData.html
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 3597]: https://tools.ietf.org/html/rfc3597
/// [`domain::rdata::rfc1035]: ../../rdata/rfc1035/index.html
#[derive(Clone)]
pub struct UnknownRecordData<Octets> {
    /// The record type of this data.
    rtype: Rtype,

    /// The record data.
    data: Octets,
}

impl<Octets> UnknownRecordData<Octets> {
    /// Creates generic record data from a bytes value contain the data.
    pub fn from_octets(rtype: Rtype, data: Octets) -> Self {
        UnknownRecordData { rtype, data }
    }

    /// Returns the record type this data is for.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Returns a reference to the record data.
    pub fn data(&self) -> &Octets {
        &self.data
    }
}

#[cfg(feature="master")]
impl UnknownRecordData<Bytes> {
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
                        *len -= 1;
                    }
                    else {
                        *first = Some(ch)
                    }
                    Ok(())
                },
                |(_, len, first)| {
                    if first.is_some() {
                        Err(SyntaxError::UnevenHexString)
                    }
                    else {
                        Ok(len)
                    }
                }
            )?
        }
        Ok(UnknownRecordData::from_octets(rtype, res.freeze()))
    }
}


//--- PartialEq and Eq

impl<Octets, Other> PartialEq<UnknownRecordData<Other>>
for UnknownRecordData<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn eq(&self, other: &UnknownRecordData<Other>) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for UnknownRecordData<Octets> { }


//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<UnknownRecordData<Other>>
for UnknownRecordData<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn partial_cmp(
        &self,
        other: &UnknownRecordData<Other>
    ) -> Option<Ordering> {
        self.data.as_ref().partial_cmp(other.data.as_ref())
    }
}

impl<Octets, Other> CanonicalOrd<UnknownRecordData<Other>>
for UnknownRecordData<Octets>
where Octets: AsRef<[u8]>, Other: AsRef<[u8]> {
    fn canonical_cmp(&self, other: &UnknownRecordData<Other>) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Ord for UnknownRecordData<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}


//--- Convert

impl<O, Other> Convert<UnknownRecordData<Other>> for UnknownRecordData<O>
where O: Convert<Other> {
    fn convert(&self) -> Result<UnknownRecordData<Other>, ShortBuf> {
        Ok(UnknownRecordData::from_octets(self.rtype, self.data.convert()?))
    }
}


//--- Compose

impl<Octets: AsRef<[u8]>> Compose for UnknownRecordData<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.data.as_ref())
    }
}


//--- RecordData and ParseRecordData

impl<Octets: AsRef<[u8]>> RecordData for UnknownRecordData<Octets> {
    fn rtype(&self) -> Rtype {
        self.rtype
    }
}

impl<Octets, Ref> ParseRecordData<Ref> for UnknownRecordData<Octets>
where Octets: AsRef<[u8]>, Ref: OctetsRef<Range = Octets> {
    fn parse_data(
        rtype: Rtype,
        parser: &mut Parser<Ref>,
    ) -> Result<Option<Self>, ParseError> {
        let rdlen = parser.remaining();
        parser.parse_octets(rdlen).map(|data| {
            Some(Self::from_octets(rtype, data))
        })
    }
}


//--- Display

impl<Octets: AsRef<[u8]>> fmt::Display for UnknownRecordData<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.as_ref().len())?;
        for ch in self.data.as_ref() {
            write!(f, " {:02x}", *ch)?
        }
        Ok(())
    }
}


//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for UnknownRecordData<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("UnknownRecordData(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

