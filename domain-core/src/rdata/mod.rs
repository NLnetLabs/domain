//! Resource data implementations.
//!
//!
//! # Record Data of Well-defined Record Types
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [`iana::Rtype`] variant they
//! implement. They are grouped into submodules for the RFCs they are defined
//! in. All types are also re-exported at the top level here. Ie., for the
//! AAAA record type, you can simple `use domain_core::rdata::Aaaa` instead of
//! `use domain_core::rdata::rfc3596::Aaaa` which nobody could possibly
//! remember. There are, however, some helper data types defined here and
//! there which are not re-exported to keep things somewhat tidy.
//!
//! See the [`iana::Rtype`] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//!
//! [`iana::Rtype`]: ../iana/enum.Rtype.html

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc2845;
pub mod rfc3596;
pub mod rfc4034;
pub mod rfc5155;
pub mod rfc7344;

#[macro_use]
mod macros;

// The rdata_types! macro (defined in self::macros) reexports the record data
// types here and creates the MasterRecordData and AllRecordData enums
// containing all record types that can appear in master files or all record
// types that exist.
//
// All record data types listed here MUST have the same name as the
// `Rtype` variant they implement – some of the code implemented by the macro
// relies on that.
//
// Add any new module here and then add all record types in that module that
// can appear in master files under "master" and all others under "pseudo".
// Your type can be generic over an octet type "O" and a domain name type "N".
// Add these as needed.
//
// Each type entry has to be followed by a comma, even the last one. The macro
// is messy enough as it is ...
rdata_types! {
    rfc1035::{
        master {
            A,
            Cname<N>,
            Hinfo<O>,
            Mb<N>,
            Md<N>,
            Mf<N>,
            Minfo<N>,
            Mr<N>,
            Mx<N>,
            Ns<N>,
            Ptr<N>,
            Soa<N>,
            Txt<O>,
            Wks<O>,
        }
        pseudo {
            Null<O>,
        }
    }
    rfc2782::{
        master {
            Srv<N>,
        }
    }
    rfc2845::{
        pseudo {
            Tsig<O, N>,
        }
    }
    rfc3596::{
        master {
            Aaaa,
        }
    }
    rfc4034::{
        master {
            Dnskey<O>,
            Rrsig<O, N>,
            Nsec<O, N>,
            Ds<O>,
        }
    }
    rfc5155::{
        master {
            Nsec3<O>,
            Nsec3param<O>,
        }
    }
    rfc7344::{
        master {
            Cdnskey<O>,
            Cds<O>,
        }
    }
}

use core::fmt;
use core::cmp::Ordering;
#[cfg(feature="bytes")] use bytes::{BufMut, Bytes, BytesMut};
use crate::cmp::CanonicalOrd;
use crate::iana::Rtype;
#[cfg(feature="bytes")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError, SyntaxError
};
use crate::octets::{Compose, OctetsBuilder, OctetsRef, ShortBuf};
use crate::parse::{Parse, ParseError, Parser};


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
pub trait ParseRecordData<Octets>: RecordData {
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
        parser: &mut Parser<Octets>,
    ) -> Result<Option<Self>, ParseError>;
}


//------------ RtypeRecordData -----------------------------------------------

/// A type for record data for a single specific record type.
///
/// If a record data type only ever processes one single record type, things
/// can be a lot simpler. The type can be given as an associated constant
/// which can be used to implement [`RecordData`]. In addition, parsing can
/// be done atop an implementation of the [`ParseAll`] trait.
///
/// This trait provides such a simplification by providing [`RecordData`]
/// for all types implementing it and the other requirements for
/// [`RecordData`]. If the type additionally implements [`ParseAll`], it will
/// also receive a [`ParseRecordData`] implementation.
///
/// [`RecordData`]: trait.RecordData.html
/// [`ParseRecordData`]: trait.ParseRecordData.html
/// [`ParseAll`]: ../parse/trait.ParseAll.html
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
/// This type accepts any record type and stores a reference to the plain
/// binary record data in the message.
///
/// Because some record types allow compressed domain names in their record
/// data yet values only contain the data’s own bytes, this type cannot be
/// used safely with these record types.
///
/// [RFC 3597] limits the types for which compressed names are allowed in the
/// record data to those defined in [RFC 1035] itself. Specific types for all
/// these record types exist in [`domain::rdata::rfc1035`].
///
/// Ultimately, you should only use this type for record types for which there
/// is no implementation available in this crate.
///
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

#[cfg(feature="bytes")]
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


//--- Compose, and Compress

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

