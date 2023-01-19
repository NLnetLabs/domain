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

use super::cmp::CanonicalOrd;
use super::iana::Rtype;
use super::scan::{Scan, Scanner, ScannerError, Symbol};
use super::wire::{Compose, Composer, ParseError};
use crate::utils::base16;
use core::cmp::Ordering;
use core::fmt;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;

//----------- RecordData -----------------------------------------------------

/// A type that represents record data.
///
/// The type needs to be able to to be able to provide the record type of a
/// record with a value’s data via the [`rtype`][Self::rtype] method.
pub trait RecordData {
    /// Returns the record type associated with this record data instance.
    ///
    /// This is a method rather than an associated function to allow one
    /// type to be used for several real record types.
    fn rtype(&self) -> Rtype;
}

impl<'a, T: RecordData> RecordData for &'a T {
    fn rtype(&self) -> Rtype {
        (*self).rtype()
    }
}

//----------- ComposeRecordData ----------------------------------------------

/// A type of record data that can be composed.
pub trait ComposeRecordData: RecordData {
    /// Returns the length of the record data if available.
    ///
    /// The method should return `None`, if the length is not known or is not
    /// the same for all targets.
    ///
    /// If `compress` is `true`, name compression is available in the target.
    /// If name compression would be used in `compose_rdata`, the method
    /// should `None` if `compress` is `true` since it can’t know the final
    /// size.
    fn rdlen(&self, compress: bool) -> Option<u16>;

    /// Appends the wire format of the record data into `target`.
    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;

    /// Appends the canonical wire format of the record data into `target`.
    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError>;

    /// Appends the record data prefixed with its length.
    fn compose_len_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if let Some(rdlen) = self.rdlen(target.can_compress()) {
            rdlen.compose(target)?;
            self.compose_rdata(target)
        } else {
            compose_prefixed(target, |target| self.compose_rdata(target))
        }
    }

    /// Appends the record data prefixed with its length.
    fn compose_canonical_len_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if let Some(rdlen) = self.rdlen(false) {
            rdlen.compose(target)?;
            self.compose_canonical_rdata(target)
        } else {
            compose_prefixed(target, |target| {
                self.compose_canonical_rdata(target)
            })
        }
    }
}

fn compose_prefixed<Target: Composer + ?Sized, F>(
    target: &mut Target,
    op: F,
) -> Result<(), Target::AppendError>
where
    F: FnOnce(&mut Target) -> Result<(), Target::AppendError>,
{
    target.append_slice(&[0; 2])?;
    let pos = target.as_ref().len();
    match op(target) {
        Ok(_) => {
            let len = u16::try_from(target.as_ref().len() - pos)
                .expect("long data");
            target.as_mut()[pos - 2..pos]
                .copy_from_slice(&(len).to_be_bytes());
            Ok(())
        }
        Err(err) => {
            target.truncate(pos);
            Err(err)
        }
    }
}

impl<'a, T: ComposeRecordData> ComposeRecordData for &'a T {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        (*self).rdlen(compress)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        (*self).compose_rdata(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        (*self).compose_canonical_rdata(target)
    }
}

//------------ ParseRecordData -----------------------------------------------

/// A record data type that can be parsed from a message.
///
/// When record data types are generic – typically over a domain name type –,
/// they may not in all cases be parseable. They may still represent record
/// data to be used when constructing the message.
///
/// To reflect this asymmetry, parsing of record data has its own trait.
pub trait ParseRecordData<'a, Octs: ?Sized>: RecordData + Sized {
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
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError>;
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
/// these record types exist in
/// [`domain::rdata::rfc1035`][crate::rdata::rfc1035].
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnknownRecordData<Octs> {
    /// The record type of this data.
    rtype: Rtype,

    /// The record data.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::utils::base16::serde::serialize",
            deserialize_with = "crate::utils::base16::serde::deserialize",
            bound(
                serialize = "Octs: AsRef<[u8]> + octseq::serde::SerializeOctets",
                deserialize = "\
                    Octs: \
                        octseq::builder::FromBuilder + \
                        octseq::serde::DeserializeOctets<'de>, \
                    <Octs as octseq::builder::FromBuilder>::Builder: \
                        octseq::builder::EmptyBuilder, \
                ",
            )
        )
    )]
    data: Octs,
}

impl<Octs> UnknownRecordData<Octs> {
    /// Creates generic record data from a bytes value contain the data.
    pub fn from_octets(
        rtype: Rtype,
        data: Octs,
    ) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
    {
        if data.as_ref().len() > 0xFFFF {
            Err(LongRecordData())
        } else {
            Ok(UnknownRecordData { rtype, data })
        }
    }

    /// Returns the record type this data is for.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Returns a reference to the record data.
    pub fn data(&self) -> &Octs {
        &self.data
    }

    /// Scans the record data.
    ///
    /// This isn’t implemented via `Scan`, because we need the record type.
    pub fn scan<S: Scanner<Octets = Octs>>(
        rtype: Rtype,
        scanner: &mut S,
    ) -> Result<Self, S::Error>
    where
        Octs: AsRef<[u8]>,
    {
        // First token is literal "\#".
        let mut first = true;
        scanner.scan_symbols(|symbol| {
            if first {
                first = false;
                match symbol {
                    Symbol::SimpleEscape(b'#') => Ok(()),
                    _ => Err(S::Error::custom("'\\#' expected")),
                }
            } else {
                Err(S::Error::custom("'\\#' expected"))
            }
        })?;
        Self::scan_without_marker(rtype, scanner)
    }

    /// Scans the record data assuming that the marker has been skipped.
    pub fn scan_without_marker<S: Scanner<Octets = Octs>>(
        rtype: Rtype,
        scanner: &mut S,
    ) -> Result<Self, S::Error>
    where
        Octs: AsRef<[u8]>,
    {
        // Second token is the rdata length.
        let len = u16::scan(scanner)?;

        // The rest is the actual data.
        let data = scanner.convert_entry(base16::SymbolConverter::new())?;

        if data.as_ref().len() != usize::from(len) {
            return Err(S::Error::custom(
                "generic data has incorrect length",
            ));
        }

        Ok(UnknownRecordData { rtype, data })
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<UnknownRecordData<SrcOcts>>
    for UnknownRecordData<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: UnknownRecordData<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Ok(UnknownRecordData {
            rtype: source.rtype,
            data: Octs::try_octets_from(source.data)?,
        })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<UnknownRecordData<Other>>
    for UnknownRecordData<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &UnknownRecordData<Other>) -> bool {
        self.data.as_ref().eq(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for UnknownRecordData<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<UnknownRecordData<Other>>
    for UnknownRecordData<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(
        &self,
        other: &UnknownRecordData<Other>,
    ) -> Option<Ordering> {
        self.data.as_ref().partial_cmp(other.data.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<UnknownRecordData<Other>>
    for UnknownRecordData<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &UnknownRecordData<Other>) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for UnknownRecordData<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.data.as_ref().cmp(other.data.as_ref())
    }
}

//--- ComposeRecordData

impl<Octs: AsRef<[u8]>> ComposeRecordData for UnknownRecordData<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(u16::try_from(self.data.as_ref().len()).expect("long rdata"))
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.data.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- RecordData and ParseRecordData

impl<Octs: AsRef<[u8]>> RecordData for UnknownRecordData<Octs> {
    fn rtype(&self) -> Rtype {
        self.rtype
    }
}

impl<'a, Octs: Octets> ParseRecordData<'a, Octs>
    for UnknownRecordData<Octs::Range<'a>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        let rdlen = parser.remaining();
        parser
            .parse_octets(rdlen)
            .map(|data| Some(Self { rtype, data }))
            .map_err(Into::into)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for UnknownRecordData<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\\# {}", self.data.as_ref().len())?;
        for ch in self.data.as_ref() {
            write!(f, " {:02x}", *ch)?
        }
        Ok(())
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for UnknownRecordData<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("UnknownRecordData(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//------------ LongRecordData ------------------------------------------------

/// The octets sequence to be used for record data is too long.
#[derive(Clone, Copy, Debug)]
pub struct LongRecordData();

impl fmt::Display for LongRecordData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("record data too long")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongRecordData {}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
pub(crate) mod test {
    use super::super::scan::{IterScanner, Scanner};
    use super::super::wire::ParseError;
    use super::*;
    use bytes::{Bytes, BytesMut};
    use core::fmt::Debug;
    use octseq::builder::infallible;
    use std::vec::Vec;

    /// Check that `rdlen` produces the correct length.
    ///
    /// The test composes `data` both regularly and cannonically and checks
    /// that the length of the composed data matches what `rdlen` returns.
    ///
    /// This test expects that `rdlen` returns some value if `compress`
    /// is false. This isn’t required but all our record types are supposed
    /// to do this, anyway.
    pub fn test_rdlen<R: ComposeRecordData>(data: R) {
        let mut buf = Vec::new();
        infallible(data.compose_rdata(&mut buf));
        assert_eq!(buf.len(), usize::from(data.rdlen(false).unwrap()));
        buf.clear();
        infallible(data.compose_canonical_rdata(&mut buf));
        assert_eq!(buf.len(), usize::from(data.rdlen(false).unwrap()));
    }

    /// Check that composing and parsing are reverse operations.
    pub fn test_compose_parse<In, F, Out>(data: &In, parse: F)
    where
        In: ComposeRecordData + PartialEq<Out> + Debug,
        F: FnOnce(&mut Parser<Bytes>) -> Result<Out, ParseError>,
        Out: Debug,
    {
        let mut buf = BytesMut::new();
        infallible(data.compose_rdata(&mut buf));
        let buf = buf.freeze();
        let mut parser = Parser::from_ref(&buf);
        let parsed = (parse)(&mut parser).unwrap();
        assert_eq!(parser.remaining(), 0);
        assert_eq!(*data, parsed);
    }

    type TestScanner =
        IterScanner<std::vec::IntoIter<std::string::String>, Vec<u8>>;

    /// Checks scanning.
    pub fn test_scan<F, T, X>(input: &[&str], scan: F, expected: &X)
    where
        F: FnOnce(
            &mut TestScanner,
        ) -> Result<T, <TestScanner as Scanner>::Error>,
        T: Debug,
        X: Debug + PartialEq<T>,
    {
        let mut scanner = IterScanner::new(
            input
                .iter()
                .map(|s| std::string::String::from(*s))
                .collect::<Vec<_>>(),
        );
        assert_eq!(*expected, scan(&mut scanner).unwrap(),);
        assert!(scanner.is_exhausted());
    }
}
