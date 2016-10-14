//! Basic resource data handling.
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

use std::fmt;
use ::iana::Rtype;
use ::rdata::fmt_rdata;
use super::{Composer, ComposeResult, Parser, ParseResult};


//----------- RecordData -----------------------------------------------------

/// A trait for types representing record data.
pub trait RecordData: Sized {
    /// Returns the record type for this record data instance.
    ///
    /// This is a method rather than an associated function to allow one
    /// type to be used for several real record types.
    fn rtype(&self) -> Rtype;

    /// Appends the record data to the end of a composer.
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()>;
}


//------------ ParsedRecordData ----------------------------------------------

/// A trait for types that allow parsing record data from a message.
pub trait ParsedRecordData<'a>: RecordData {
    /// Parses the record data out of a parser.
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>>;
}


//------------ GenericRecordData --------------------------------------------

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
#[derive(Clone, Debug)]
pub struct GenericRecordData<'a> {
    /// The record type of this data.
    rtype: Rtype,

    /// A parser for the record’s data.
    ///
    /// The parser will be positioned at the beginning of the record data and
    /// will be limited to the length of the record data.
    parser: Parser<'a>,
}

impl<'a> GenericRecordData<'a> {
    /// Tries to re-parse the data for the given record data type.
    ///
    /// # Panics
    ///
    /// This method panics if the specified record data type does not
    /// actually feel like parsing data of the value’s record type.
    fn reparse<D: ParsedRecordData<'a>>(&self) -> ParseResult<D> {
        D::parse(self.rtype, &mut self.parser.clone()).map(Option::unwrap)
    }
}

impl<'a> RecordData for GenericRecordData<'a> {
    fn rtype(&self) -> Rtype {
        self.rtype
    }

    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                        -> ComposeResult<()> {
        use ::rdata::rfc1035::parsed::*;

        match self.rtype {
            // Special treatment for any type from RFC 1035 that contains
            // domain names.
            Rtype::Cname => try!(self.reparse::<Cname>()).compose(target),
            Rtype::Mb => try!(self.reparse::<Mb>()).compose(target),
            Rtype::Md => try!(self.reparse::<Md>()).compose(target),
            Rtype::Mf => try!(self.reparse::<Mf>()).compose(target),
            Rtype::Mg => try!(self.reparse::<Mg>()).compose(target),
            Rtype::Minfo => try!(self.reparse::<Minfo>()).compose(target),
            Rtype::Mr => try!(self.reparse::<Mr>()).compose(target),
            Rtype::Mx => try!(self.reparse::<Mx>()).compose(target),
            Rtype::Ns => try!(self.reparse::<Ns>()).compose(target),
            Rtype::Ptr => try!(self.reparse::<Ptr>()).compose(target),
            Rtype::Soa => try!(self.reparse::<Soa>()).compose(target),

            // Anything else can go verbatim.
            _ => {
                let len = self.parser.remaining();
                let bytes = try!(self.parser.clone().parse_bytes(len));
                target.as_mut().compose_bytes(bytes)
            }
        }
    }
}

impl<'a> ParsedRecordData<'a> for GenericRecordData<'a> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        let my_parser = parser.clone();
        let len = parser.remaining();
        try!(parser.skip(len));
        Ok(Some(GenericRecordData {
            rtype: rtype,
            parser: my_parser
        }))
    }
}

impl<'a> fmt::Display for GenericRecordData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_rdata(self.rtype, &mut self.parser.clone(), f)
    }
}

