//! Traits for record data.
//!
//! There is two classes of traits in here. The more basic two traits,
//! `RecordData` and `CompactRecordData`, need to be implemented by all
//! types. They represent creating and parsing record data, respectively.
//! They are split since some record data types contain domain names and
//! while creation is possible with all name types, parsing is only
//! available with `CompactDomainName`.
//!
//! The second two traits are for types that implement exactly one type
//! of record data. They exist to avoid having to implement certain
//! functionality multiple times. They contain implementations for the
//! first two traits.

use std::fmt;
use super::super::bytes::{BytesBuf};
use super::super::iana::RRType;
pub use super::super::question::Result; // XXX Temporary


//------------ Basic Traits -------------------------------------------------

/// A trait for creating record data.
pub trait RecordData: fmt::Display {
    /// Returns the record type for this record data instance.
    fn rtype(&self) -> RRType;

    /// Appends the record data to the end of a buffer.
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

/// A trait for parsing record data.
pub trait CompactRecordData<'a>: RecordData + Sized {
    /// Parses the record data from the slice if the type is right.
    ///
    /// If this record data type does not feel responsible for records of
    /// type `rtype`, it should return `Ok(None)`. Otherwise it should
    /// return something or an error if parsing fails.
    ///
    /// The `context` argument contains the slice of the entire DNS
    /// message for giving to `CompactDomainName`s.
    fn from_bytes(rtype: RRType, slice: &'a[u8], context: &'a[u8])
                      -> Result<Option<Self>>;
}


//------------ Traits for Concrete Types ------------------------------------

/// A trait for creating concrete record data.
///
/// This is the companion trait to `RecordData`. The only difference is that
/// `rtype()` is an associated function instead of a method since all records
/// with this data have the same type.
pub trait ConcreteRecordData<'a>: fmt::Display + Sized {
    /// Returns the record type for all records of this data type.
    fn rtype() -> RRType;

    /// Appends the record data to the end of a buffer.
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}

/// A trait for parsing concrete record data.
///
/// This is the companion trait to `CompactRecordData`.
pub trait CompactConcreteRecordData<'a>: ConcreteRecordData<'a> + Sized {
    /// Parses the record data from the slice.
    ///
    /// Since the function is only ever called if the record type was
    /// right, there is no need for an `Option<Self>`.
    fn parse(rdata: &'a[u8], context: &'a [u8]) -> Result<Self>;
}

impl<'a, C: ConcreteRecordData<'a>> RecordData for C {
    fn rtype(&self) -> RRType {
        Self::rtype()
    }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        self.push_buf(buf)
    }
}

impl<'a, C: CompactConcreteRecordData<'a>> CompactRecordData<'a> for C {
    fn from_bytes(rtype: RRType, rdata: &'a[u8], context: &'a [u8])
             -> Result<Option<Self>> {
        if rtype != Self::rtype() { Ok(None) }
        else { Ok(Some(try!(Self::parse(rdata, context)))) }
    }
}
