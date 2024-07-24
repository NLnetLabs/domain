//! Zone related errors.

use std::fmt::Display;
use std::io;
use std::vec::Vec;

use crate::base::iana::Class;
use crate::base::Rtype;
use crate::zonefile::inplace;

use super::types::{StoredName, StoredRecord};

//------------ ZoneCutError --------------------------------------------------

/// A zone cut is not valid with respect to the zone's apex.
#[derive(Clone, Copy, Debug)]
pub enum ZoneCutError {
    /// A zone cut cannot exist outside of the zone.
    OutOfZone,

    /// A zone cut cannot exist at the apex of a zone.
    ZoneCutAtApex,
}

impl From<OutOfZone> for ZoneCutError {
    fn from(_: OutOfZone) -> ZoneCutError {
        ZoneCutError::OutOfZone
    }
}

impl Display for ZoneCutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneCutError::OutOfZone => write!(f, "Out of zone"),
            ZoneCutError::ZoneCutAtApex => write!(f, "Zone cut at apex"),
        }
    }
}

//----------- CnameError -----------------------------------------------------

/// A CNAME is not valid with respect to the zone's apex.
#[derive(Clone, Copy, Debug)]
pub enum CnameError {
    /// A CNAME cannot exist outside of the zone.
    OutOfZone,

    /// A CNAME cannot exist at the apex of a zone.
    CnameAtApex,
}

impl From<OutOfZone> for CnameError {
    fn from(_: OutOfZone) -> CnameError {
        CnameError::OutOfZone
    }
}

impl Display for CnameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CnameError::OutOfZone => write!(f, "Out of zone"),
            CnameError::CnameAtApex => write!(f, "CNAME at apex"),
        }
    }
}

//----------- OutOfZone ------------------------------------------------------

/// A domain name is not under the zone’s apex.
#[derive(Clone, Copy, Debug)]
pub struct OutOfZone;

//------------ RecordError ---------------------------------------------------

/// A zone file record is invalid.
#[derive(Clone, Debug)]
pub enum RecordError {
    /// The class of the record does not match the class of the zone.
    ClassMismatch(StoredRecord, Class),

    /// Attempted to add zone cut records where there is no zone cut.
    ///
    /// At least one record of non-zone cut type Rtype already exists.
    IllegalZoneCut(StoredRecord, Rtype),

    /// Attempted to add a normal record to a zone cut or CNAME.
    IllegalRecord(StoredRecord, Rtype),

    /// Attempted to add a CNAME record where there are other records.
    ///
    /// At least one record of type Rtype already exists.
    IllegalCname(StoredRecord, Rtype),

    /// Attempted to add multiple CNAME records for an owner.
    MultipleCnames(StoredRecord),

    /// The record could not be parsed.
    MalformedRecord(inplace::Error),

    /// The record is parseable but not valid.
    InvalidRecord(ZoneErrors),

    /// The SOA record was not found.
    MissingSoa(StoredRecord),
}

impl Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecordError::ClassMismatch(rec, zone_class) => {
                write!(f, "The class of the record does not match the class {zone_class} of the zone: {rec}")
            }
            RecordError::IllegalZoneCut(rec, existing_rtype) => {
                write!(f, "Attempted to add zone cut records where non-zone cut records ({existing_rtype}) already exist: {rec}")
            }
            RecordError::IllegalRecord(rec, existing_rtype) => {
                write!(f, "Attempted to add a normal record where a {existing_rtype} record already exists: {rec}")
            }
            RecordError::IllegalCname(rec, existing_rtype) => {
                write!(f, "Attempted to add a CNAME record where a {existing_rtype} record already exists: {rec}")
            }
            RecordError::MultipleCnames(rec) => {
                write!(f, "Attempted to add a CNAME record a CNAME record already exists: {rec}")
            }
            RecordError::MalformedRecord(err) => {
                write!(f, "The record could not be parsed: {err}")
            }
            RecordError::InvalidRecord(err) => {
                write!(f, "The record is parseable but not valid: {err}")
            }
            RecordError::MissingSoa(rec) => {
                write!(f, "The SOA record was not found: {rec}")
            }
        }
    }
}

//------------ ZoneErrors ----------------------------------------------------

/// A set of problems relating to a zone.
#[derive(Clone, Debug, Default)]
pub struct ZoneErrors {
    errors: Vec<(StoredName, ContextError)>,
}

impl ZoneErrors {
    /// Add an error to the set.
    pub fn add_error(&mut self, name: StoredName, error: ContextError) {
        self.errors.push((name, error))
    }

    /// Unwrap the set of errors.
    ///
    /// Returns the set of errors as [Result::Err(ZonErrors)] or [Result::Ok]
    /// if the set is empty.
    pub fn unwrap(self) -> Result<(), Self> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl Display for ZoneErrors {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Zone file errors: [")?;
        for err in &self.errors {
            write!(f, "'{}': {},", err.0, err.1)?;
        }
        write!(f, "]")
    }
}

//------------ ContextError --------------------------------------------------

/// A zone file record is not correct for its context.
#[derive(Clone, Debug)]
pub enum ContextError {
    /// A NS RRset is missing at a zone cut.
    ///
    /// (This happens if there is only a DS RRset.)
    MissingNs,

    /// A zone cut appeared where it shouldn’t have.
    InvalidZonecut(ZoneCutError),

    /// A CNAME appeared where it shouldn’t have.
    InvalidCname(CnameError),

    /// A record is out of zone.
    OutOfZone(Rtype),
}

impl Display for ContextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ContextError::MissingNs => write!(f, "Missing NS"),
            ContextError::InvalidZonecut(err) => {
                write!(f, "Invalid zone cut: {err}")
            }
            ContextError::InvalidCname(err) => {
                write!(f, "Invalid CNAME: {err}")
            }
            ContextError::OutOfZone(err) => write!(f, "Out of zone: {err}"),
        }
    }
}

//------------ ZoneTreeModificationError -------------------------------------

/// An attempt to modify a [`ZoneTree`] failed.
///
/// [`ZoneTree`]: crate::zonetree::ZoneTree
#[derive(Debug)]
pub enum ZoneTreeModificationError {
    /// The specified zone already exists.
    ZoneExists,

    /// The specified zone does not exist.
    ZoneDoesNotExist,

    /// The operation failed due to an I/O error.
    Io(io::Error),
}

impl From<io::Error> for ZoneTreeModificationError {
    fn from(src: io::Error) -> Self {
        ZoneTreeModificationError::Io(src)
    }
}

impl From<ZoneTreeModificationError> for io::Error {
    fn from(src: ZoneTreeModificationError) -> Self {
        match src {
            ZoneTreeModificationError::Io(err) => err,
            ZoneTreeModificationError::ZoneDoesNotExist => {
                io::Error::new(io::ErrorKind::Other, "zone does not exist")
            }
            ZoneTreeModificationError::ZoneExists => {
                io::Error::new(io::ErrorKind::Other, "zone exists")
            }
        }
    }
}

impl Display for ZoneTreeModificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneTreeModificationError::ZoneExists => {
                write!(f, "Zone already exists")
            }
            ZoneTreeModificationError::ZoneDoesNotExist => {
                write!(f, "Zone does not exist")
            }
            ZoneTreeModificationError::Io(err) => {
                write!(f, "Io error: {err}")
            }
        }
    }
}
