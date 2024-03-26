//! Zone related errors.

//------------ ZoneCutError --------------------------------------------------

use std::fmt::Display;
use std::vec::Vec;

use crate::base::Rtype;
use crate::zonetree::StoredDname;

use super::inplace;

/// A zone cut is not valid with respect to the zone's apex.
#[derive(Clone, Copy, Debug)]
pub enum ZoneCutError {
    OutOfZone,
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
    OutOfZone,
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

#[derive(Clone, Debug)]
pub enum RecordError {
    /// The class of the record does not match the class of the zone.
    ClassMismatch,

    /// Attempted to add zone cut records where there is no zone cut.
    IllegalZoneCut,

    /// Attempted to add a normal record to a zone cut or CNAME.
    IllegalRecord,

    /// Attempted to add a CNAME record where there are other records.
    IllegalCname,

    /// Attempted to add multiple CNAME records for an owner.
    MultipleCnames,

    /// The record could not be parsed.
    MalformedRecord(inplace::Error),

    /// The record is parseable but not valid.
    InvalidRecord(ZoneErrors),

    /// The SOA record was not found.
    MissingSoa,
}

impl Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecordError::ClassMismatch => write!(f, "ClassMismatch"),
            RecordError::IllegalZoneCut => write!(f, "IllegalZoneCut"),
            RecordError::IllegalRecord => write!(f, "IllegalRecord"),
            RecordError::IllegalCname => write!(f, "IllegalCname"),
            RecordError::MultipleCnames => write!(f, "MultipleCnames"),
            RecordError::MalformedRecord(err) => {
                write!(f, "MalformedRecord: {err}")
            }
            RecordError::InvalidRecord(err) => {
                write!(f, "InvalidRecord: {err}")
            }
            RecordError::MissingSoa => write!(f, "MissingSoa"),
        }
    }
}

//------------ ZoneErrors ----------------------------------------------------

/// A set of problems relating to a zone.
#[derive(Clone, Debug, Default)]
pub struct ZoneErrors {
    errors: Vec<(StoredDname, OwnerError)>,
}

impl ZoneErrors {
    pub fn add_error(&mut self, name: StoredDname, error: OwnerError) {
        self.errors.push((name, error))
    }

    pub fn into_result(self) -> Result<(), Self> {
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

//------------ OwnerError ---------------------------------------------------

#[derive(Clone, Debug)]
pub enum OwnerError {
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

impl Display for OwnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OwnerError::MissingNs => write!(f, "Missing NS"),
            OwnerError::InvalidZonecut(err) => {
                write!(f, "Invalid zone cut: {err}")
            }
            OwnerError::InvalidCname(err) => {
                write!(f, "Invalid CNAME: {err}")
            }
            OwnerError::OutOfZone(err) => write!(f, "Out of zone: {err}"),
        }
    }
}
