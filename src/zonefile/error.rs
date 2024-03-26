//------------ ZoneCutError --------------------------------------------------

use std::fmt::Display;

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
