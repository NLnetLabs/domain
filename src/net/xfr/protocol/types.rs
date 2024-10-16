//! XFR related types.

//------------ XfrRecord ------------------------------------------------------

use bytes::Bytes;

use crate::{
    base::{wire::ParseError, ParsedName, Record, Rtype},
    rdata::ZoneRecordData,
};

/// The type of record processed by [`XfrResponseInterpreter`].
///
/// [`XfrResponseInterpreter`]: super::interpreter::XfrResponseInterpreter
pub type ParsedRecord =
    Record<ParsedName<Bytes>, ZoneRecordData<Bytes, ParsedName<Bytes>>>;

//------------ XfrType --------------------------------------------------------

/// The type of XFR response sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum XfrType {
    /// RFC 5936 AXFR.
    ///
    /// A complete snapshot of a zone at a particular version.
    Axfr,

    /// RFC 1995 IXFR.
    ///
    /// An incremental diff of the version of the zone that the server has
    /// compared to the version of the zone that the client has.
    Ixfr,
}

//--- From<Rtype>

impl TryFrom<Rtype> for XfrType {
    type Error = ();

    fn try_from(rtype: Rtype) -> Result<Self, Self::Error> {
        match rtype {
            Rtype::AXFR => Ok(XfrType::Axfr),
            Rtype::IXFR => Ok(XfrType::Ixfr),
            _ => Err(()),
        }
    }
}

//------------ IxfrUpdateMode -------------------------------------------------

/// The kind of records currently being processed, either adds or deletes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum IxfrUpdateMode {
    /// The records being parsed are deletions.
    ///
    /// Deletions come before additions.
    #[default]
    Deleting,

    /// The records being parsed are additions.
    Adding,
}

impl IxfrUpdateMode {
    /// Toggle between the possible [`IxfrUpdateMode`] variants.
    pub fn toggle(&mut self) {
        match self {
            IxfrUpdateMode::Deleting => *self = IxfrUpdateMode::Adding,
            IxfrUpdateMode::Adding => *self = IxfrUpdateMode::Deleting,
        }
    }
}

//------------ ProcessingError ------------------------------------------------

/// An error reported by [`XfrResponseInterpreter`].
///
/// [`XfrResponseInterpreter`]: super::interpreter::XfrResponseInterpreter
#[derive(Debug)]
pub enum Error {
    /// The message could not be parsed.
    ParseError(ParseError),

    /// The response message is not an XFR response.
    NotValidXfrResponse,

    /// At least one record in the XFR response sequence is incorrect.
    Malformed,

    /// A complete transfer was already processed.
    Finished,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ParseError(err) => {
                f.write_fmt(format_args!("XFR response parsing error: {err}"))
            }
            Error::NotValidXfrResponse => {
                f.write_str("Not a valid XFR response")
            }
            Error::Malformed => f.write_str("Malformed XFR response"),
            Error::Finished => f.write_str("XFR already finished"),
        }
    }
}

//------------ IterationError -------------------------------------------------

/// Errors that can occur during [`XfrZoneUpdateIterator`]` iteration.
///
/// [`XfrZoneUpdateIterator`]: super::iterator::XfrZoneUpdateIterator
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IterationError {
    /// Transfer processing failed.
    ParseError(ParseError),
}
