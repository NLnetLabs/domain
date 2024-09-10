//! XFR related types.

//------------ XfrRecord ------------------------------------------------------

use bytes::Bytes;

use crate::{
    base::{wire::ParseError, ParsedName, Record, Rtype, Serial},
    rdata::ZoneRecordData,
};

/// The type of record processed by [`XfrResponseProcessor`].
///
/// [`XfrResponseProcessor`]: super::processor::XfrResponseProcessor
pub type XfrRecord =
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

//------------ XfrEvent -------------------------------------------------------

/// An event emitted by [`XfrResponseProcessor`] during transfer processing.
///
/// [`XfrResponseProcessor`]: super::processor::XfrResponseProcessor
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XfrEvent<R> {
    /// Delete record R in zone serial S.
    ///
    /// The transfer signalled that the given record should be deleted from
    /// the zone version with the given serial number.
    ///
    /// Note: If the transfer contains N deletions of fhe same record then
    /// this event will occur N times.
    DeleteRecord(Serial, R),

    /// Add record R in zone serial S.
    ///
    /// The transfer signalled that the given record should be added to the
    /// zone version with the given serial number.
    ///
    /// Note: If the transfer contains N additions of fhe same record then
    /// this event will occur N times.
    AddRecord(Serial, R),

    /// Prepare to delete records in zone serial S.
    ///
    /// The transfer signalled that zero or more record deletions will follow,
    /// all for the zone version with the given serial number.
    BeginBatchDelete(R),

    /// Prepare to add records in zone serial S.
    ///
    /// The transfer signalled that zero or more record additions will follow,
    /// all for the zone version with the given serial number.
    BeginBatchAdd(R),

    /// Transfer completed successfully.
    ///
    /// Note: This event is not emitted until the final record of the final
    /// response in a set of one or more transfer responss has been seen.
    EndOfTransfer(R),

    /// Transfer processing failed.
    ///
    /// This event indicates that there is a problem with the transfer data
    /// and that transfer processing cannot continue.
    ProcessingFailed,
}

//--- Display

impl<R> std::fmt::Display for XfrEvent<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            XfrEvent::DeleteRecord(_, _) => f.write_str("DeleteRecord"),
            XfrEvent::AddRecord(_, _) => f.write_str("AddRecord"),
            XfrEvent::BeginBatchDelete(_) => f.write_str("BeginBatchDelete"),
            XfrEvent::BeginBatchAdd(_) => f.write_str("BeginBatchAdd"),
            XfrEvent::EndOfTransfer(_) => f.write_str("EndOfTransfer"),
            XfrEvent::ProcessingFailed => f.write_str("ProcessingFailed"),
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

/// An error reported by [`XfrResponseProcessor`].
///
/// [`XfrResponseProcessor`]: super::processor::XfrResponseProcessor
#[derive(Debug)]
pub enum ProcessingError {
    /// The message could not be parsed.
    ParseError(ParseError),

    /// The response message is not an XFR response.
    NotValidXfrResponse,

    /// At least one record in the XFR response sequence is incorrect.
    Malformed,
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProcessingError::ParseError(err) => {
                f.write_fmt(format_args!("XFR response parsing error: {err}"))
            }
            ProcessingError::NotValidXfrResponse => {
                f.write_str("Not a valid XFR response")
            }
            ProcessingError::Malformed => {
                f.write_str("Malformed XFR response")
            }
        }
    }
}

//------------ IterationError -------------------------------------------------

/// Errors that can occur during [`XfrEventIterator`]` iteration.
///
/// [`XfrEventIterator`]: super::iterator::XfrEventIterator
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IterationError {
    /// Transfer processing failed.
    ParseError(ParseError),
}