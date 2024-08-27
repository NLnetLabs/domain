//! XFR related types.

//------------ XfrRecord ------------------------------------------------------

use bytes::Bytes;

use crate::{
    base::{wire::ParseError, ParsedName, Record, Rtype, Serial},
    rdata::AllRecordData,
};

/// The type of record processed by [`XfrResponseProcessor`].
pub type XfrRecord =
    Record<ParsedName<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;

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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
    BeginBatchDelete(Serial),

    /// Prepare to add records in zone serial S.
    ///
    /// The transfer signalled that zero or more record additions will follow,
    /// all for the zone version with the given serial number.
    BeginBatchAdd(Serial),

    /// Transfer completed successfully.
    ///
    /// Note: This event is not emitted until the final record of the final
    /// response in a set of one or more transfer responss has been seen.
    EndOfTransfer,

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
            XfrEvent::EndOfTransfer => f.write_str("EndOfTransfer"),
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

//------------ Error ----------------------------------------------------------

/// An error reported by [`XfrResponseProcessor`].
#[derive(Debug)]
pub enum Error {
    /// The message could not be parsed.
    ParseError(ParseError),

    /// The request message is not an XFR query/
    NotValidXfrRequest,

    /// The response message is not an XFR response.
    NotValidXfrResponse,

    /// At least one record in the XFR response sequence is incorrect.
    Malformed,

    /// At least one record in the XFR response sequence was not consumed
    /// by the caller.
    AnswerNotFullyProcessed,

    /// Processing was already terminated for this XFR response sequence.
    Terminated,
}

//------------ XfrEventIteratorError ------------------------------------------

/// Errors that can occur during XfrEventIterator iteration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XfrEventIteratorError {
    /// Transfer processing failed.
    ParseError(ParseError),
}
