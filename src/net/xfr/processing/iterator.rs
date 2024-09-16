//! Emit events while iterating over an XFR response message.

use bytes::Bytes;
use tracing::trace;

use crate::base::message::RecordIter;
use crate::base::{Message, ParsedName};
use crate::rdata::ZoneRecordData;

use super::processor::RecordProcessor;
use super::types::{IterationError, ProcessingError, XfrEvent, XfrRecord};

//------------ XfrEventIterator -----------------------------------------------

/// An iterator over [`XfrResponseInterpreter`] generated [`XfrEvent`]s.
///
/// [`XfrResponseInterpreter`]: super::processor::XfrResponseInterpreter
pub struct XfrEventIterator<'a, 'b> {
    /// The parent processor.
    state: &'a mut RecordProcessor,

    /// An iterator over the records in the current response.
    iter: RecordIter<'b, Bytes, ZoneRecordData<Bytes, ParsedName<Bytes>>>,
}

impl<'a, 'b> XfrEventIterator<'a, 'b> {
    pub(super) fn new(
        state: &'a mut RecordProcessor,
        resp: &'b Message<Bytes>,
    ) -> Result<Self, ProcessingError> {
        let answer = resp.answer().map_err(ProcessingError::ParseError)?;

        // https://datatracker.ietf.org/doc/html/rfc5936#section-3
        // 3. Zone Contents
        //   "The objective of the AXFR session is to request and transfer
        //    the contents of a zone, in order to permit the AXFR client
        //    to faithfully reconstruct the zone as it exists at the
        //    primary server for the given zone serial number.  The word
        //    "exists" here designates the externally visible behavior,
        //    i.e., the zone content that is being served (handed out to
        //    clients) -- not its persistent representation in a zone file
        //    or database used by the server -- and that for consistency
        //    should be served subsequently by the AXFR client in an
        //    identical manner."
        //
        // So, walk over all the records in the answer, not just those
        // that might be expected to exist in a zone (i.e. not just
        // ZoneRecordData record types).

        let mut iter = answer.limit_to();

        if state.rr_count == 0 {
            let Some(Ok(_)) = iter.next() else {
                return Err(ProcessingError::Malformed);
            };
            state.rr_count += 1;
        }

        Ok(Self { state, iter })
    }
}

impl<'a, 'b> Iterator for XfrEventIterator<'a, 'b> {
    type Item = Result<XfrEvent<XfrRecord>, IterationError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next()? {
            Ok(record) => {
                trace!("XFR record {}: {record:?}", self.state.rr_count);
                let event = self.state.process_record(record);
                Some(Ok(event))
            }

            Err(err) => {
                trace!(
                    "XFR record {}: parsing error: {err}",
                    self.state.rr_count
                );
                Some(Err(IterationError::ParseError(err)))
            }
        }
    }
}
