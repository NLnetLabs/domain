//! Emit events while iterating over an XFR response message.

use bytes::Bytes;
use tracing::trace;

use crate::base::{message::AnyRecordIter, Message, ParsedName};
use crate::rdata::AllRecordData;

use super::processor::RecordProcessor;
use super::types::{Error, XfrEvent, XfrEventIteratorError, XfrRecord};

///------------ XfrEventIterator -----------------------------------------------

/// An iterator over [`XfrResponseProcessor`] generated [`XfrEvent`]s.
pub struct XfrEventIterator<'a, 'b> {
    /// The parent processor.
    state: &'a mut RecordProcessor,

    /// An iterator over the records in the current response.
    iter: AnyRecordIter<'b, Bytes, AllRecordData<Bytes, ParsedName<Bytes>>>,
}

impl<'a, 'b> XfrEventIterator<'a, 'b> {
    pub(super) fn new(
        state: &'a mut RecordProcessor,
        resp: &'b Message<Bytes>,
    ) -> Result<Self, Error> {
        let answer = resp.answer().map_err(Error::ParseError)?;

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

        let mut iter = answer.into_records();

        if state.rr_count == 0 {
            let Some(Ok(_)) = iter.next() else {
                return Err(Error::Malformed);
            };
            state.rr_count += 1;
        }

        Ok(Self { state, iter })
    }
}

impl<'a, 'b> Iterator for XfrEventIterator<'a, 'b> {
    type Item = Result<XfrEvent<XfrRecord>, XfrEventIteratorError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok(record)) => {
                trace!("XFR record {}: {record:?}", self.state.rr_count);
                let event = self.state.process_record(record);
                Some(Ok(event))
            }

            Some(Err(err)) => {
                Some(Err(XfrEventIteratorError::ParseError(err)))
            }

            None => {
                // No more events available: end iteration.
                None
            }
        }
    }
}
