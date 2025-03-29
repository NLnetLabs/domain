//! Emit events while iterating over an XFR response message.

use bytes::Bytes;
use tracing::trace;

use crate::base::message::RecordIter;
use crate::base::{Message, ParsedName, Record};
use crate::rdata::ZoneRecordData;
use crate::zonetree::types::ZoneUpdate;

use super::interpreter::RecordProcessor;
use super::types::{Error, IterationError, ParsedRecord, XfrType};

//------------ XfrZoneUpdateIterator ------------------------------------------

/// An iterator over [`XfrResponseInterpreter`] generated [`ZoneUpdate`]s.
///
/// [`XfrResponseInterpreter`]: super::interpreter::XfrResponseInterpreter
pub struct XfrZoneUpdateIterator<'a, 'b> {
    /// The parent processor.
    state: &'a mut RecordProcessor,

    /// An iterator over the records in the current response.
    iter: RecordIter<'b, Bytes, ZoneRecordData<Bytes, ParsedName<Bytes>>>,

    /// TODO
    saved_update: Option<ZoneUpdate<Record<ParsedName<Bytes>, ZoneRecordData<Bytes, ParsedName<Bytes>>>>>,
}

impl<'a, 'b> XfrZoneUpdateIterator<'a, 'b> {
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

        let mut iter = answer.limit_to();

        if state.rr_count == 0 {
            // Skip the opening SOA record, it was already processed and
            // stored by the given RecordProcessor.
            let Some(Ok(_)) = iter.next() else {
                return Err(Error::Malformed);
            };
        }

        Ok(Self { state, iter, saved_update: None })
    }
}

impl Iterator for XfrZoneUpdateIterator<'_, '_> {
    type Item = Result<ZoneUpdate<ParsedRecord>, IterationError>;

    fn next(&mut self) -> Option<Self::Item> {
        let is_first_rr = self.state.rr_count == 0;

        if is_first_rr {
            // We already skipped the first record in new() above by calling
            // iter.next(). We didn't reflect that yet in rr_count because we
            // wanted to still be able to detect the first call to next() and
            // handle it specially for AXFR.
            self.state.rr_count += 1;
        
            if self.state.actual_xfr_type == XfrType::Axfr {
                // For AXFR we're not making incremental changes to a zone,
                // we're replacing its entire contents, so before returning
                // any actual updates to apply first instruct the consumer to
                // "discard" everything it has.
                return Some(Ok(ZoneUpdate::DeleteAllRecords));
            }
        }

        if let Some(update) = self.saved_update.take() {
            return Some(Ok(update));
        }

        match self.iter.next()? {
            Ok(record) => {
                trace!("XFR record {}: {record:?}", self.state.rr_count);
                let update = self.state.process_record(record);

                if is_first_rr && self.state.actual_xfr_type == XfrType::Axfr {
                    // We didn't return DeleteAllRecords above because the
                    // transfer was thought to be IXFR rather than AXFR, but
                    // now that the next record has been processed we have had
                    // the chance to detect fallback from IXFR to AXFR for
                    // which we should also delete all records first. Save this
                    // update so that we can first return DeleteAllRecords.
                    self.saved_update = Some(update);
                    return Some(Ok(ZoneUpdate::DeleteAllRecords));
                }

                Some(Ok(update))
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
