//! Emit events while iterating over an XFR response message.

use bytes::Bytes;
use tracing::trace;

use crate::base::message::RecordIter;
use crate::base::{Message, ParsedName};
use crate::rdata::ZoneRecordData;
use crate::zonetree::types::ZoneUpdate;

use super::interpreter::RecordProcessor;
use super::types::{Error, IterationError, ParsedRecord};

//------------ XfrZoneUpdateIterator ------------------------------------------

/// An iterator over [`XfrResponseInterpreter`] generated [`ZoneUpdate`]s.
///
/// [`XfrResponseInterpreter`]: super::interpreter::XfrResponseInterpreter
pub struct XfrZoneUpdateIterator<'a, 'b> {
    /// The parent processor.
    processor: &'a mut RecordProcessor,

    /// An iterator over the records in the current response.
    iter: RecordIter<'b, Bytes, ZoneRecordData<Bytes, ParsedName<Bytes>>>,

    held_update: Option<ZoneUpdate<ParsedRecord>>,
}

impl<'a, 'b> XfrZoneUpdateIterator<'a, 'b> {
    pub(super) fn new(
        processor: &'a mut RecordProcessor,
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

        let iter = answer.limit_to();

        Ok(Self {
            processor,
            iter,
            held_update: None,
        })
    }
}

impl Iterator for XfrZoneUpdateIterator<'_, '_> {
    type Item = Result<ZoneUpdate<ParsedRecord>, IterationError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(update) = self.held_update.take() {
            return Some(Ok(update));
        }

        loop {
            match self.iter.next() {
                Some(Ok(record)) => {
                    trace!(
                        "XFR record {}: {record:?}",
                        self.processor.rr_count()
                    );
                    match self.processor.process_record(record).transpose() {
                        None => {
                            // No update resulted from processing this record.
                            // Move on to the next record.
                            continue;
                        }

                        Some(Ok((update, extra_update))) => {
                            // One or more updates resulted from processing
                            // this record. Keep any subsequent update and
                            // return the first or only update.
                            self.held_update = extra_update;
                            return Some(Ok(update));
                        }

                        Some(Err(err)) => {
                            return Some(Err(err));
                        }
                    }
                }

                Some(Err(err)) => {
                    trace!(
                        "XFR record {}: parsing error: {err}",
                        self.processor.rr_count()
                    );
                    return Some(Err(IterationError::ParseError(err)));
                }

                None => {
                    return None;
                }
            }
        }
    }
}
