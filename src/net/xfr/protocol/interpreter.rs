use std::fmt::Debug;

use bytes::Bytes;

use crate::base::iana::Opcode;
use crate::base::{Message, ParsedName, Rtype};
use crate::rdata::{Soa, ZoneRecordData};
use crate::zonetree::types::ZoneUpdate;

use super::iterator::XfrZoneUpdateIterator;
use super::types::{Error, IxfrUpdateMode, ParsedRecord, XfrType};
use super::IterationError;

//------------ XfrResponseInterpreter -----------------------------------------

/// An AXFR/IXFR response interpreter.
///
/// Use [`XfrResponseInterpreter`] to interpret a sequence of AXFR or IXFR
/// response messages as a sequence of [`ZoneUpdate`]s.
///
/// # Usage
///
/// For each response stream to be interpreted, construct an
/// [`XfrResponseInterpreter`] for the corresponding XFR request message, then
/// pass each XFR response message to [`interpret_response()`].
///
/// Each call to [`interpret_response()`] will return an [`XfrZoneUpdateIterator`]
/// which when iterated over will produce a sequence of [`ZoneUpdate`]s for a
/// single response message. The iterator emits [`ZoneUpdate::Complete`] when
/// the last record in the transfer is reached.
///
/// If [`ZoneUpdate::Complete`] has not yet been emitted it means that the
/// sequence is incomplete and the next response message in the sequence
/// should be passed to [`interpret_response()`].
///
/// [`interpret_response()`]: XfrResponseInterpreter::interpret_response()
/// [`ZoneUpdate`]: crate::zonetree::types::ZoneUpdate
/// [`ZoneUpdate::Complete`]: crate::zonetree::types::ZoneUpdate
#[derive(Default)]
pub struct XfrResponseInterpreter {
    /// Internal state.
    ///
    /// None until the first call to [`interpret_response()`].
    ///
    /// [`interpret_response()`]: XfrResponseInterpreter::interpret_response()
    inner: Option<Inner>,
}

impl XfrResponseInterpreter {
    /// Creates a new XFR message processor.
    pub fn new() -> Self {
        Self::default()
    }
}

impl XfrResponseInterpreter {
    /// Process a single AXFR/IXFR response message.
    ///
    /// Returns an [`XfrZoneUpdateIterator`] over [`ZoneUpdate`]s emitted
    /// during processing.
    ///
    /// Call this function with the next outstanding response message to
    /// continue iterating over an incomplete transfer (i.e. previous
    /// iterators were exhausted without emiting [`ZoneUpdate::Finished`].
    ///
    /// Checking that the given response corresponds by ID to the related
    /// original XFR query or that the question section of the response, if
    /// present (RFC 5936 allows it to be empty for subsequent AXFR responses)
    /// matches that of the original query is NOT done here but instead is
    /// left to the caller to do.
    pub fn interpret_response(
        &mut self,
        resp: Message<Bytes>,
    ) -> Result<XfrZoneUpdateIterator, Error> {
        if self.is_finished() {
            return Err(Error::Finished);
        }

        // Check that the given message is a DNS XFR response.
        self.check_response(&resp)?;

        if let Some(inner) = &mut self.inner {
            inner.resp = resp;
        } else {
            self.initialize(resp)?;
        }

        let inner = self.inner.as_mut().unwrap();

        XfrZoneUpdateIterator::new(&mut inner.processor, &inner.resp)
    }

    /// Is the transfer finished?
    ///
    /// Returns true if the end of the transfer has been detected, false otherwise.
    pub fn is_finished(&self) -> bool {
        self.inner
            .as_ref()
            .map(|inner| inner.processor.is_finished())
            .unwrap_or_default()
    }
}

impl XfrResponseInterpreter {
    /// Initialize inner state.
    fn initialize(&mut self, resp: Message<Bytes>) -> Result<(), Error> {
        self.inner = Some(Inner::new(resp)?);
        Ok(())
    }

    /// Check if an XFR response header is valid.
    ///
    /// Enforce the rules defined in 2.2. AXFR Messages of RFC 5936. See:
    /// https://www.rfc-editor.org/rfc/rfc5936.html#section-2.2
    ///
    /// Returns Ok on success, Err otherwise. On success the type of XFR that
    /// was determined is returned as well as the answer section from the XFR
    /// response.
    fn check_response(&self, resp: &Message<Bytes>) -> Result<(), Error> {
        let resp_header = resp.header();
        let resp_counts = resp.header_counts();

        if resp.is_error()
            || !resp_header.qr()
            || resp_header.opcode() != Opcode::QUERY
            || resp_header.tc()
            || resp_counts.ancount() == 0
            || resp_counts.nscount() != 0
        {
            return Err(Error::NotValidXfrResponse);
        }

        //https://www.rfc-editor.org/rfc/rfc5936.html#section-2.2.1
        // 2.2.1. Header Values
        //   "QDCOUNT     MUST be 1 in the first message;
        //                MUST be 0 or 1 in all following messages;"
        let qdcount = resp_counts.qdcount();
        let first_message = self.inner.is_none();
        if (first_message && qdcount != 1) || (!first_message && qdcount > 1)
        {
            return Err(Error::NotValidXfrResponse);
        }

        Ok(())
    }
}

//------------ Inner ----------------------------------------------------------

/// Internal dynamic state of [`XfrResponseInterpreter`].
///
/// Separated out from [`XfrResponseInterpreter`] to avoid needing multiple
/// mutable self references in [`interpret_response()`].
///
/// [`interpret_response()`]: XfrResponseInterpreter::interpret_response()
struct Inner {
    /// The response message currently being processed.
    resp: Message<Bytes>,

    /// State that influences and is influenced by resposne processing.
    processor: RecordProcessor,
}

impl Inner {
    /// Initialise the processosr.
    ///
    /// Records the initial SOA record and other details will will be used
    /// while processing the rest of the response.
    fn new(resp: Message<Bytes>) -> Result<Self, Error> {
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

        let mut records = answer.limit_to();

        let xfr_type = match resp.qtype() {
            Some(Rtype::AXFR) => XfrType::Axfr,
            Some(Rtype::IXFR) => XfrType::Ixfr,
            _ => unreachable!(),
        };

        let Some(Ok(record)) = records.next() else {
            return Err(Error::Malformed);
        };

        // The initial record should be a SOA record.
        let ZoneRecordData::Soa(soa) = record.into_data() else {
            return Err(Error::NotValidXfrResponse);
        };

        let state = RecordProcessor::new(xfr_type, soa);

        Ok(Inner {
            resp,
            processor: state,
        })
    }
}

//------------ RecordProcessor ------------------------------------------------

/// State related to processing the XFR response sequence.
#[derive(Debug)]
pub(super) struct RecordProcessor {
    /// The type of XFR response sequence being parsed.
    ///
    /// This can differ to the type of XFR response sequence that we expected
    /// to parse because the server can fallback from IXFR to AXFR.
    actual_xfr_type: XfrType,

    /// The initial SOA record that signals the start and end of both AXFR and
    /// IXFR response sequences.
    initial_soa: Soa<ParsedName<Bytes>>,

    /// The current SOA record.
    ///
    /// For AXFR response sequences this will be the same as `initial_soa`.
    /// For IXFR response sequences this will be the last SOA record parsed as
    /// each diff sequence contains two SOA records: one at the start of the
    /// delete sequence and one at the start of the add sequence.
    current_soa: Soa<ParsedName<Bytes>>,

    /// The kind of records currently being processed, either adds or deletes.
    ixfr_update_mode: IxfrUpdateMode,

    /// The number of resource records parsed so far.
    rr_count: usize,

    // True if ZoneUpdate::DeleteAllRecords has already been returned for an
    // AXFR transfer.
    axfr_delete_already_returned: bool,

    /// True if the end of the transfer has been detected, false otherwise.
    finished: bool,
}

impl RecordProcessor {
    /// Create a new [`RecordProcessor`].
    fn new(
        initial_xfr_type: XfrType,
        initial_soa: Soa<ParsedName<Bytes>>,
    ) -> Self {
        // Processing of each diff group toggles the mode between adding and
        // deleting. As the first diff group represents a deletion, set the
        // initial mode to adding so that at the start of handling the first
        // diff group the mode is correctly toggled to deleting.
        let ixfr_update_mode = IxfrUpdateMode::Adding;

        Self {
            actual_xfr_type: initial_xfr_type,
            initial_soa: initial_soa.clone(),
            current_soa: initial_soa,
            rr_count: 0,
            ixfr_update_mode,
            axfr_delete_already_returned: false,
            finished: false,
        }
    }

    pub(super) fn finish(&mut self) {
        self.finished = true;
    }

    /// Process a single resource record.
    ///
    /// Returns zero, one or two [`ZoneUpdate`]s that should be emitted for
    /// the processed record.
    // This is a relatively internal interface so allow the complex type.
    #[allow(clippy::type_complexity)]
    pub(super) fn process_record(
        &mut self,
        rec: ParsedRecord,
    ) -> Result<
        Option<(ZoneUpdate<ParsedRecord>, Option<ZoneUpdate<ParsedRecord>>)>,
        IterationError,
    > {
        if self.finished {
            return Err(IterationError::AlreadyFinished);
        }

        self.rr_count += 1;

        // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2
        // 2.2.  AXFR Response
        //   "..clients MUST accept any ordering and grouping of the non-SOA
        //    RRs.  Each RR SHOULD be transmitted only once, and AXFR clients
        //    MUST ignore any duplicate RRs received."
        //
        // Note: We do NOT implement this MUST here because it would be very
        // inefficient to actually check that any received non-SOA RR has not
        // been seen before during the in-progress transfer. Clients of
        // XfrResponseInterpreter are better placed to enforce this rule if
        // needed, e.g. at the moment of insertion into a zone tree checking
        // that the record is not already present or insertion of a duplicate
        // having no effect as it is already present.

        let soa = match rec.data() {
            ZoneRecordData::Soa(soa) => Some(soa),
            _ => None,
        };

        let record_matches_initial_soa = soa == Some(&self.initial_soa);

        let update = match self.actual_xfr_type {
            // AXFR and IXFR start case:
            // Both AXFR and IXFR begin with an initial SOA record.
            XfrType::Axfr | XfrType::Ixfr if self.rr_count == 1 => {
                if soa.is_none() {
                    return Err(IterationError::MissingInitialSoa);
                } else {
                    return Ok(None);
                }
            }

            // AXFR end case:
            // AXFRs are terminated by a second copy of the opening SOA record.
            XfrType::Axfr if record_matches_initial_soa => {
                // https://www.rfc-editor.org/rfc/rfc5936.html#section-2.2
                // 2.2.  AXFR Response
                //   ...
                //   "In such a series, the first message MUST begin with the
                //    SOA resource record of the zone, and the last message
                //    MUST conclude with the same SOA resource record.
                //    Intermediate messages MUST NOT contain the SOA resource
                //    record."
                ZoneUpdate::Finished(rec)
            }

            // AXFR in-progress case:
            // Any other record.
            XfrType::Axfr => ZoneUpdate::AddRecord(rec),

            // IXFR -> AXFR fallback case:
            XfrType::Ixfr
                if self.rr_count == 2 && rec.rtype() != Rtype::SOA =>
            {
                // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                // 4. Response Format
                //   "If incremental zone transfer is not available, the
                //    entire zone is returned.  The first and the last RR
                //    of the response is the SOA record of the zone.  I.e.
                //    the behavior is the same as an AXFR response except
                //    the query type is IXFR.
                //
                //    If incremental zone transfer is available, one or
                //    more difference sequences is returned.  The list of
                //    difference sequences is preceded and followed by a
                //    copy of the server's current version of the SOA.
                //
                //    Each difference sequence represents one update to
                //    the zone (one SOA serial change) consisting of
                //    deleted RRs and added RRs.  The first RR of the
                //    deleted RRs is the older SOA RR and the first RR of
                //    the added RRs is the newer SOA RR.
                //
                //    Modification of an RR is performed first by removing
                //    the original RR and then adding the modified one."

                // As this is IXFR and this is the second record, it should
                // be the "first RR of the deleted RRs" which should be
                // "the older SOA RR". However, it isn't a SOA RR. As such
                // assume that "incremental zone transfer is not available"
                // and so "the behaviour is the same as an AXFR response",
                self.actual_xfr_type = XfrType::Axfr;
                ZoneUpdate::AddRecord(rec)
            }

            XfrType::Ixfr => {
                if let Some(soa) = soa {
                    // IXFR diff boundary or end case:
                    self.ixfr_update_mode.toggle();
                    self.current_soa = soa.clone();

                    match self.ixfr_update_mode {
                        IxfrUpdateMode::Deleting => {
                            // We just finished a (Delete, Add) diff sequence.
                            // Is this the end of the transfer, or the start
                            // of a new diff sequence?
                            if record_matches_initial_soa {
                                ZoneUpdate::Finished(rec)
                            } else {
                                ZoneUpdate::BeginBatchDelete(rec)
                            }
                        }
                        IxfrUpdateMode::Adding => {
                            // We just switched from the Delete phase of a
                            // diff sequence to the add phase of the diff
                            // sequence.
                            ZoneUpdate::BeginBatchAdd(rec)
                        }
                    }
                } else {
                    // IXFR diff in-progress case:
                    match self.ixfr_update_mode {
                        IxfrUpdateMode::Deleting => {
                            ZoneUpdate::DeleteRecord(rec)
                        }
                        IxfrUpdateMode::Adding => ZoneUpdate::AddRecord(rec),
                    }
                }
            }
        };

        if matches!(update, ZoneUpdate::Finished(_)) {
            self.finished = true;
        }

        let updates = if self.actual_xfr_type == XfrType::Axfr
            && !self.axfr_delete_already_returned
        {
            // For AXFR we're not making incremental changes to a zone,
            // we're replacing its entire contents, so before returning
            // any actual updates to apply first instruct the consumer to
            // "discard" everything it has.
            self.axfr_delete_already_returned = true;
            (ZoneUpdate::DeleteAllRecords, Some(update))
        } else {
            (update, None)
        };

        Ok(Some(updates))
    }

    pub fn rr_count(&self) -> usize {
        self.rr_count
    }

    pub fn actual_xfr_type(&self) -> XfrType {
        self.actual_xfr_type
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }
}
