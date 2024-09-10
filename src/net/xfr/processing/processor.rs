use std::fmt::Debug;

use bytes::Bytes;

use crate::base::iana::Opcode;
use crate::base::{Message, ParsedName, Rtype};
use crate::rdata::{Soa, ZoneRecordData};

use super::iterator::XfrEventIterator;
use super::types::{
    IxfrUpdateMode, ProcessingError, XfrEvent, XfrRecord, XfrType,
};

//------------ XfrResponseProcessor -------------------------------------------

/// An AXFR/IXFR response processor.
///
/// Use [`XfrResponseProcessor`] to process a sequence of AXFR or IXFR
/// response messages into a corresponding sequence of high level
/// [`XfrEvent`]s.
///
/// # Usage
///
/// For each response stream to be processed, construct an
/// [`XfrResponseProcessor`] for the corresponding XFR request message, then
/// pass each XFR response message to [`process_answer()`].
///
/// Each call to [`process_answer()`] will return an [`XfrEventIterator`]
/// which when iterated over will produce a sequence of [`XfrEvent`]s for a
/// single response message. The iterator emits an [`XfrEvent::EndOfTransfer`]
/// event when the last record in the transfer is reached.
///
/// If [`XfrEvent::EndOfTransfer`] event has not yet been emitted it means
/// that the sequence is incomplete and the next response message in the
/// sequence should be passed to [`process_answer()`].
///
/// [`process_answer()`]: XfrResponseProcessor::process_answer()
#[derive(Default)]
pub struct XfrResponseProcessor {
    /// Internal state.
    ///
    /// None until the first call to [`process_answer()`].
    inner: Option<Inner>,
}

impl XfrResponseProcessor {
    /// Creates a new XFR message processor.
    pub fn new() -> Self {
        Self::default()
    }
}

impl XfrResponseProcessor {
    /// Process a single AXFR/IXFR response message.
    ///
    /// Returns an [`XfrEventIterator`] over [`XfrEvent`]s emitted during
    /// processing.
    ///
    /// If the returned iterator does not emit an [`XfrEvent::EndOfTransfer`]
    /// event, call this function with the next outstanding response message
    /// to continue iterating over the incomplete transfer.
    /// 
    /// Checking that the given response corresponds by ID to the related
    /// original XFR query or that the question section of the response, if
    /// present (RFC 5936 allows it to be empty for subsequent AXFR responses)
    /// matches that of the original query is NOT done here but instead is
    /// left to the caller to do.
    pub fn process_answer(
        &mut self,
        resp: Message<Bytes>,
    ) -> Result<XfrEventIterator, ProcessingError> {
        // Check that the given message is a DNS XFR response.
        self.check_response(&resp)?;

        if let Some(inner) = &mut self.inner {
            inner.resp = resp;
        } else {
            self.initialize(resp)?;
        }

        let inner = self.inner.as_mut().unwrap();

        XfrEventIterator::new(&mut inner.state, &inner.resp)
    }
}

impl XfrResponseProcessor {
    /// Initialize inner state.
    fn initialize(
        &mut self,
        resp: Message<Bytes>,
    ) -> Result<(), ProcessingError> {
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
    fn check_response(
        &self,
        resp: &Message<Bytes>,
    ) -> Result<(), ProcessingError> {
        let resp_header = resp.header();
        let resp_counts = resp.header_counts();

        if resp.is_error()
            || !resp_header.qr()
            || resp_header.opcode() != Opcode::QUERY
            || resp_header.tc()
            || resp_counts.ancount() == 0
            || resp_counts.nscount() != 0
        {
            return Err(ProcessingError::NotValidXfrResponse);
        }

        //https://www.rfc-editor.org/rfc/rfc5936.html#section-2.2.1
        // 2.2.1. Header Values
        //   "QDCOUNT     MUST be 1 in the first message;
        //                MUST be 0 or 1 in all following messages;"
        let qdcount = resp_counts.qdcount();
        let first_message = self.inner.is_none();
        if (first_message && qdcount != 1) || (!first_message && qdcount > 1)
        {
            return Err(ProcessingError::NotValidXfrResponse);
        }

        Ok(())
    }
}

//------------ Inner ----------------------------------------------------------

/// Internal dynamic state of [`XfrResponseProcessor`].
///
/// Separated out from [`XfrResponseProcessor`] to avoid needing multiple
/// mutable self references in [`process_answer()`].
struct Inner {
    /// The response message currently being processed.
    resp: Message<Bytes>,

    /// State that influences and is influenced by resposne processing.
    state: RecordProcessor,
}

impl Inner {
    /// Initialise the processosr.
    ///
    /// Records the initial SOA record and other details will will be used
    /// while processing the rest of the response.
    fn new(resp: Message<Bytes>) -> Result<Self, ProcessingError> {
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

        let mut records = answer.limit_to();

        let xfr_type = match resp.qtype() {
            Some(Rtype::AXFR) => XfrType::Axfr,
            Some(Rtype::IXFR) => XfrType::Ixfr,
            _ => unreachable!(),
        };

        let Some(Ok(record)) = records.next() else {
            return Err(ProcessingError::Malformed);
        };

        // The initial record should be a SOA record.
        let ZoneRecordData::Soa(soa) = record.into_data() else {
            return Err(ProcessingError::NotValidXfrResponse);
        };

        let state = RecordProcessor::new(xfr_type, soa);

        Ok(Inner { resp, state })
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
    pub(super) actual_xfr_type: XfrType,

    /// The initial SOA record that signals the start and end of both AXFR and
    /// IXFR response sequences.
    pub(super) initial_soa: Soa<ParsedName<Bytes>>,

    /// The current SOA record.
    ///
    /// For AXFR response sequences this will be the same as `initial_soa`.
    /// For IXFR response sequences this will be the last SOA record parsed as
    /// each diff sequence contains two SOA records: one at the start of the
    /// delete sequence and one at the start of the add sequence.
    pub(super) current_soa: Soa<ParsedName<Bytes>>,

    /// The kind of records currently being processed, either adds or deletes.
    pub(super) ixfr_update_mode: IxfrUpdateMode,

    /// The number of resource records parsed so far.
    pub(super) rr_count: usize,
}

impl RecordProcessor {
    /// Create a new [`RecordProcessor`].
    fn new(
        initial_xfr_type: XfrType,
        initial_soa: Soa<ParsedName<Bytes>>,
    ) -> Self {
        Self {
            actual_xfr_type: initial_xfr_type,
            initial_soa: initial_soa.clone(),
            current_soa: initial_soa,
            rr_count: 0,
            ixfr_update_mode: Default::default(),
        }
    }

    /// Process a single resource record.
    ///
    /// Returns an [`XfrEvent`] that should be emitted for the processed
    /// record, if any.
    pub(super) fn process_record(
        &mut self,
        rec: XfrRecord,
    ) -> XfrEvent<XfrRecord> {
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
        // XfrResponseProcessor are better placed to enforce this rule if
        // needed, e.g. at the moment of insertion into a zone tree checking
        // that the record is not already present or insertion of a duplicate
        // having no effect as it is already present.

        let soa = match rec.data() {
            ZoneRecordData::Soa(soa) => Some(soa),
            _ => None,
        };

        let record_matches_initial_soa = soa == Some(&self.initial_soa);

        match self.actual_xfr_type {
            XfrType::Axfr if record_matches_initial_soa => {
                // https://www.rfc-editor.org/rfc/rfc5936.html#section-2.2
                // 2.2.  AXFR Response
                //   ...
                //   "In such a series, the first message MUST begin with the
                //    SOA resource record of the zone, and the last message
                //    MUST conclude with the same SOA resource record.
                //    Intermediate messages MUST NOT contain the SOA resource
                //    record."
                XfrEvent::EndOfTransfer(rec)
            }

            XfrType::Axfr => {
                XfrEvent::AddRecord(self.current_soa.serial(), rec)
            }

            XfrType::Ixfr if self.rr_count < 2 => unreachable!(),

            XfrType::Ixfr if self.rr_count == 2 => {
                if record_matches_initial_soa {
                    // IXFR not available, AXFR of empty zone detected.
                    XfrEvent::EndOfTransfer(rec)
                } else if let Some(soa) = soa {
                    // This SOA record is the start of an IXFR diff sequence.
                    self.current_soa = soa.clone();

                    // We don't need to set the IXFR update more here as it
                    // should already be set to Deleting.
                    debug_assert_eq!(
                        self.ixfr_update_mode,
                        IxfrUpdateMode::Deleting
                    );

                    XfrEvent::BeginBatchDelete(rec)
                } else {
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
                    XfrEvent::AddRecord(self.current_soa.serial(), rec)
                }
            }

            XfrType::Ixfr => {
                if let Some(soa) = soa {
                    self.ixfr_update_mode.toggle();
                    self.current_soa = soa.clone();

                    match self.ixfr_update_mode {
                        IxfrUpdateMode::Deleting => {
                            // We just finished a (Delete, Add) diff sequence.
                            // Is this the end of the transfer, or the start
                            // of a new diff sequence?
                            if record_matches_initial_soa {
                                XfrEvent::EndOfTransfer(rec)
                            } else {
                                XfrEvent::BeginBatchDelete(rec)
                            }
                        }
                        IxfrUpdateMode::Adding => {
                            // We just switched from the Delete phase of a
                            // diff sequence to the add phase of the diff
                            // sequence.
                            XfrEvent::BeginBatchAdd(rec)
                        }
                    }
                } else {
                    match self.ixfr_update_mode {
                        IxfrUpdateMode::Deleting => XfrEvent::DeleteRecord(
                            self.current_soa.serial(),
                            rec,
                        ),
                        IxfrUpdateMode::Adding => XfrEvent::AddRecord(
                            self.current_soa.serial(),
                            rec,
                        ),
                    }
                }
            }
        }
    }
}