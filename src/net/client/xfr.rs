//! Parsing of AXFR/IXFR response messages for higher level processing.
//!
//! This module provides [`XfrResponseProcessor`] which enables you to process
//! one or more AXFR/IXFR response messages in terms of the high level
//! [`XfrEvent`]s that they represent without having to deal with the
//! AXFR/IXFR protocol details.
use std::fmt::Debug;

use bytes::Bytes;
use tracing::trace;

use crate::base::iana::Opcode;
use crate::base::message::AnyRecordIter;
use crate::base::wire::ParseError;
use crate::base::{Message, ParsedName, Record, Rtype, Serial};
use crate::rdata::{AllRecordData, Soa};

//------------ XfrRecord ------------------------------------------------------

/// The type of record processed by [`XfrResponseProcessor`].
pub type XfrRecord =
    Record<ParsedName<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;

//------------ XfrResponseProcessor -------------------------------------------

/// An AXFR/IXFR response processor.
///
/// [`XfrResponseProcessor`] can be invoked on one or more sequentially
/// AXFR/IXFR received response messages to verify them and during processing
/// emit events which can be consumed via the iterator returned by
/// [`process_answer()`].
///
/// Each [`XfrEventIterator`] produces events for a single response message.
/// If the end of the XFR response sequence has been reached the iterator will
/// emit an [`XfrEvent::TransferComplete`] event.
///
/// If the `TransferComplete` event has not been seen it means that the
/// sequence is incomplete and the next response message in the sequence
/// should be passed to [`process_next_answer()`] along with the exhausted
/// iterator. This will populate thr [`XfrEventIterator`] with more records
/// to parse thereby causing iteration to resume.
///
/// The process of producing and consuming iterators continues until the end
/// of the transfer is detected or a parsing error occurs.
pub struct XfrResponseProcessor {
    /// The XFR request for which responses should be processed.
    req: Message<Bytes>,

    /// Internal state.
    inner: Inner,
}

#[derive(Default)]
struct Inner {
    /// The response message currently being processed.
    resp: Option<Message<Bytes>>,

    /// The processing state.
    iteration_state: Option<State>,
}

impl XfrResponseProcessor {
    /// Creates a new instance of [`XfrMessageProcessor`].
    ///
    /// Processes a single XFR response stream.
    pub fn new(req: Message<Bytes>) -> Result<Self, Error> {
        Self::check_request(&req)?;
        Ok(Self {
            req,
            inner: Default::default(),
        })
    }
}

impl XfrResponseProcessor {
    /// Process a single AXFR/IXFR response message.
    ///
    /// Return an [`XfrEventIterator`] over [`XfrEvent`]s emitted during
    /// processing.
    ///
    /// If the returned iterator does not emit an
    /// [`XfrEvent::TransferComplete`] event, call [`process_next_answer()`]
    /// with the next response message to continue iterating over the transfer
    /// responses.
    pub fn process_answer(
        &mut self,
        resp: Message<Bytes>,
    ) -> Result<XfrEventIterator, Error> {
        // Check that the given message is a DNS XFR response.
        self.check_response(&resp)?;

        let is_first = self.inner.initialize(&self.req, resp)?;

        XfrEventIterator::new(
            is_first,
            &mut self.inner.iteration_state,
            self.inner.resp.as_ref().unwrap(),
        )
    }

    /// Check if an XFR request is valid.
    fn check_request(req: &Message<Bytes>) -> Result<(), Error> {
        let req_header = req.header();
        let req_counts = req.header_counts();

        if req.is_error()
            || req_header.qr()
            || req_counts.qdcount() != 1
            || req_counts.ancount() != 0
            || req_header.opcode() != Opcode::QUERY
        {
            return Err(Error::NotValidXfrRequest);
        }

        let Some(qtype) = req.qtype() else {
            return Err(Error::NotValidXfrRequest);
        };

        if !matches!(qtype, Rtype::AXFR | Rtype::IXFR) {
            return Err(Error::NotValidXfrRequest);
        }

        // https://datatracker.ietf.org/doc/html/rfc1995#section-3
        // 3. Query Format
        //   "The IXFR query packet format is the same as that of a normal DNS
        //    query, but with the query type being IXFR and the authority
        //    section containing the SOA record of client's version of the
        //    zone."
        if matches!(qtype, Rtype::IXFR) && req_counts.nscount() != 1 {
            return Err(Error::NotValidXfrRequest);
        }

        Ok(())
    }

    /// Check if an XFR response header is valid.
    ///
    /// Enforce the rules defined in 2. AXFR Messages of RFC 5936. See:
    /// https://www.rfc-editor.org/rfc/rfc5936.html#section-2
    ///
    /// Takes a request as well as a response as the response is checked to
    /// see if it is in reply to the given request.
    ///
    /// Returns Ok on success, Err otherwise. On success the type of XFR that
    /// was determined is returned as well as the answer section from the XFR
    /// response.
    fn check_response(&self, resp: &Message<Bytes>) -> Result<(), Error> {
        let resp_header = resp.header();
        let resp_counts = resp.header_counts();

        if resp.is_error()
            || !resp.is_answer_header(&self.req)
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
        if (self.inner.iteration_state.is_none() && qdcount != 1)
            || (self.inner.iteration_state.is_some() && qdcount > 1)
        {
            return Err(Error::NotValidXfrResponse);
        }

        Ok(())
    }
}

impl Inner {
    /// Initialise the processosr.
    ///
    /// Records the initial SOA record and other details will will be used
    /// while processing the rest of the response.
    fn initialize(
        &mut self,
        req: &Message<Bytes>,
        resp: Message<Bytes>,
    ) -> Result<bool, Error> {
        self.resp = Some(resp);

        if self.iteration_state.is_none() {
            let Some(resp) = &self.resp else {
                unreachable!();
            };

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

            let mut records = answer.into_records();

            let xfr_type = match req.qtype() {
                Some(Rtype::AXFR) => XfrType::Axfr,
                Some(Rtype::IXFR) => XfrType::Ixfr,
                _ => unreachable!(), // Checked already in check_request().
            };

            let Some(Ok(record)) = records.next() else {
                return Err(Error::Malformed);
            };

            // The initial record should be a SOA record.
            let AllRecordData::Soa(soa) = record.into_data() else {
                return Err(Error::NotValidXfrResponse);
            };

            self.iteration_state.replace(State::new(xfr_type, soa));

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

//------------ State ----------------------------------------------------------

/// State related to parsing the XFR response sequence.
#[derive(Debug)]
struct State {
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
}

impl State {
    /// Create a new parsing state.
    fn new(
        initial_xfr_type: XfrType,
        initial_soa: Soa<ParsedName<Bytes>>,
    ) -> Self {
        Self {
            actual_xfr_type: initial_xfr_type,
            initial_soa: initial_soa.clone(),
            current_soa: initial_soa,
            rr_count: 1,
            ixfr_update_mode: Default::default(),
        }
    }

    /// Parse a single resource record.
    ///
    /// Returns an [`XfrEvent`] that should be emitted for the parsed record,
    /// if any.
    fn parse_record(&mut self, rec: XfrRecord) -> XfrEvent<XfrRecord> {
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
            AllRecordData::Soa(soa) => Some(soa),
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
                XfrEvent::EndOfTransfer
            }

            XfrType::Axfr => {
                XfrEvent::AddRecord(self.current_soa.serial(), rec)
            }

            XfrType::Ixfr if self.rr_count < 2 => unreachable!(),

            XfrType::Ixfr if self.rr_count == 2 => {
                if record_matches_initial_soa {
                    // IXFR not available, AXFR of empty zone detected.
                    XfrEvent::EndOfTransfer
                } else if let Some(soa) = soa {
                    // This SOA record is the start of an IXFR diff sequence.
                    self.current_soa = soa.clone();

                    // We don't need to set the IXFR update more here as it
                    // should already be set to Deleting.
                    debug_assert_eq!(
                        self.ixfr_update_mode,
                        IxfrUpdateMode::Deleting
                    );

                    XfrEvent::BeginBatchDelete(soa.serial())
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
                                XfrEvent::EndOfTransfer
                            } else {
                                XfrEvent::BeginBatchDelete(
                                    self.current_soa.serial(),
                                )
                            }
                        }
                        IxfrUpdateMode::Adding => {
                            // We just switched from the Delete phase of a
                            // diff sequence to the add phase of the diff
                            // sequence.
                            XfrEvent::BeginBatchAdd(self.current_soa.serial())
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

//------------ RecordResult ---------------------------------------------------

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

//------------ XfrEventIterator -----------------------------------------------

/// An iterator over [`XfrResponseProcessor`] generated [`XfrEvent`]s.
pub struct XfrEventIterator<'a, 'b> {
    /// The parent processor.
    iteration_state: &'a mut Option<State>,

    /// An iterator over the records in the current response.
    iter: AnyRecordIter<'b, Bytes, AllRecordData<Bytes, ParsedName<Bytes>>>,
}

impl<'a, 'b> XfrEventIterator<'a, 'b> {
    fn new(
        is_first: bool,
        iteration_state: &'a mut Option<State>,
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

        if is_first {
            let Some(Ok(_)) = iter.next() else {
                return Err(Error::Malformed);
            };
        }

        Ok(Self {
            iteration_state,
            iter,
        })
    }
}

impl<'a, 'b> Iterator for XfrEventIterator<'a, 'b> {
    type Item = Result<XfrEvent<XfrRecord>, XfrEventIteratorError>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(iteration_state) = self.iteration_state else {
            unreachable!();
        };

        match self.iter.next() {
            Some(Ok(record)) => {
                trace!(
                    "XFR record {}: {record:?}",
                    iteration_state.rr_count
                );
                let event = iteration_state.parse_record(record);

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

//------------ XfrEventIteratorError ------------------------------------------

/// Errors that can occur during XfrEventIterator iteration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XfrEventIteratorError {
    /// Transfer processing failed.
    ParseError(ParseError),
}

//------------ IxfrUpdateMode -------------------------------------------------

/// The kind of records currently being processed, either adds or deletes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum IxfrUpdateMode {
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
    fn toggle(&mut self) {
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

//------------ XfrType --------------------------------------------------------

/// The type of XFR response sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum XfrType {
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

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use bytes::BytesMut;
    use octseq::Octets;

    use crate::base::iana::Rcode;
    use crate::base::message_builder::{
        AnswerBuilder, AuthorityBuilder, QuestionBuilder,
    };
    use crate::base::net::Ipv4Addr;
    use crate::base::rdata::ComposeRecordData;
    use crate::base::{MessageBuilder, Ttl};
    use crate::base::{Name, ToName};
    use crate::rdata::A;

    use super::XfrEvent as XE;
    use super::*;

    #[test]
    fn request_message_is_rejected() {
        init_logging();

        // Create a no/n-XFR request to reply to.
        let req = mk_request("example.com", Rtype::A).into_message();

        // Create an XFR response processor.
        let res = XfrResponseProcessor::new(req.clone());

        // Process the request and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert!(matches!(res, Err(Error::NotValidXfrRequest)));
    }

    #[test]
    fn non_xfr_response_is_rejected() {
        init_logging();

        // Create an AXFR-like request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create a non-XFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        let resp = answer.into_message();

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert!(matches!(
            processor.process_answer(resp),
            Err(Error::NotValidXfrResponse)
        ));
    }

    #[test]
    fn axfr_response_with_no_answers_is_rejected() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create a response that lacks answers.
        let resp = mk_empty_answer(&req, Rcode::NOERROR).into_message();

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert!(matches!(
            processor.process_answer(resp),
            Err(Error::NotValidXfrResponse)
        ));
    }

    #[test]
    fn error_axfr_response_is_rejected() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create a minimal valid AXFR response, just something that should
        // not be rejected by the XFR processor due to its content. It should
        // however be rejected due to the non-NOERROR rcode.
        let mut answer = mk_empty_answer(&req, Rcode::SERVFAIL);
        add_answer_record(&req, &mut answer, mk_soa(Serial::now()));
        let resp = answer.into_message();

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert!(matches!(
            processor.process_answer(resp),
            Err(Error::NotValidXfrResponse)
        ));
    }

    #[test]
    fn incomplete_axfr_response_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create an incomplete AXFR response. A proper AXFR response has at
        // least two identical SOA records, one at the start and one at the
        // end, but this response contains only a single SOA record. This is
        // not considered invalid however because a subsequent response could
        // still provide the missing SOA record.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, mk_soa(Serial::now()));
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify that no events are by the XFR processor.
        assert!(it.next().is_none());
    }

    #[test]
    fn axfr_response_with_only_soas_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create a complete but minimal AXFR response. A proper AXFR response
        // has at least two identical SOA records, one at the start and one at
        // the end, with actual zone records in between. This response has only
        // the start and end SOA and no content in between. RFC 5936 doesn't
        // seem to disallow this.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let soa = mk_soa(Serial::now());
        add_answer_record(&req, &mut answer, soa.clone());
        add_answer_record(&req, &mut answer, soa);
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer))));
        assert!(it.next().is_none());
    }

    #[test]
    fn axfr_multi_response_with_only_soas_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create a complete but minimal AXFR response. A proper AXFR response
        // has at least two identical SOA records, one at the start and one at
        // the end, with actual zone records in between. This response has only
        // the start and end SOA and no content in between. RFC 5936 doesn't
        // seem to disallow this.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let soa = mk_soa(Serial::now());
        add_answer_record(&req, &mut answer, soa.clone());
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        assert!(it.next().is_none());

        // Create another AXFR response to complete the transfer.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, soa);
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer))));
        assert!(it.next().is_none());
    }

    #[test]
    fn axfr_response_generates_expected_events() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Create an AXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let serial = Serial::now();
        let soa = mk_soa(serial);
        add_answer_record(&req, &mut answer, soa.clone());
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        add_answer_record(&req, &mut answer, soa);
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        let s = serial;
        assert!(matches!(it.next(), Some(Ok(XE::AddRecord(n, _))) if n == s));
        assert!(matches!(it.next(), Some(Ok(XE::AddRecord(n, _))) if n == s));
        assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer))));
        assert!(it.next().is_none());
    }

    #[test]
    fn ixfr_response_generates_expected_events() {
        init_logging();

        // Create an IXFR request to reply to.
        let req = mk_request("example.com", Rtype::IXFR);
        let mut authority = req.authority();
        let client_serial = Serial::now();
        let soa = mk_soa(client_serial);
        add_authority_record(&mut authority, soa);
        let req = authority.into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Prepare some serial numbers and SOA records to use in the IXFR response.
        let old_serial = client_serial;
        let new_serial = client_serial.add(1);
        let old_soa = mk_soa(old_serial);
        let new_soa = mk_soa(new_serial);

        // Create an IXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        // Outer SOA with servers current SOA
        add_answer_record(&req, &mut answer, new_soa.clone());
        // Start of diff sequence: SOA of the servers' previous zone version
        // (which matches that of the client) followed by records to be
        // deleted as they were in that version of the zone but are not in the
        // new version of the zone.
        add_answer_record(&req, &mut answer, old_soa);
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        // SOA of the servers` new zone version (which is ahead of that of the
        // client) followed by records to be added as they were added in this
        // new version of the zone.`
        add_answer_record(&req, &mut answer, new_soa.clone());
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        // Closing SOA with servers current SOA
        add_answer_record(&req, &mut answer, new_soa);
        let resp = answer.into_message();

        // Process the response.
        let it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        let owner = ParsedName::from(Name::from_str("example.com").unwrap());
        let expected_events = [
            Ok(XfrEvent::BeginBatchDelete(old_serial)),
            Ok(XfrEvent::DeleteRecord(
                old_serial,
                Record::from((
                    owner.clone(),
                    0,
                    AllRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
                )),
            )),
            Ok(XfrEvent::DeleteRecord(
                old_serial,
                Record::from((
                    owner.clone(),
                    0,
                    AllRecordData::A(A::new(Ipv4Addr::BROADCAST)),
                )),
            )),
            Ok(XfrEvent::BeginBatchAdd(new_serial)),
            Ok(XfrEvent::AddRecord(
                new_serial,
                Record::from((
                    owner.clone(),
                    0,
                    AllRecordData::A(A::new(Ipv4Addr::BROADCAST)),
                )),
            )),
            Ok(XfrEvent::AddRecord(
                new_serial,
                Record::from((
                    owner,
                    0,
                    AllRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
                )),
            )),
            Ok(XfrEvent::EndOfTransfer),
        ];

        assert!(it.eq(expected_events));
    }

    #[test]
    fn multi_ixfr_response_generates_expected_events() {
        init_logging();

        // Create an IXFR request to reply to.
        let req = mk_request("example.com", Rtype::IXFR);
        let mut authority = req.authority();
        let client_serial = Serial::now();
        let soa = mk_soa(client_serial);
        add_authority_record(&mut authority, soa);
        let req = authority.into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new(req.clone()).unwrap();

        // Prepare some serial numbers and SOA records to use in the IXFR response.
        let old_serial = client_serial;
        let new_serial = client_serial.add(1);
        let old_soa = mk_soa(old_serial);
        let new_soa = mk_soa(new_serial);

        // Create a partial IXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        // Outer SOA with servers current SOA
        add_answer_record(&req, &mut answer, new_soa.clone());
        // Start of diff sequence: SOA of the servers' previous zone version
        // (which matches that of the client) followed by records to be
        // deleted as they were in that version of the zone but are not in the
        // new version of the zone.
        add_answer_record(&req, &mut answer, old_soa);
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        assert!(matches!(it.next(), Some(Ok(XE::BeginBatchDelete(_)))));
        assert!(matches!(it.next(), Some(Ok(XE::DeleteRecord(..)))));

        // Craete a second IXFR response that completes the transfer
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        // SOA of the servers` new zone version (which is ahead of that of the
        // client) followed by records to be added as they were added in this
        // new version of the zone.`
        add_answer_record(&req, &mut answer, new_soa.clone());
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        // Closing SOA with servers current SOA
        add_answer_record(&req, &mut answer, new_soa);
        let resp = answer.into_message();

        // Process the response.
        let mut it = processor.process_answer(resp).unwrap();

        // Verify the events emitted by the XFR processor.
        assert!(matches!(it.next(), Some(Ok(XE::DeleteRecord(..)))));
        assert!(matches!(it.next(), Some(Ok(XE::BeginBatchAdd(_)))));
        assert!(matches!(it.next(), Some(Ok(XE::AddRecord(..)))));
        assert!(matches!(it.next(), Some(Ok(XE::AddRecord(..)))));
        assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer))));
        assert!(it.next().is_none());
    }

    //------------ Helper functions -------------------------------------------

    fn init_logging() {
        // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
        // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
        // numbers and types as they are being executed.
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_thread_ids(true)
            .without_time()
            .try_init()
            .ok();
    }

    fn mk_request(qname: &str, qtype: Rtype) -> QuestionBuilder<BytesMut> {
        let req = MessageBuilder::new_bytes();
        let mut req = req.question();
        req.push((Name::vec_from_str(qname).unwrap(), qtype))
            .unwrap();
        req
    }

    fn mk_empty_answer(
        req: &Message<Bytes>,
        rcode: Rcode,
    ) -> AnswerBuilder<BytesMut> {
        let builder = MessageBuilder::new_bytes();
        builder.start_answer(req, rcode).unwrap()
    }

    fn add_answer_record<O: Octets, T: ComposeRecordData>(
        req: &Message<O>,
        answer: &mut AnswerBuilder<BytesMut>,
        item: T,
    ) {
        let question = req.sole_question().unwrap();
        let qname = question.qname();
        let qclass = question.qclass();
        answer
            .push((qname, qclass, Ttl::from_secs(0), item))
            .unwrap();
    }

    fn add_authority_record<T: ComposeRecordData>(
        authority: &mut AuthorityBuilder<BytesMut>,
        item: T,
    ) {
        let (qname, qclass) = {
            let question = authority.as_message().sole_question().unwrap();
            let qname = question.qname().to_bytes();
            let qclass = question.qclass();
            (qname, qclass)
        };
        authority
            .push((qname, qclass, Ttl::from_secs(0), item))
            .unwrap();
    }

    fn mk_soa(serial: Serial) -> Soa<Name<Bytes>> {
        let mname = Name::from_str("mname").unwrap();
        let rname = Name::from_str("rname").unwrap();
        let ttl = Ttl::from_secs(0);
        Soa::new(mname, rname, serial, ttl, ttl, ttl, ttl)
    }
}
