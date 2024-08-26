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
use crate::base::wire::ParseError;
use crate::base::{
    Message, ParsedName, Record, RecordSection, Rtype, Serial,
};
use crate::rdata::{AllRecordData, Soa};

//------------ XfrRecord ------------------------------------------------------

/// The type of record processed by [`XfrResponseProcessor`].
pub type XfrRecord =
    Record<ParsedName<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;

//------------ XfrResponseProcessor -------------------------------------------

/// An AXFR/IXFR response processor.
///
/// [`XfrResponseProcessor`] can be invoked on one ore more sequentially
/// AXFR/IXFR received response messages to verify them and during processing
/// emit events which an implementor of [`XfrEventHandler`] can handle.
///
/// Each instance of [`XfrResponseProcessosr`] should process a single XFR
/// response sequence. Once an instance of [`XfrResponseProcessosr`] has
/// finished processing an XFR response sequence it must be discarded.
/// Attempting to use it once processing has finished will result in an error.
/// To process another XFR response sequence create another instance of
/// [`XfrResponseProcessor`].
pub struct XfrResponseProcessor<T: XfrEventHandler> {
    /// The event handler that events will be sent to for handling.
    evt_handler: T,

    /// The current processing state.
    state: State,
}

impl<T: XfrEventHandler> XfrResponseProcessor<T> {
    /// Create a new XFR response processor.
    ///
    /// Events will be emitted to the given [`XfrEventHandler`] implementation.
    pub fn new(evt_handler: T) -> Self {
        Self {
            evt_handler,
            state: State::default(),
        }
    }

    /// Process a single AXFR/IXFR response message.
    ///
    /// During processing events will be emitted to the registered
    /// [`XfrEventHandler`] for handling.
    ///
    /// Returns Ok(true) if the XFR response was the last in the seqence,
    /// Ok(false) if more XFR response messages are needed to complete the
    /// sequence, or Err on error.
    pub async fn process_answer(
        &mut self,
        req: &Message<Bytes>,
        resp: Message<Bytes>,
    ) -> Result<bool, Error> {
        // Check that the given message is a DNS XFR response.
        let res = self.check_is_xfr_answer(req, &resp).await;

        // Unpack the XFR type and answer object. We cannot do this in the
        // line above using `map_err()` and `?` as the Rust compiler complains
        // about attempting to return `resp` while a reference to it still
        // exists.
        let (xfr_type, answer) = match res {
            Ok(values) => values,
            Err(err) => return Err(Error::from_check_error(resp, err)),
        };

        // https://datatracker.ietf.org/doc/html/rfc5936#section-3
        // 3. Zone Contents "The objective of the AXFR session is to request
        //   and transfer the contents of a zone, in order to permit the AXFR
        //    client to faithfully reconstruct the zone as it exists at the
        //    primary server for the given zone serial number.  The word
        //    "exists" here designates the externally visible behavior, i.e.,
        //    the zone content that is being served (handed out to clients) --
        //    not its persistent representation in a zone file or database
        //    used by the server -- and that for consistency should be served
        //    subsequently by the AXFR client in an identical manner."
        //
        // So, walk over all the records in the answer, not just those that
        // might be expected to exist in a zone (i.e. not just ZoneRecordData
        // record types).
        let mut records = answer.into_records();

        match self.state {
            // When given the first response in a sequence, do some initial
            // setup.
            State::AwaitingFirstAnswer => {
                let Some(Ok(record)) = records.next() else {
                    return Err(Error::Malformed);
                };

                if let Err(err) =
                    self.initialize(xfr_type, req.header().id(), record).await
                {
                    return Err(Error::from_check_error(resp, err));
                }
            }

            // For subsequent messages make sure that the XFR
            State::AwaitingNextAnswer {
                initial_xfr_type,
                initial_query_id,
                ..
            } => {
                if xfr_type != initial_xfr_type
                    || req.header().id() != initial_query_id
                {
                    // The XFR type is extracted from the request. If we were
                    // given a different request with a different question and
                    // qtype on a subsequent invocation of process_answer()
                    // that would be unexpected.
                    return Err(Error::NotValidXfrQuery);
                }
            }

            State::TransferComplete => {
                // We already finished processing an XFR response sequence. We
                // don't expect there to be any more messages to process!.
                return Err(Error::Malformed);
            }

            State::TransferFailed => {
                // We had to terminate processing of the XFR response sequence
                // due to a problem with the received data, so we don't expect
                // to be invoked again with another response message!
                return Err(Error::Terminated);
            }
        };

        let State::AwaitingNextAnswer { read, .. } = &mut self.state else {
            unreachable!();
        };

        for record in records.flatten() {
            trace!("XFR record {}: {record:?}", read.rr_count);

            if let Some(event) = read.record(record).await? {
                match event {
                    XfrEvent::EndOfTransfer => {
                        self.state = State::TransferComplete;
                        self.evt_handler.handle_event(event).await?;
                        return Ok(true);
                    }

                    XfrEvent::ProcessingFailed => {
                        self.state = State::TransferFailed;
                        let _ = self.evt_handler.handle_event(event).await;
                        return Err(Error::Malformed);
                    }

                    _ => {
                        self.evt_handler.handle_event(event).await?;
                    }
                }
            }
        }

        // Finished processing this message but did not yet reach the end of
        // the transfer, more responses are expected.
        Ok(false)
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
    async fn check_is_xfr_answer<'a>(
        &mut self,
        req: &Message<Bytes>,
        resp: &'a Message<Bytes>,
    ) -> Result<(XfrType, RecordSection<'a, Bytes>), CheckError> {
        // Check the request.
        let req_header = req.header();
        let req_counts = req.header_counts();

        if req.is_error()
            || req_header.qr()
            || req_counts.qdcount() != 1
            || req_counts.ancount() != 0
            || req_header.opcode() != Opcode::QUERY
        {
            return Err(CheckError::NotValidXfrRequest);
        }

        let Some(qtype) = req.qtype() else {
            return Err(CheckError::NotValidXfrRequest);
        };

        let xfr_type = match qtype {
            Rtype::AXFR => XfrType::Axfr,
            Rtype::IXFR => XfrType::Ixfr,
            _ => return Err(CheckError::NotValidXfrRequest),
        };

        // https://datatracker.ietf.org/doc/html/rfc1995#section-3
        // 3. Query Format
        //   "The IXFR query packet format is the same as that of a normal DNS
        //    query, but with the query type being IXFR and the authority
        //    section containing the SOA record of client's version of the
        //    zone."
        if matches!(xfr_type, XfrType::Ixfr) && req_counts.nscount() != 1 {
            return Err(CheckError::NotValidXfrResponse);
        }

        // Check the response.
        let resp_header = resp.header();
        let resp_counts = resp.header_counts();

        if resp.is_error()
            || !resp.is_answer_header(req)
            || resp_header.opcode() != Opcode::QUERY
            || resp_header.tc()
            || resp_counts.ancount() == 0
            || resp_counts.nscount() != 0
        {
            return Err(CheckError::NotValidXfrResponse);
        }

        // https://datatracker.ietf.org/doc/html/rfc1995#section-2.2.1
        // 2.2.1. Header Values
        //   "QDCOUNT     MUST be 1 in the first message;
        //                MUST be 0 or 1 in all following messages;"
        if matches!(self.state, State::AwaitingFirstAnswer)
            && (resp_counts.qdcount() != 1
                || resp.sole_question() != req.sole_question())
        {
            return Err(CheckError::NotValidXfrResponse);
        }

        let answer = resp.answer().map_err(CheckError::ParseError)?;

        Ok((xfr_type, answer))
    }

    /// Initialise the processosr.
    ///
    /// Records the initial SOA record and other details will will be used
    /// while processing the rest of the response.
    async fn initialize(
        &mut self,
        initial_xfr_type: XfrType,
        initial_query_id: u16,
        soa_record: XfrRecord,
    ) -> Result<(), CheckError> {
        // The initial record should be a SOA record.
        let data = soa_record.into_data();

        let AllRecordData::Soa(soa) = data else {
            return Err(CheckError::NotValidXfrResponse);
        };

        let read = ParsingState::new(initial_xfr_type, soa);

        self.state = State::AwaitingNextAnswer {
            initial_xfr_type,
            initial_query_id,
            read,
        };

        Ok(())
    }
}

//------------ State ----------------------------------------------------------

/// The current processing state.
#[derive(Default)]
enum State {
    /// Waiting for the first XFR response message.
    #[default]
    AwaitingFirstAnswer,

    /// Waiting for a subsequent XFR response message.
    AwaitingNextAnswer {
        /// The type of XFR response sequence expected based on the initial
        /// request and response.
        initial_xfr_type: XfrType,

        /// The header ID of the original XFR request.
        initial_query_id: u16,

        /// The current parsing state.
        read: ParsingState,
    },

    /// The end of the XFR response sequence was detected.
    TransferComplete,

    /// An unrecoverable problem occurred while processing the XFR response
    /// sequence.
    TransferFailed,
}

//------------ ParsingState ---------------------------------------------------

/// State related to parsing the XFR response sequence.
#[derive(Debug)]
struct ParsingState {
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

impl ParsingState {
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
    async fn record(
        &mut self,
        rec: XfrRecord,
    ) -> Result<Option<XfrEvent<XfrRecord>>, Error> {
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
                Ok(Some(XfrEvent::EndOfTransfer))
            }

            XfrType::Axfr => {
                Ok(Some(XfrEvent::AddRecord(self.current_soa.serial(), rec)))
            }

            XfrType::Ixfr if self.rr_count < 2 => unreachable!(),

            XfrType::Ixfr if self.rr_count == 2 => {
                if record_matches_initial_soa {
                    // IXFR not available, AXFR of empty zone detected.
                    Ok(Some(XfrEvent::EndOfTransfer))
                } else if let Some(soa) = soa {
                    // This SOA record is the start of an IXFR diff sequence.
                    self.current_soa = soa.clone();

                    // We don't need to set the IXFR update more here as it
                    // should already be set to Deleting.
                    debug_assert_eq!(
                        self.ixfr_update_mode,
                        IxfrUpdateMode::Deleting
                    );

                    Ok(Some(XfrEvent::BeginBatchDelete(soa.serial())))
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
                    Ok(Some(XfrEvent::AddRecord(
                        self.current_soa.serial(),
                        rec,
                    )))
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
                                Ok(Some(XfrEvent::EndOfTransfer))
                            } else {
                                Ok(Some(XfrEvent::BeginBatchDelete(
                                    self.current_soa.serial(),
                                )))
                            }
                        }
                        IxfrUpdateMode::Adding => {
                            // We just switched from the Delete phase of a
                            // diff sequence to the add phase of the diff
                            // sequence.
                            Ok(Some(XfrEvent::BeginBatchAdd(
                                self.current_soa.serial(),
                            )))
                        }
                    }
                } else {
                    match self.ixfr_update_mode {
                        IxfrUpdateMode::Deleting => {
                            Ok(Some(XfrEvent::DeleteRecord(
                                self.current_soa.serial(),
                                rec,
                            )))
                        }
                        IxfrUpdateMode::Adding => {
                            Ok(Some(XfrEvent::AddRecord(
                                self.current_soa.serial(),
                                rec,
                            )))
                        }
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

//------------ XfrEventHandler ---------------------------------------------------

/// A trait for implementing handlers of [`XfrEvent`]s.
pub trait XfrEventHandler {
    type Fut: std::future::Future<Output = Result<(), Error>>;

    /// Handle the given [`XfrEvent`].
    ///
    /// Returning an Err will cause transfer processsing to be aborted and the
    /// error to be returned to the client of [`XfrResponseProcessor`], except in
    /// the case of [`XfrEvent::ProcessingFailed`] for which the return value of
    /// this handler will be ignored by [`XfrResponseProcessor`].
    fn handle_event(&self, evt: XfrEvent<XfrRecord>) -> Self::Fut;
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
    ParseError(ParseError, Message<Bytes>),

    /// The request message is not an XFR query/
    NotValidXfrQuery,

    /// The response message is not an XFR response.
    NotValidXfrResponse(Message<Bytes>),

    /// At least one record in the XFR response sequence is incorrect.
    Malformed,

    /// Processing was already terminated for this XFR response sequence.
    Terminated,
}

impl Error {
    /// Convert a [`CheckError`] to an [`Error`].
    fn from_check_error(
        msg: Message<Bytes>,
        prepare_err: CheckError,
    ) -> Self {
        match prepare_err {
            CheckError::ParseError(err) => Self::ParseError(err, msg),
            CheckError::NotValidXfrRequest => Self::NotValidXfrQuery,
            CheckError::NotValidXfrResponse => Self::NotValidXfrResponse(msg),
        }
    }
}

//------------ PrepareError ---------------------------------------------------

/// Errors that can occur during intiial checking of an XFR response sequence.
#[derive(Debug)]
enum CheckError {
    /// A parsing error occurred while checking the original request and
    /// response messages.
    ParseError(ParseError),

    /// The XFR request is not valid according to the rules defined by RFC
    /// 5936 (AXFR) or RFC 1995 (IXFR).
    NotValidXfrRequest,

    /// The XFR response is not valid according to the rules defined by RFC
    /// 5936 (AXFR) or RFC 1995 (IXFR).
    NotValidXfrResponse,
}

//--- From<ParseError>

impl From<ParseError> for CheckError {
    fn from(err: ParseError) -> Self {
        Self::ParseError(err)
    }
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
    use core::future::ready;
    use core::future::Ready;
    use core::str::FromStr;

    use std::string::String;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::vec::Vec;

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

    use super::*;

    #[tokio::test]
    async fn request_message_is_rejected() {
        init_logging();

        // Create a non-XFR request to reply to.
        let req = mk_request("example.com", Rtype::A).into_message();

        // Process the request and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert_xfr_response(
            &req.clone(),
            req,
            |res| matches!(res, Err(Error::NotValidXfrResponse(_))),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn non_xfr_response_is_rejected() {
        init_logging();

        // Create a non-XFR request to reply to.
        let req = mk_request("example.com", Rtype::A).into_message();

        // Create a non-XFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Err(Error::NotValidXfrResponse(_))),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn axfr_response_with_no_answers_is_rejected() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create a response that lacks answers.
        let answer = mk_empty_answer(&req, Rcode::NOERROR);

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Err(Error::NotValidXfrResponse(_))),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn error_axfr_response_is_rejected() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create a minimal valid AXFR response, just something that should
        // not be rejected by the XFR processor due to its content. It should
        // however be rejected due to the non-NOERROR rcode.
        let mut answer = mk_empty_answer(&req, Rcode::SERVFAIL);
        add_answer_record(&req, &mut answer, mk_soa(Serial::now()));

        // Process the response and assert that it is rejected as not being
        // a valid XFR response and that no XFR processor events were emitted.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Err(Error::NotValidXfrResponse(_))),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn incomplete_axfr_response_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an incomplete AXFR response. A proper AXFR response has at
        // least two identical SOA records, one at the start and one at the
        // end, but this response contains only a single SOA record. This is
        // not considered invalid however because a subsequent response could
        // still provide the missing SOA record.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, mk_soa(Serial::now()));

        // Process the response and assert that Ok(false) is returned by the
        // XFR processor indicating that the XFR response was incomplete. Also
        // verify the events emitted by the XFR processor.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(false)),
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn axfr_response_with_only_soas_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create a complete but minimal AXFR response. A proper AXFR response
        // has at least two identical SOA records, one at the start and one at
        // the end, with actual zone records in between. This response has only
        // the start and end SOA and no content in between. RFC 5936 doesn't
        // seem to disallow this.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let soa = mk_soa(Serial::now());
        add_answer_record(&req, &mut answer, soa.clone());
        add_answer_record(&req, &mut answer, soa);

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(true)),
            &["EndOfTransfer"],
        )
        .await;
    }

    #[tokio::test]
    async fn axfr_multi_response_with_only_soas_is_accepted() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create a complete but minimal AXFR response. A proper AXFR response
        // has at least two identical SOA records, one at the start and one at
        // the end, with actual zone records in between. This response has only
        // the start and end SOA and no content in between. RFC 5936 doesn't
        // seem to disallow this.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let soa = mk_soa(Serial::now());
        add_answer_record(&req, &mut answer, soa.clone());

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        let (evt_handler, mut processor) = assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(false)),
            &[],
        )
        .await;

        // Create another AXFR response to complete the transfer.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        add_answer_record(&req, &mut answer, soa);

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        assert_xfr_response_with_processor(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(true)),
            &["EndOfTransfer"],
            evt_handler,
            &mut processor,
        )
        .await;
    }

    #[tokio::test]
    async fn axfr_response_generates_expected_events() {
        init_logging();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an AXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let soa = mk_soa(Serial::now());
        add_answer_record(&req, &mut answer, soa.clone());
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        add_answer_record(&req, &mut answer, soa);

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(true)),
            &["AddRecord", "AddRecord", "EndOfTransfer"],
        )
        .await;
    }

    #[tokio::test]
    async fn ixfr_response_generates_expected_events() {
        init_logging();

        // Create an IXFR request to reply to.
        let req = mk_request("example.com", Rtype::IXFR);
        let mut authority = req.authority();
        let client_serial = Serial::now();
        let soa = mk_soa(client_serial);
        add_authority_record(&mut authority, soa);
        let req = authority.into_message();

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

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(true)),
            &[
                "BeginBatchDelete",
                "DeleteRecord",
                "DeleteRecord",
                "BeginBatchAdd",
                "AddRecord",
                "AddRecord",
                "EndOfTransfer",
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn multi_ixfr_response_generates_expected_events() {
        init_logging();

        // Create an IXFR request to reply to.
        let req = mk_request("example.com", Rtype::IXFR);
        let mut authority = req.authority();
        let client_serial = Serial::now();
        let soa = mk_soa(client_serial);
        add_authority_record(&mut authority, soa);
        let req = authority.into_message();

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

        // Process the response and assert that Ok(true) is returned by the
        // XFR processor indicating that the XFR response was complete. Also
        // verify the events emitted by the XFR processor.
        let (evt_handler, mut processor) = assert_xfr_response(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(false)),
            &["BeginBatchDelete", "DeleteRecord"],
        )
        .await;

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

        assert_xfr_response_with_processor(
            &req,
            answer.into_message(),
            |res| matches!(res, Ok(true)),
            &[
                "BeginBatchDelete", // Seen during processing of the 1st answer
                "DeleteRecord", // Seen during processing of the 1st answer
                "DeleteRecord", // Seen during processing of the 2nd answer
                "BeginBatchAdd", // Seen during processing of the 2nd answer
                "AddRecord",    // Seen during processing of the 2nd answer
                "AddRecord",    // Seen during processing of the 2nd answer
                "EndOfTransfer", // Seen during processing of the 2nd answer
            ],
            evt_handler,
            &mut processor,
        )
        .await;
    }

    //------------ TestXfrEventHandler ----------------------------------------

    #[derive(Clone, Default)]
    struct TestXfrEventHandler {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl TestXfrEventHandler {
        pub fn new() -> Self {
            Self::default()
        }

        pub async fn events(self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
    }

    impl XfrEventHandler for TestXfrEventHandler {
        type Fut = Ready<Result<(), Error>>;

        fn handle_event(&self, evt: XfrEvent<XfrRecord>) -> Self::Fut {
            trace!("Received event: {evt}");
            self.events.lock().unwrap().push(format!("{evt}"));
            ready(Ok(()))
        }
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

    async fn assert_xfr_response(
        req: &Message<Bytes>,
        resp: Message<Bytes>,
        res_check_cb: fn(&Result<bool, Error>) -> bool,
        expected_events: &[&str],
    ) -> (
        TestXfrEventHandler,
        XfrResponseProcessor<TestXfrEventHandler>,
    ) {
        let evt_handler = TestXfrEventHandler::new();
        let mut processor = XfrResponseProcessor::new(evt_handler.clone());

        assert_xfr_response_with_processor(
            req,
            resp,
            res_check_cb,
            expected_events,
            evt_handler.clone(),
            &mut processor,
        )
        .await;

        (evt_handler, processor)
    }

    async fn assert_xfr_response_with_processor(
        req: &Message<Bytes>,
        resp: Message<Bytes>,
        res_check_cb: fn(&Result<bool, Error>) -> bool,
        expected_events: &[&str],
        evt_handler: TestXfrEventHandler,
        processor: &mut XfrResponseProcessor<TestXfrEventHandler>,
    ) {
        let res = processor.process_answer(req, resp).await;

        // Verify that the XFR processor returns an error.
        assert!(
            res_check_cb(&res),
            "Unexpected result {res:?} from the XFR processor",
        );

        // Verify that no XFR processing events were emitted.
        assert_eq!(
            &evt_handler.clone().events().await,
            expected_events,
            "Unexpected events were emitted by the XFR processor"
        );
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
