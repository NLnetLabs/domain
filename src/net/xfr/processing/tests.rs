use core::str::FromStr;

use bytes::{Bytes, BytesMut};
use octseq::{Octets, Parser};

use crate::base::iana::Rcode;
use crate::base::message_builder::{
    AnswerBuilder, AuthorityBuilder, QuestionBuilder,
};
use crate::base::net::Ipv4Addr;
use crate::base::rdata::ComposeRecordData;
use crate::base::{
    Message, MessageBuilder, ParsedName, Record, Rtype, Serial, Ttl,
};
use crate::base::{Name, ToName};
use crate::rdata::{Soa, ZoneRecordData, A};

use super::processor::XfrResponseInterpreter;
use super::types::{
    IterationError, ProcessingError, XfrEvent, XfrEvent as XE, XfrRecord,
};

#[test]
fn non_xfr_response_is_rejected() {
    init_logging();

    // Create an AXFR-like request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

    // Create a non-XFR response.
    let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    let resp = answer.into_message();

    // Process the response and assert that it is rejected as not being
    // a valid XFR response and that no XFR processor events were emitted.
    assert!(matches!(
        processor.process_answer(resp),
        Err(ProcessingError::NotValidXfrResponse)
    ));
}

#[test]
fn axfr_response_with_no_answers_is_rejected() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

    // Create a response that lacks answers.
    let resp = mk_empty_answer(&req, Rcode::NOERROR).into_message();

    // Process the response and assert that it is rejected as not being
    // a valid XFR response and that no XFR processor events were emitted.
    assert!(matches!(
        processor.process_answer(resp),
        Err(ProcessingError::NotValidXfrResponse)
    ));
}

#[test]
fn error_axfr_response_is_rejected() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

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
        Err(ProcessingError::NotValidXfrResponse)
    ));
}

#[test]
fn incomplete_axfr_response_is_accepted() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

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
    let mut processor = XfrResponseInterpreter::new();

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
    assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer(_)))));
    assert!(it.next().is_none());
}

#[test]
fn axfr_multi_response_with_only_soas_is_accepted() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

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
    assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer(_)))));
    assert!(it.next().is_none());
}

#[test]
fn axfr_response_generates_expected_events() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response processor.
    let mut processor = XfrResponseInterpreter::new();

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
    assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer(_)))));
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
    let mut processor = XfrResponseInterpreter::new();

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
    add_answer_record(&req, &mut answer, old_soa.clone());
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
    // SOA of the servers` new zone version (which is ahead of that of the
    // client) followed by records to be added as they were added in this
    // new version of the zone.`
    add_answer_record(&req, &mut answer, new_soa.clone());
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    // Closing SOA with servers current SOA
    add_answer_record(&req, &mut answer, new_soa.clone());
    let resp = answer.into_message();

    // Process the response.
    let it = processor.process_answer(resp).unwrap();

    // Make parsed versions of the old and new SOAs.
    let mut buf = BytesMut::new();
    new_soa.compose_rdata(&mut buf).unwrap();
    let buf = buf.freeze();
    let mut parser = Parser::from_ref(&buf);
    let expected_new_soa = Soa::parse(&mut parser).unwrap();

    let mut buf = BytesMut::new();
    old_soa.compose_rdata(&mut buf).unwrap();
    let buf = buf.freeze();
    let mut parser = Parser::from_ref(&buf);
    let expected_old_soa = Soa::parse(&mut parser).unwrap();

    // Verify the events emitted by the XFR processor.
    let owner =
        ParsedName::<Bytes>::from(Name::from_str("example.com").unwrap());
    let expected_events: [Result<XfrEvent<XfrRecord>, IterationError>; 7] = [
        Ok(XfrEvent::BeginBatchDelete(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_old_soa),
        )))),
        Ok(XfrEvent::DeleteRecord(
            old_serial,
            Record::from((
                owner.clone(),
                0,
                ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
            )),
        )),
        Ok(XfrEvent::DeleteRecord(
            old_serial,
            Record::from((
                owner.clone(),
                0,
                ZoneRecordData::A(A::new(Ipv4Addr::BROADCAST)),
            )),
        )),
        Ok(XfrEvent::BeginBatchAdd(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_new_soa.clone()),
        )))),
        Ok(XfrEvent::AddRecord(
            new_serial,
            Record::from((
                owner.clone(),
                0,
                ZoneRecordData::A(A::new(Ipv4Addr::BROADCAST)),
            )),
        )),
        Ok(XfrEvent::AddRecord(
            new_serial,
            Record::from((
                owner.clone(),
                0,
                ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
            )),
        )),
        Ok(XfrEvent::EndOfTransfer(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_new_soa),
        )))),
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
    let mut processor = XfrResponseInterpreter::new();

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
    assert!(it.next().is_none());

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
    assert!(matches!(it.next(), Some(Ok(XE::EndOfTransfer(_)))));
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
