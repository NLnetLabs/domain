use core::str::FromStr;

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use octseq::{Octets, Parser};

use crate::base::iana::Rcode;
use crate::base::message_builder::{
    AnswerBuilder, AuthorityBuilder, QuestionBuilder,
};
use crate::base::net::{Ipv4Addr, Ipv6Addr};
use crate::base::rdata::ComposeRecordData;
use crate::base::{
    Message, MessageBuilder, ParsedName, Record, Rtype, Serial, Ttl,
};
use crate::base::{Name, ToName};
use crate::rdata::{Aaaa, Soa, ZoneRecordData, A};
use crate::zonetree::types::{ZoneUpdate, ZoneUpdate as ZU};

use super::interpreter::XfrResponseInterpreter;
use super::types::{Error, IterationError, ParsedRecord};

#[test]
fn non_xfr_response_is_rejected() {
    init_logging();

    // Create an AXFR-like request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Create a non-XFR response.
    let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    let resp = answer.into_message();

    // Process the response and assert that it is rejected as not being
    // a valid XFR response and that no XFR interpreter updates were emitted.
    assert!(matches!(
        interpreter.interpret_response(resp),
        Err(Error::NotValidXfrResponse)
    ));
}

#[test]
fn axfr_response_with_no_answers_is_rejected() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Create a response that lacks answers.
    let resp = mk_empty_answer(&req, Rcode::NOERROR).into_message();

    // Process the response and assert that it is rejected as not being
    // a valid XFR response and that no XFR interpreter updates were emitted.
    assert!(matches!(
        interpreter.interpret_response(resp),
        Err(Error::NotValidXfrResponse)
    ));
}

#[test]
fn error_axfr_response_is_rejected() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Create a minimal valid AXFR response, just something that should
    // not be rejected by the XFR interpreter due to its content. It should
    // however be rejected due to the non-NOERROR rcode.
    let mut answer = mk_empty_answer(&req, Rcode::SERVFAIL);
    add_answer_record(&req, &mut answer, mk_soa(Serial::now()));
    let resp = answer.into_message();

    // Process the response and assert that it is rejected as not being
    // a valid XFR response and that no XFR interpreter updates were emitted.
    assert!(matches!(
        interpreter.interpret_response(resp),
        Err(Error::NotValidXfrResponse)
    ));
}

#[test]
fn incomplete_axfr_response_is_accepted() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Create an incomplete AXFR response. A proper AXFR response has at
    // least two identical SOA records, one at the start and one at the
    // end, but this response contains only a single SOA record. This is
    // not considered invalid however because a subsequent response could
    // still provide the missing SOA record.
    let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
    add_answer_record(&req, &mut answer, mk_soa(Serial::now()));
    let resp = answer.into_message();

    // Process the response.
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify that no updates are output by the XFR interpreter.
    assert_eq!(it.next(), Some(Ok(ZoneUpdate::DeleteAllRecords)));
    assert!(it.next().is_none());
}

#[test]
fn axfr_response_with_only_soas_is_accepted() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

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
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert_eq!(it.next(), Some(Ok(ZoneUpdate::DeleteAllRecords)));
    assert!(matches!(it.next(), Some(Ok(ZU::Finished(_)))));
    assert!(it.next().is_none());
}

#[test]
fn axfr_multi_response_with_only_soas_is_accepted() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

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
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert_eq!(it.next(), Some(Ok(ZoneUpdate::DeleteAllRecords)));
    assert!(it.next().is_none());

    // Create another AXFR response to complete the transfer.
    let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
    add_answer_record(&req, &mut answer, soa);
    let resp = answer.into_message();

    // Process the response.
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert!(matches!(it.next(), Some(Ok(ZU::Finished(_)))));
    assert!(it.next().is_none());
}

#[test]
fn axfr_response_generates_expected_updates() {
    init_logging();

    // Create an AXFR request to reply to.
    let req = mk_request("example.com", Rtype::AXFR).into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Create an AXFR response.
    let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
    let serial = Serial::now();
    let soa = mk_soa(serial);
    add_answer_record(&req, &mut answer, soa.clone());
    add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    add_answer_record(&req, &mut answer, Aaaa::new(Ipv6Addr::LOCALHOST));
    add_answer_record(&req, &mut answer, soa);
    let resp = answer.into_message();

    // Process the response.
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert_eq!(it.next(), Some(Ok(ZoneUpdate::DeleteAllRecords)));
    assert!(
        matches!(it.next(), Some(Ok(ZoneUpdate::AddRecord(r))) if r.rtype() == Rtype::A)
    );
    assert!(
        matches!(it.next(), Some(Ok(ZoneUpdate::AddRecord(r))) if r.rtype() == Rtype::AAAA)
    );
    assert!(matches!(it.next(), Some(Ok(ZoneUpdate::Finished(_)))));
    assert!(it.next().is_none());
}

#[test]
fn ixfr_response_generates_expected_updates() {
    init_logging();

    // Create an IXFR request to reply to.
    let req = mk_request("example.com", Rtype::IXFR);
    let mut authority = req.authority();
    let client_serial = Serial::now();
    let soa = mk_soa(client_serial);
    add_authority_record(&mut authority, soa);
    let req = authority.into_message();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

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
    let it = interpreter.interpret_response(resp).unwrap();

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

    // Verify the updates emitted by the XFR interpreter.
    let owner =
        ParsedName::<Bytes>::from(Name::from_str("example.com").unwrap());
    let expected_updates: [Result<ZoneUpdate<ParsedRecord>, IterationError>;
        7] = [
        Ok(ZoneUpdate::BeginBatchDelete(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_old_soa),
        )))),
        Ok(ZoneUpdate::DeleteRecord(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
        )))),
        Ok(ZoneUpdate::DeleteRecord(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::A(A::new(Ipv4Addr::BROADCAST)),
        )))),
        Ok(ZoneUpdate::BeginBatchAdd(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_new_soa.clone()),
        )))),
        Ok(ZoneUpdate::AddRecord(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::A(A::new(Ipv4Addr::BROADCAST)),
        )))),
        Ok(ZoneUpdate::AddRecord(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
        )))),
        Ok(ZoneUpdate::Finished(Record::from((
            owner.clone(),
            0,
            ZoneRecordData::Soa(expected_new_soa),
        )))),
    ];

    assert!(it.eq(expected_updates));
}

#[test]
fn multi_ixfr_response_generates_expected_updates() {
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
    let resp = mk_first_ixfr_response(&req, &new_soa, old_soa);

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Process the response.
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert!(matches!(it.next(), Some(Ok(ZU::BeginBatchDelete(_)))));
    assert!(matches!(it.next(), Some(Ok(ZU::DeleteRecord(..)))));
    assert!(it.next().is_none());

    // Craete a second IXFR response that completes the transfer
    let resp = mk_second_ixfr_response(req, new_soa);

    // Process the response.
    let mut it = interpreter.interpret_response(resp).unwrap();

    // Verify the updates emitted by the XFR interpreter.
    assert!(matches!(it.next(), Some(Ok(ZU::DeleteRecord(..)))));
    assert!(matches!(it.next(), Some(Ok(ZU::BeginBatchAdd(_)))));
    assert!(matches!(it.next(), Some(Ok(ZU::AddRecord(..)))));
    assert!(matches!(it.next(), Some(Ok(ZU::AddRecord(..)))));
    assert!(matches!(it.next(), Some(Ok(ZU::Finished(_)))));
    assert!(it.next().is_none());
}

#[test]
fn is_finished() {
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
    let mut responses: VecDeque<_> = vec![
        mk_first_ixfr_response(&req, &new_soa, old_soa),
        mk_second_ixfr_response(req, new_soa),
    ]
    .into();

    // Create an XFR response interpreter.
    let mut interpreter = XfrResponseInterpreter::new();

    // Process the responses
    let mut count = 0;
    while !interpreter.is_finished() {
        let resp = responses.pop_front().unwrap();
        let it = interpreter.interpret_response(resp).unwrap();
        count += it.count();
    }

    assert!(interpreter.is_finished());
    assert!(responses.is_empty());
    assert_eq!(count, 7);
}

fn mk_first_ixfr_response(
    req: &Message<Bytes>,
    new_soa: &Soa<Name<Bytes>>,
    old_soa: Soa<Name<Bytes>>,
) -> Message<Bytes> {
    let mut answer = mk_empty_answer(req, Rcode::NOERROR);
    // Outer SOA with servers current SOA
    add_answer_record(req, &mut answer, new_soa.clone());
    // Start of diff sequence: SOA of the servers' previous zone version
    // (which matches that of the client) followed by records to be
    // deleted as they were in that version of the zone but are not in the
    // new version of the zone.
    add_answer_record(req, &mut answer, old_soa);
    add_answer_record(req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
    answer.into_message()
}

fn mk_second_ixfr_response(
    req: Message<Bytes>,
    new_soa: Soa<Name<Bytes>>,
) -> Message<Bytes> {
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
    answer.into_message()
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
