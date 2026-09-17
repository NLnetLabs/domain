// Client transport that generates replies from a pre-loaded set of records.
// This tpye is meant to be used to the validator so it may cut some corners.
// It could be made fully general and moved to net::client if that is desired.

use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::ParsedName;
use crate::base::Record;
use crate::base::StaticCompressor;
use crate::base::iana::Rcode;
use crate::dep::octseq::OctetsInto;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::Error;
use crate::net::client::request::GetResponse;
use crate::net::client::request::SendRequest;
use crate::rdata::AllRecordData;
use bytes::Bytes;
use std::boxed::Box;
use std::future::Future;
use std::future::ready;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::vec::Vec;

#[derive(Clone)]
pub struct ReplyFromChain {
    records: Arc<
        Mutex<
            Vec<
                Record<
                    ParsedName<Bytes>,
                    AllRecordData<Bytes, ParsedName<Bytes>>,
                >,
            >,
        >,
    >,
}

impl ReplyFromChain {
    pub fn new(msg: &Message<Bytes>) -> Self {
        let mut records = Vec::new();
        for rr in msg.answer().unwrap() {
            let rr = rr.unwrap();
            let rr = rr.into_record().unwrap().unwrap();
            records.push(rr);
        }
        for rr in msg.authority().unwrap() {
            let rr = rr.unwrap();
            let rr = rr.into_record().unwrap().unwrap();
            records.push(rr);
        }
        let records = Arc::new(Mutex::new(records));
        Self { records }
    }
    pub fn empty() -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
        }
    }
    pub fn set_from_message(&self, msg: &Message<Bytes>) {
        let mut records = self.records.lock().unwrap();
        (*records).truncate(0);
        for rr in msg.answer().unwrap() {
            let rr = rr.unwrap();
            let rr = rr.into_record().unwrap().unwrap();
            (*records).push(rr);
        }
        for rr in msg.authority().unwrap() {
            let rr = rr.unwrap();
            let rr = rr.into_record().unwrap().unwrap();
            (*records).push(rr);
        }
    }
}

impl<CR> SendRequest<CR> for ReplyFromChain
where
    CR: ComposeRequest,
{
    fn send_request(
        &self,
        msg: CR,
    ) -> Box<(dyn GetResponse + std::marker::Send + Sync + 'static)> {
        let msg = msg.to_message().unwrap();
        let question = msg.sole_question().unwrap();
        println!("Looking for {question:?}");
        let mut result = Vec::new();
        let records = self.records.lock().unwrap();
        for e in &*records {
            if e.owner() == question.qname()
                && e.class() == question.qclass()
                && e.rtype() == question.qtype()
            {
                result.push(e);
            }
            if let AllRecordData::Rrsig(rrsig) = e.data() {
                if e.owner() == question.qname()
                    && e.class() == question.qclass()
                    && rrsig.type_covered() == question.qtype()
                {
                    result.push(e);
                }
            }
        }
        println!("Found results: {result:?}");
        if result.len() != 0 {
            let reply = create_reply(&msg, result);
            return Box::new(ReplyResponse::new(reply));
        }
        todo!()
    }
}

#[derive(Debug)]
struct ReplyResponse {
    response: Message<Bytes>,
}

impl ReplyResponse {
    fn new(response: Message<Bytes>) -> Self {
        Self { response }
    }
}

impl GetResponse for ReplyResponse {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    > {
        Box::pin(ready(Ok(self.response.clone())))
    }
}

fn create_reply(
    msg: &Message<Vec<u8>>,
    result: Vec<
        &Record<ParsedName<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>,
    >,
) -> Message<Bytes> {
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = msg.header();
    target.header_mut().set_rcode(Rcode::NOERROR);

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        target.push(rr.unwrap()).expect("should not fail");
    }
    let mut target = target.answer();
    for rr in result {
        target.push(rr).unwrap();
    }

    let result = target.as_builder().clone();
    let msg = Message::<Bytes>::from_octets(
        result.finish().into_target().octets_into(),
    )
    .expect("Message should be able to parse output from MessageBuilder");
    msg
}
