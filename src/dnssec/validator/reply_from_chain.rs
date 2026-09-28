//! Client transport that generates replies from a pre-loaded set of records.
//! This type is meant to be used to the validator so it may cut some corners.
//! It could be made fully general and moved to net::client if that is desired.
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::Name;
use crate::base::ParsedName;
use crate::base::Record;
use crate::base::StaticCompressor;
use crate::base::iana::Rcode;
use crate::base::opt::Chain;
use crate::dep::octseq::OctetsInto;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::Error;
use crate::net::client::request::GetResponse;
use crate::net::client::request::SendRequest;
use crate::rdata::AllRecordData;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use bytes::Bytes;
use core::future::Future;
use core::future::ready;
use core::pin::Pin;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct ReplyFromChain<Upstream> {
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
    chain: Arc<Mutex<Chain<Name<Bytes>>>>,
    upstream: Upstream,
}

impl<Upstream> ReplyFromChain<Upstream> {
    pub fn new(msg: &Message<Bytes>, upstream: Upstream) -> Self {
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
        let chain =
            Arc::new(Mutex::new(msg.opt().unwrap().opt().chain().unwrap()));
        let records = Arc::new(Mutex::new(records));
        Self {
            records,
            chain,
            upstream,
        }
    }
    pub fn empty(upstream: Upstream) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            chain: Arc::new(Mutex::new(Chain::empty())),
            upstream,
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
        let chain = msg.opt().unwrap().opt().chain().unwrap();
        *(self.chain.lock().unwrap()) = chain;
    }
}

impl<CR, Upstream> SendRequest<CR> for ReplyFromChain<Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR>,
{
    fn send_request(
        &self,
        msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync + 'static> {
        let inner_msg = msg.to_message().unwrap();
        let question = inner_msg.sole_question().unwrap();

        if self
            .chain
            .lock()
            .unwrap()
            .start()
            .is_none_or(|chain| !question.qname().ends_with(chain))
        {
            // Outside of this CHAIN reply, send upstream
            // TODO: This assumes we have received everything in a single
            // reply
            // We should probably make multiple CHAIN requests right away
            return self.upstream.send_request(msg);
        }

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
        if result.len() != 0 {
            let reply = create_reply(&inner_msg, result);
            return Box::new(ReplyResponse::new(reply));
        } else {
            return Box::new(ErrorResponse::new());
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

#[derive(Debug)]
struct ErrorResponse {}

impl ErrorResponse {
    fn new() -> Self {
        Self {}
    }
}

impl GetResponse for ErrorResponse {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    > {
        Box::pin(ready(Err(Error::ConnectionClosed)))
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
