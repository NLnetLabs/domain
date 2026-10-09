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

/// Any record returned in a CHAIN reply.
type AnyRecord =
    Record<ParsedName<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;

/// A container for CHAIN [RFC 7901] reply.
///
/// Used to provide DNSSEC records directly from a CHAIN response,
/// avoiding upstream requests when possible.
///
/// [RFC 7901]: https://tools.ietf.org/html/rfc7901
#[derive(Debug, Clone)]
pub struct ReplyFromChain<Upstream> {
    /// List of all records from CHAIN reply.
    ///
    /// This contains both answer and authority sections records.
    records: Arc<Mutex<Vec<AnyRecord>>>,
    /// The CHAIN EDNS0 option value from the reply.
    chain: Arc<Mutex<Chain<Name<Bytes>>>>,
    /// The upstream [`SendRequest`] to use for records outside of this chain.
    upstream: Upstream,
}

impl<Upstream> ReplyFromChain<Upstream> {
    /// Creates a new value from the provided reply and upstream.
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

    /// Creates an empty value with the provided upstream.
    ///
    /// [`ReplyFromChain::add_from_message`] can be used to add reply data.
    pub fn empty(upstream: Upstream) -> Self {
        Self {
            records: Arc::new(Mutex::new(Vec::new())),
            chain: Arc::new(Mutex::new(Chain::empty())),
            upstream,
        }
    }
}

impl<Upstream> ReplyFromChain<Upstream> {
    /// Adds records from the provided message.
    pub fn add_from_message(&self, msg: &Message<Bytes>) {
        let mut records = self.records.lock().unwrap();
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
        *(self.chain.lock().unwrap()) = chain.clone();
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
        if !result.is_empty() {
            let reply = create_reply(&inner_msg, result);
            Box::new(ReplyResponse::new(reply))
        } else {
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
                // TODO: depending on interpretation of CHAIN in reply, this
                // might be wrong - e.g. for example.com. with request
                // CHAIN=com. this is right now expected to return com., but
                // it might also make sense to return example.com. in which
                // case this check is wrong.
                self.upstream.send_request(msg)
            } else {
                let reply = create_reply(&inner_msg, result);
                Box::new(ReplyResponse::new(reply))
            }
        }
    }
}

/// A static [`GetResponse`] implementation, returning pre-defined response.
/// TODO: Does this make sense as a general struct when response can be
/// pre-defined?
#[derive(Debug)]
struct ReplyResponse {
    /// The pre-defined response to use
    response: Message<Bytes>,
}

impl ReplyResponse {
    /// Creates a new value with provided pre-defined response.
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

/// Creates a reply by adding all provided records into answer section.
fn create_reply(
    msg: &Message<Vec<u8>>,
    result: Vec<&AnyRecord>,
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
    Message::<Bytes>::from_octets(result.finish().into_target().octets_into())
        .expect("Message should be able to parse output from MessageBuilder")
}

//============ Tests ==========================================================

#[cfg(test)]
mod tests {
    use core::{cmp::Ordering, str::FromStr, sync::atomic::AtomicUsize};

    use crate::{
        base::{
            Question, Rtype, ToName, Ttl,
            iana::{Class, SecurityAlgorithm},
            message_builder::AdditionalBuilder,
        },
        net::client::request::RequestMessage,
        rdata::{Dnskey, Rrsig},
        utils::base64,
    };

    use super::*;

    #[derive(Debug)]
    struct ErrorResponse;

    impl GetResponse for ErrorResponse {
        fn get_response(
            &mut self,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Message<Bytes>, Error>>
                    + Send
                    + Sync,
            >,
        > {
            Box::pin(ready(Err(Error::ConnectionClosed)))
        }
    }

    #[derive(Clone, Default)]
    struct UpstreamSendRequest {
        calls: Arc<AtomicUsize>,
    }

    impl UpstreamSendRequest {
        fn get_call_count(&self) -> usize {
            self.calls.load(core::sync::atomic::Ordering::Relaxed)
        }
    }

    impl<CR> SendRequest<CR> for UpstreamSendRequest
    where
        CR: ComposeRequest,
    {
        fn send_request(
            &self,
            _request_msg: CR,
        ) -> Box<dyn GetResponse + Send + Sync> {
            self.calls
                .fetch_add(1, core::sync::atomic::Ordering::Release);
            Box::new(ErrorResponse)
        }
    }

    fn build_dnskey_rr<Octs>() -> Dnskey<Octs>
    where
        Octs: octseq::FromBuilder,
        <Octs as octseq::FromBuilder>::Builder: octseq::EmptyBuilder,
    {
        Dnskey::new(
            257,
            3,
            SecurityAlgorithm::ED25519,
            base64::decode::<Octs>("dGVzdA==").unwrap(),
        )
        .unwrap()
    }

    fn build_dnskey_rrsig<Octs, N>(owner: N) -> Rrsig<Octs, N>
    where
        Octs: octseq::FromBuilder,
        <Octs as octseq::FromBuilder>::Builder: octseq::EmptyBuilder,
        N: ToName,
    {
        Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::ECDSAP256SHA256,
            2,
            Ttl::from_secs(3600),
            1560314494.into(),
            1555130494.into(),
            2371,
            owner,
            base64::decode::<Octs>("dGVzdA==").unwrap(),
        )
        .unwrap()
    }

    fn build_reply_for_chain(
        builder: impl Fn(
            MessageBuilder<StaticCompressor<Vec<u8>>>,
        ) -> AdditionalBuilder<StaticCompressor<Vec<u8>>>,
    ) -> Message<Bytes> {
        let target =
            MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
                .expect("Vec is expected to have enough space");

        let target = builder(target);

        Message::<Bytes>::from_octets(
            target.finish().into_target().octets_into(),
        )
        .expect("Message should be able to parse output from MessageBuilder")
    }

    fn build_request<N: ToName>(
        question: Question<N>,
    ) -> RequestMessage<Vec<u8>> {
        let mut req_msg = MessageBuilder::new_vec();
        req_msg.header_mut().set_rd(true);
        let mut req_msg = req_msg.question();
        req_msg.push(question).unwrap();
        let req_msg = req_msg.additional();
        let mut req = RequestMessage::new(req_msg).unwrap();
        req.set_dnssec_ok(true);
        req
    }

    /// Checks that a single record can be retrieved from `ReplyFromChain`.
    #[tokio::test]
    async fn test_get_record_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new_in(
            Name::<Bytes>::from_str("example.com.").unwrap(),
            Rtype::DNSKEY,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        let result = resp.get_response().await.unwrap();

        assert_eq!(upstream.get_call_count(), 0);
        assert_eq!(result.header_counts().ancount(), 1);
        let first_answer = result
            .answer()
            .expect("answer should be present")
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(first_answer.owner().name_cmp(&name), Ordering::Equal);
        assert_eq!(first_answer.rtype(), Rtype::DNSKEY);
        assert_eq!(
            *first_answer
                .to_record::<Dnskey<Bytes>>()
                .unwrap()
                .unwrap()
                .data(),
            build_dnskey_rr::<Bytes>()
        );
    }

    /// Checks that a single record + RRSIG can be retrieved from
    /// `ReplyFromChain`, when RRSIG is available.
    #[tokio::test]
    async fn test_get_record_with_rrsig_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            answer
                .push((
                    name.clone(),
                    123,
                    build_dnskey_rrsig::<Vec<u8>, Name<Bytes>>(name.clone()),
                ))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new_in(
            Name::<Bytes>::from_str("example.com.").unwrap(),
            Rtype::DNSKEY,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        let result = resp.get_response().await.unwrap();

        assert_eq!(upstream.get_call_count(), 0);
        assert_eq!(result.header_counts().ancount(), 2);
        let mut answers = result.answer().expect("answer should be present");
        let first_answer = answers.next().unwrap().unwrap();
        assert_eq!(first_answer.owner().name_cmp(&name), Ordering::Equal);
        assert_eq!(first_answer.rtype(), Rtype::DNSKEY);
        assert_eq!(
            *first_answer
                .to_record::<Dnskey<Bytes>>()
                .unwrap()
                .unwrap()
                .data(),
            build_dnskey_rr::<Bytes>()
        );
        let second_answer = answers.next().unwrap().unwrap();
        assert_eq!(second_answer.owner().name_cmp(&name), Ordering::Equal);
        assert_eq!(second_answer.rtype(), Rtype::RRSIG);
        assert_eq!(
            *second_answer
                .to_record::<Rrsig<Bytes, ParsedName<Bytes>>>()
                .unwrap()
                .unwrap()
                .data(),
            build_dnskey_rrsig::<Bytes, ParsedName<Bytes>>(name.into())
        );
    }

    /// Checks that empty answer is returned for QTYPEs not stored from the response.
    #[tokio::test]
    async fn test_get_wrong_record_type_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new_in(
            Name::<Bytes>::from_str("example.com.").unwrap(),
            Rtype::TXT,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        let result = resp.get_response().await.unwrap();

        assert_eq!(upstream.get_call_count(), 0);
        assert_eq!(result.header_counts().ancount(), 0);
    }

    /// Checks that empty answer is returned for QCLASS not stored from the response.
    #[tokio::test]
    async fn test_get_wrong_class_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new(
            Name::<Bytes>::from_str("example.com.").unwrap(),
            Rtype::TXT,
            Class::CH,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        let result = resp.get_response().await.unwrap();

        assert_eq!(upstream.get_call_count(), 0);
        assert_eq!(result.header_counts().ancount(), 0);
    }

    /// Checks that upstream is used for names not stored from the response.
    #[tokio::test]
    async fn test_get_wrong_name_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new_in(
            Name::<Bytes>::from_str("quad9.net.").unwrap(),
            Rtype::DNSKEY,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        resp.get_response().await.expect_err("Request should fail");

        assert_eq!(upstream.get_call_count(), 1);
    }

    /// Checks that upstream is used for names not included in the chain.
    #[tokio::test]
    async fn test_get_out_of_chain_record_from_reply() {
        let name = Name::<Bytes>::from_str("example.com.").unwrap();
        let reply = build_reply_for_chain(|builder| {
            let mut answer = builder.answer();
            answer
                .push((name.clone(), 123, build_dnskey_rr::<Vec<u8>>()))
                .unwrap();
            let mut add = answer.additional();
            add.opt(|opt| opt.chain(name.clone())).unwrap();
            add
        });
        let upstream = UpstreamSendRequest::default();
        let reply_from_chain = ReplyFromChain::new(&reply, upstream.clone());

        let question = Question::new_in(
            Name::<Bytes>::from_str("com.").unwrap(),
            Rtype::DNSKEY,
        );

        let mut resp = reply_from_chain.send_request(build_request(question));
        resp.get_response().await.expect_err(
            "Request should fail, because upstream is 
            configured to always fail",
        );

        assert_eq!(upstream.get_call_count(), 1);
    }
}
