//------------ Answer --------------------------------------------------------

use super::{SharedRr, SharedRrset, StoredDname};
use crate::base::iana::Rcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::Message;
use crate::base::MessageBuilder;
use octseq::Octets;

#[derive(Clone)]
pub struct Answer {
    /// The response code of the answer.
    rcode: Rcode,

    /// The content of the answer.
    content: AnswerContent,

    /// The optional authority section to be included in the answer.
    authority: Option<AnswerAuthority>,
}

impl Answer {
    pub fn new(rcode: Rcode) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Default::default(),
        }
    }

    pub fn with_authority(rcode: Rcode, authority: AnswerAuthority) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Some(authority),
        }
    }

    pub fn other(rcode: Rcode) -> Self {
        Answer::new(rcode)
    }

    pub fn refused() -> Self {
        Answer::new(Rcode::Refused)
    }

    pub fn add_cname(&mut self, cname: SharedRr) {
        self.content = AnswerContent::Cname(cname);
    }

    pub fn add_answer(&mut self, answer: SharedRrset) {
        self.content = AnswerContent::Data(answer);
    }

    pub fn add_authority(&mut self, authority: AnswerAuthority) {
        self.authority = Some(authority)
    }

    pub fn to_message<RequestOctets: Octets, Target: Composer>(
        &self,
        message: &Message<RequestOctets>,
        builder: MessageBuilder<Target>,
    ) -> AdditionalBuilder<Target> {
        let question = message.sole_question().unwrap();
        let qname = question.qname();
        let qclass = question.qclass();
        let mut builder = builder.start_answer(message, self.rcode).unwrap();

        match self.content {
            AnswerContent::Data(ref answer) => {
                for item in answer.data() {
                    // TODO: This will panic if too many answers were given,
                    // rather than give the caller a way to push the rest into
                    // another message.
                    builder
                        .push((qname, qclass, answer.ttl(), item))
                        .unwrap();
                }
            }
            AnswerContent::Cname(ref cname) => builder
                .push((qname, qclass, cname.ttl(), cname.data()))
                .unwrap(),
            AnswerContent::NoData => {}
        }

        let mut builder = builder.authority();
        if let Some(authority) = self.authority.as_ref() {
            if let Some(soa) = authority.soa.as_ref() {
                builder
                    .push((
                        authority.owner.clone(),
                        qclass,
                        soa.ttl(),
                        soa.data(),
                    ))
                    .unwrap();
            }
            if let Some(ns) = authority.ns.as_ref() {
                for item in ns.data() {
                    builder
                        .push((
                            authority.owner.clone(),
                            qclass,
                            ns.ttl(),
                            item,
                        ))
                        .unwrap()
                }
            }
            if let Some(ref ds) = authority.ds {
                for item in ds.data() {
                    builder
                        .push((
                            authority.owner.clone(),
                            qclass,
                            ds.ttl(),
                            item,
                        ))
                        .unwrap()
                }
            }
        }

        builder.additional()
    }

    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    pub fn content(&self) -> &AnswerContent {
        &self.content
    }

    pub fn authority(&self) -> Option<&AnswerAuthority> {
        self.authority.as_ref()
    }
}

//------------ AnswerContent -------------------------------------------------

/// The content of the answer.
#[derive(Clone)]
pub enum AnswerContent {
    Data(SharedRrset),
    Cname(SharedRr),
    NoData,
}

//------------ AnswerAuthority -----------------------------------------------

/// The authority section of a query answer.
#[derive(Clone)]
pub struct AnswerAuthority {
    /// The owner name of the record sets in the authority section.
    owner: StoredDname,

    /// The SOA record if it should be included.
    soa: Option<SharedRr>,

    /// The NS record set if it should be included.
    ns: Option<SharedRrset>,

    /// The DS record set if it should be included..
    ds: Option<SharedRrset>,
}

impl AnswerAuthority {
    pub fn new(
        owner: StoredDname,
        soa: Option<SharedRr>,
        ns: Option<SharedRrset>,
        ds: Option<SharedRrset>,
    ) -> Self {
        AnswerAuthority { owner, soa, ns, ds }
    }
}
