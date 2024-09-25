//! Answers to zone tree queries.

use octseq::Octets;

use crate::base::iana::Rcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::MessageBuilder;
use crate::base::{Message, Ttl};

use super::types::{StoredName, StoredRecordData};
use super::{SharedRr, SharedRrset};

//------------ Answer --------------------------------------------------------

/// A DNS answer to a query against a [`Zone`].
///
/// [`Answer`] is the type returned by [`ReadableZone::query`].
///
/// Callers of [`ReadableZone::query`] will likely only ever need to use the
/// [`Self::to_message`] function. Alternatively, for complete control use the
/// getter functions on [`Answer`] instead and construct a response message
/// yourself using [`MessageBuilder`].
///
/// Implementers of alternate backing stores for [`Zone`]s will need to use
/// one of the various `Answer` constructor functions when
/// [`ReadableZone::query`] is invoked for your zone content in order to
/// tailor the DNS message produced by [`Self::to_message`] based on the
/// outcome of the query.
///
/// [`Zone`]: crate::zonetree::Zone
/// [`ReadableZone::query`]: crate::zonetree::traits::ReadableZone::query
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
    /// Creates an "empty" answer.
    ///
    /// The answer, authority and additinal sections will be empty.
    pub fn new(rcode: Rcode) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Default::default(),
        }
    }

    /// Creates a new message with a populated authority section.
    ///
    /// The answer and additional sections will be empty.
    pub fn with_authority(rcode: Rcode, authority: AnswerAuthority) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Some(authority),
        }
    }

    /// Creates a new [Rcode::REFUSED] answer.
    ///
    /// This is equivalent to calling [`Answer::new(Rcode::Refused)`].
    pub fn refused() -> Self {
        Answer::new(Rcode::REFUSED)
    }

    /// Adds a CNAME to the answer section.
    pub fn add_cname(&mut self, cname: SharedRr) {
        self.content = AnswerContent::Cname(cname);
    }

    /// Adds an RRset to the answer section.
    pub fn add_answer(&mut self, answer: SharedRrset) {
        self.content = AnswerContent::Data(answer);
    }

    /// Sets the content of the authority section.
    pub fn set_authority(&mut self, authority: AnswerAuthority) {
        self.authority = Some(authority)
    }

    /// Generate a DNS response [`Message`] for this answer.
    ///
    /// The response [Rcode], question, answer and authority sections of the
    /// produced [`AdditionalBuilder`] will be populated based on the
    /// properties of this [`Answer`] as determined by the constructor and
    /// add/set functions called prior to calling this function.
    ///
    /// <div class="warning">
    ///
    /// This function does **NOT** currently set the
    /// [AA](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1)
    /// flag on the produced message.
    ///
    /// </div>
    ///
    /// See also: [`MessageBuilder::start_answer`]
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

    /// Gets the [`Rcode`] for this answer.
    pub fn rcode(&self) -> Rcode {
        self.rcode
    }

    /// Gets the answer section content for this answer.
    pub fn content(&self) -> &AnswerContent {
        &self.content
    }

    /// Gets the authority section content for this answer.
    pub fn authority(&self) -> Option<&AnswerAuthority> {
        self.authority.as_ref()
    }
}

//------------ AnswerContent -------------------------------------------------

/// The content of the answer.
#[derive(Clone)]
pub enum AnswerContent {
    /// An answer consisting of an RRSET.
    Data(SharedRrset),

    /// An answer consisting of a CNAME RR.
    Cname(SharedRr),

    /// An empty answer.
    NoData,
}

impl AnswerContent {
    /// Gets the first record TTL and data, if any.
    ///
    /// This can be used to get both the data as a specific variant, and the
    /// associated TTL, in a single step:
    ///
    /// ```
    /// # let answer = Answer::new(Rcode::NOERROR);
    /// let Some((soa_ttl, ZoneRecordData::Soa(soa))) =
    ///     some_answer.content().first()
    /// else {
    ///     // ...
    /// };
    /// ```
    pub fn first(&self) -> Option<(Ttl, StoredRecordData)> {
        match self {
            AnswerContent::Data(shared_rrset) => shared_rrset
                .data()
                .first()
                .map(|data| (shared_rrset.ttl(), data.clone())),
            AnswerContent::Cname(shared_rr) => {
                Some((shared_rr.ttl(), shared_rr.data().clone()))
            }
            AnswerContent::NoData => None,
        }
    }
}

//------------ AnswerAuthority -----------------------------------------------

/// The authority section of a query answer.
#[derive(Clone)]
pub struct AnswerAuthority {
    /// The owner name of the record sets in the authority section.
    owner: StoredName,

    /// The SOA record if it should be included.
    soa: Option<SharedRr>,

    /// The NS record set if it should be included.
    ns: Option<SharedRrset>,

    /// The DS record set if it should be included..
    ds: Option<SharedRrset>,
}

impl AnswerAuthority {
    /// Creates a new representation of an authority section.
    pub fn new(
        owner: StoredName,
        soa: Option<SharedRr>,
        ns: Option<SharedRrset>,
        ds: Option<SharedRrset>,
    ) -> Self {
        AnswerAuthority { owner, soa, ns, ds }
    }
}
