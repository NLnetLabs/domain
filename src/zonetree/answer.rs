//! Answers to zone tree queries.

use alloc::vec;
use alloc::vec::Vec;

use octseq::Octets;

use crate::base::MessageBuilder;
use crate::base::iana::Rcode;
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, Ttl};

use super::types::{StoredName, StoredRecord, StoredRecordData};
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

    /// The optional additional section to be included in the answer.
    additional: Option<AnswerAdditional>,

    /// The optional authority section to be included in the answer.
    authority: Option<AnswerAuthority>,

    /// Should the answer be flagged as authoritative?
    authoritative: bool,
}

impl Answer {
    /// Creates an "empty" answer.
    ///
    /// The answer, authority and additional sections will be empty and the
    /// response will NOT have the AA (Authoritative Answer) flag set.
    pub fn new(rcode: Rcode) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Default::default(),
            additional: Default::default(),
            authoritative: false,
        }
    }

    /// Creates a new message with a populated authority section.
    ///
    /// The answer section will be empty. The additional section will be
    /// populated with the additional records in the given
    /// [`AnswerAuthority`]. The response will NOT have the AA (Authoritative
    /// Answer) flag set.
    pub fn with_authority(rcode: Rcode, authority: AnswerAuthority) -> Self {
        Answer {
            rcode,
            content: AnswerContent::NoData,
            authority: Some(authority),
            additional: Default::default(),
            authoritative: false,
        }
    }

    /// Creates a new [Rcode::REFUSED] answer.
    ///
    /// This is equivalent to calling `Answer::new(Rcode::REFUSED)`.
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

    /// Sets the content of the additional section.
    pub fn set_additional(&mut self, additional: AnswerAdditional) {
        self.additional = Some(additional)
    }

    /// Sets the content of the authority section.
    pub fn set_authority(&mut self, authority: AnswerAuthority) {
        self.authority = Some(authority)
    }

    /// Marks the response authoritative or not.
    ///
    /// Determines whether or not the response will have the AA (Authoritative
    /// Answer) flag set.
    pub fn set_authoritative(&mut self, authoritative: bool) {
        self.authoritative = authoritative;
    }

    /// Generate a DNS response [`Message`] for this answer.
    ///
    /// The response [Rcode], question, answer and authority sections of the
    /// produced [`AdditionalBuilder`] will be populated based on the
    /// properties of this [`Answer`] as determined by the constructor and
    /// add/set functions called prior to calling this function.
    ///
    /// The method will return an error message if it couldn’t create a
    /// response that at least contained the question. It will
    ///
    /// See also: [`MessageBuilder::try_start_answer`]
    pub fn to_message<RequestOctets: Octets, Target: Composer>(
        &self,
        message: &Message<RequestOctets>,
        builder: MessageBuilder<Target>,
    ) -> AdditionalBuilder<Target> {
        let Ok(question) = message.sole_question() else {
            return builder
                .start_error(
                    message,
                    if message.header_counts().qdcount() != 1 {
                        Rcode::NOTIMP
                    } else {
                        Rcode::FORMERR
                    },
                )
                .additional();
        };
        let qname = question.qname();
        let qclass = question.qclass();
        let mut builder = match builder.try_start_answer(message, self.rcode)
        {
            Ok(builder) => builder,
            Err(builder) => return builder.additional(),
        };

        if self.authoritative {
            builder.header_mut().set_aa(true);
        }

        // If records don’t fit in the answer, we need to set the TC bit for
        // records in the answer and authority section. While we are allowed
        // to keep partial RRsets in this case, we don’t and instead roll
        // back to the beginning of the section, just to be safe.
        //
        // The same holds for required records in the additional section.
        //
        // For optional additional content, we are not allowed to set
        // the TC bit and instead have to include full RRsets. Since the
        // message builder doesn’t currently allow us to set check points to
        // roll back to, we simple clear the entire additional section in
        // this case. If there was required additional content, we then still
        // need to set the TC bit. Technically, we should rewind to the end
        // of the mandatory additional content and not set the TC bit, we
        // currently can’t do that with our message builder.

        match self.content {
            AnswerContent::Data(ref answer) => {
                for item in answer.data() {
                    if builder
                        .push((qname, qclass, answer.ttl(), item))
                        .is_err()
                    {
                        return builder.tc_rewind_into().additional();
                    }
                }
            }
            AnswerContent::Cname(ref cname) => {
                if builder
                    .push((qname, qclass, cname.ttl(), cname.data()))
                    .is_err()
                {
                    return builder.tc_rewind_into().additional();
                }
            }
            AnswerContent::NoData => {}
        }

        let mut builder = builder.authority();
        if let Some(authority) = self.authority.as_ref() {
            if let Some(soa) = authority.soa.as_ref() {
                if builder
                    .push((
                        authority.owner.clone(),
                        qclass,
                        soa.ttl(),
                        soa.data(),
                    ))
                    .is_err()
                {
                    return builder.tc_rewind_into().additional();
                }
            }
            if let Some(ns) = authority.ns.as_ref() {
                for item in ns.data() {
                    if builder
                        .push((
                            authority.owner.clone(),
                            qclass,
                            ns.ttl(),
                            item,
                        ))
                        .is_err()
                    {
                        return builder.tc_rewind_into().additional();
                    }
                }
            }
            if let Some(ref ds) = authority.ds {
                for item in ds.data() {
                    if builder
                        .push((
                            authority.owner.clone(),
                            qclass,
                            ds.ttl(),
                            item,
                        ))
                        .is_err()
                    {
                        return builder.tc_rewind_into().additional();
                    }
                }
            }
        }

        let mut builder = builder.additional();

        if let Some(additional) = self.additional.as_ref() {
            for item in &additional.required {
                if builder.push(item).is_err() {
                    return builder.tc_rewind_into();
                }
            }

            for item in &additional.discardable {
                if builder.push(item).is_err() {
                    if !additional.required.is_empty() {
                        return builder.tc_rewind_into();
                    } else {
                        return builder.rewind_into();
                    }
                }
            }
        }

        builder
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
    /// ```should_panic
    /// # use domain::base::iana::Rcode;
    /// # use domain::rdata::ZoneRecordData;
    /// # use domain::zonetree::Answer;
    /// # let some_answer = Answer::new(Rcode::NOERROR);
    /// let Some((soa_ttl, ZoneRecordData::Soa(soa))) =
    ///     some_answer.content().first()
    /// else {
    ///     panic!("some_answer is not a variant of AnswerContent that has data");
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

//------------ AnswerAdditional ----------------------------------------------

// The additional section of a query answer.
#[derive(Clone, Default)]
pub struct AnswerAdditional {
    /// Any required additional address records to include.
    ///
    /// If not all additional records will fit in the answer, these should be
    /// kept.
    required: Vec<StoredRecord>,

    /// Any discardable additional address records to include.
    ///
    /// If not all additional records will fit in the answer, these can be
    /// discarded.
    discardable: Vec<StoredRecord>,
}

impl AnswerAdditional {
    /// Creates a new representation of an additional section.
    pub fn new(required: Vec<StoredRecord>) -> Self {
        Self {
            required,
            discardable: vec![],
        }
    }

    /// Add discardable records to the additional section.
    ///
    /// If not all additional records will fit in the answer, the required
    /// records should be kept and the discardable records can be discarded.
    pub fn push_discardable(&mut self, discardable: Vec<StoredRecord>) {
        self.discardable = discardable;
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

    /// The DS record set if it should be included.
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
