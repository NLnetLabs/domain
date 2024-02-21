//! Quering for zone data.

use std::sync::Arc;
use crate::base::iana::{Rcode, Rtype};
use crate::base::message::Message;
use crate::base::message_builder::{AdditionalBuilder, MessageBuilder};
use crate::base::name::{Label, ToDname};
use crate::base::wire::Composer;
use crate::dep::octseq::Octets;
use super::flavor::Flavor;
use super::nodes::{
    NodeChildren, NodeRrsets, OutOfZone, Special, ZoneApex, ZoneCut, ZoneNode,
};
use super::rrset::{SharedRr, SharedRrset, StoredDname};
use super::versioned::Version;
use super::zone::VersionMarker;


//------------ ReadZone ------------------------------------------------------

pub struct ReadZone {
    apex: Arc<ZoneApex>,
    flavor: Option<Flavor>,
    version: Version,
    _version_marker: Arc<VersionMarker>,
}

impl ReadZone {
    pub(super) fn new(
        apex: Arc<ZoneApex>,
        flavor: Option<Flavor>,
        version: Version,
        _version_marker: Arc<VersionMarker>,
    ) -> Self {
        ReadZone { apex, flavor, version, _version_marker }
    }

    pub fn query(
        &self, qname: &impl ToDname, qtype: Rtype
    ) -> Result<Answer, OutOfZone> {
        let mut qname = self.apex.prepare_name(qname)?;

        let answer = if let Some(label) = qname.next() {
            self.query_below_apex(label, qname, qtype)
        }
        else {
            self.query_rrsets(self.apex.rrsets(), qtype)
        };

        Ok(answer.into_answer(self))
    }

    fn query_below_apex<'l>(
        &self,
        label: &Label, qname: impl Iterator<Item=&'l Label>, qtype: Rtype,
    ) -> NodeAnswer {
        self.query_children(self.apex.children(), label, qname, qtype)
    }

    fn query_node<'l>(
        &self,
        node: &ZoneNode,
        mut qname: impl Iterator<Item=&'l Label>,
        qtype: Rtype,
    ) -> NodeAnswer {
        if let Some(label) = qname.next() {
            self.query_node_below(node, label, qname, qtype)
        }
        else {
            self.query_node_here(node, qtype)
        }
    }

    fn query_node_below<'l>(
        &self,
        node: &ZoneNode,
        label: &Label,
        qname: impl Iterator<Item=&'l Label>,
        qtype: Rtype,
    ) -> NodeAnswer {
        node.with_special(self.flavor, self.version, |special| {
            match special {
                Some(Special::Cut(ref cut)) => {
                    NodeAnswer::authority(
                        AnswerAuthority::new(
                            cut.name.clone(),
                            None,
                            Some(cut.ns.clone()),
                            cut.ds.as_ref().cloned()
                        )
                    )
                }
                Some(Special::NxDomain) => {
                    NodeAnswer::nx_domain()
                }
                Some(Special::Cname(_)) | None => {
                    self.query_children(node.children(), label, qname, qtype)
                }
            }
        })
    }

    fn query_node_here(
        &self,
        node: &ZoneNode,
        qtype: Rtype,
    ) -> NodeAnswer {
        node.with_special(self.flavor, self.version, |special| {
            match special {
                Some(Special::Cut(cut)) => self.query_at_cut(cut, qtype),
                Some(Special::Cname(cname)) => {
                    NodeAnswer::cname(cname.clone())
                }
                Some(Special::NxDomain) => NodeAnswer::nx_domain(),
                None => self.query_rrsets(node.rrsets(), qtype),
            }
        })
    }

    fn query_rrsets(
        &self,  rrsets: &NodeRrsets, qtype: Rtype,
    ) -> NodeAnswer {
        match rrsets.get(qtype, self.flavor, self.version) {
            Some(rrset) => NodeAnswer::data(rrset),
            None => NodeAnswer::no_data(),
        }
    }

    fn query_at_cut(
        &self, cut: &ZoneCut, qtype: Rtype
    ) -> NodeAnswer {
        match qtype {
            Rtype::Ds => {
                if let Some(rrset) = cut.ds.as_ref() {
                    NodeAnswer::data(rrset.clone())
                }
                else {
                    NodeAnswer::no_data()
                }
            }
            _ => {
                NodeAnswer::authority(
                    AnswerAuthority::new(
                        cut.name.clone(),
                        None,
                        Some(cut.ns.clone()),
                        cut.ds.as_ref().cloned()
                    )
                )
            }
        }
    }

    fn query_children<'l>(
        &self,
        children: &NodeChildren,
        label: &Label,
        qname: impl Iterator<Item=&'l Label>,
        qtype: Rtype,
    ) -> NodeAnswer {
        // Step 1: See if we have a non-terminal child for label. If so,
        //         continue there. Because of flavors, the child may exist
        //         but maked as NXDomain in which case it doesn’t really
        //         exist.
        let answer = children.with(label, |node| {
            if let Some(node) = node {
                if node.is_nx_domain(self.flavor, self.version) {
                    None
                }
                else {
                    Some(self.query_node(node, qname, qtype))
                }
            }
            else {
                None
            }
        });
        if let Some(answer) = answer {
            return answer
        }

        // Step 2: Now see if we have an asterisk label. If so, query that
        // node.
        children.with(Label::wildcard(), |node| {
            match node {
                Some(node) => self.query_node_here(node, qtype),
                None => NodeAnswer::nx_domain()
            }
        })
    }
}


//------------ NodeAnswer ----------------------------------------------------

/// An answer that includes instructions to the apex on what it needs to do.
#[derive(Clone)]
struct NodeAnswer {
    /// The actual answer.
    answer: Answer,

    /// Does the apex need to add the SOA RRset to the answer?
    add_soa: bool,
}

impl NodeAnswer {
    fn data(rrset: SharedRrset) -> Self {
        // Empty RRsets are used to remove a default RRset for a flavor. So
        // they really are NODATA responses.
        if rrset.is_empty() {
            Self::no_data()
        }
        else {
            let mut answer = Answer::new(Rcode::NoError);
            answer.add_answer(rrset);
            NodeAnswer {
                answer,
                add_soa: false,
            }
        }
    }

    fn no_data() -> Self {
        NodeAnswer{
            answer: Answer::new(Rcode::NoError),
            add_soa: true,
        }
    }

    fn cname(rr: SharedRr) -> Self {
        let mut answer = Answer::new(Rcode::NoError);
        answer.add_cname(rr);
        NodeAnswer {
            answer,
            add_soa: false
        }
    }

    fn nx_domain() -> Self {
        NodeAnswer {
            answer: Answer::new(Rcode::NXDomain),
            add_soa: true,
        }
    }

    fn authority(authority: AnswerAuthority) -> Self {
        NodeAnswer {
            answer: Answer::with_authority(Rcode::NoError, authority),
            add_soa: false,
        }
    }

    fn into_answer(mut self, zone: &ReadZone) -> Answer {
        if self.add_soa {
            if let Some(soa) = zone.apex.get_soa(zone.flavor, zone.version) {
                self.answer.add_authority(
                    AnswerAuthority::new(
                        zone.apex.apex_name().clone(), Some(soa), None, None
                    )
                )
            }
        }
        self.answer
    }
}


//------------ Answer --------------------------------------------------------

#[derive(Clone)]
pub struct Answer {
    /// The response code of the answer.
    rcode: Rcode,

    /// The content of the answer.
    content: AnswerContent,

    /// The optional authority section to be included in the answer.
    authority: Option<AnswerAuthority>
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
        builder: MessageBuilder<Target>
    ) -> AdditionalBuilder<Target> {
        let question = message.sole_question().unwrap();
        let qname = question.qname();
        let qclass = question.qclass();
        let mut builder = builder.start_answer(message, self.rcode).unwrap();

        match self.content {
            AnswerContent::Data(ref answer) => {
                for item in answer.data() {
                    builder.push((qname, qclass, answer.ttl(), item)).unwrap();
                }
            }
            AnswerContent::Cname(ref cname) => {
                builder.push(
                    (qname, qclass, cname.ttl(), cname.data())
                ).unwrap()
            }
            AnswerContent::NoData => { }
        }

        let mut builder = builder.authority();
        if let Some(authority) = self.authority.as_ref() {
            if let Some(soa) = authority.soa.as_ref() {
                builder.push((
                    authority.owner.clone(), qclass, soa.ttl(), soa.data()
                )).unwrap();
            }
            if let Some(ns) = authority.ns.as_ref() {
                for item in ns.data() {
                    builder.push((
                            authority.owner.clone(), qclass,
                            ns.ttl(),
                            item
                    )).unwrap()
                }
            }
            if let Some(ref ds) = authority.ds {
                for item in ds.data() {
                    builder.push(
                        (authority.owner.clone(), qclass, ds.ttl(), item)
                    ).unwrap()
                }
            }
        }

        builder.additional()
    }
}


//------------ AnswerContent -------------------------------------------------

/// The content of the answer.
#[derive(Clone)]
pub enum AnswerContent {
    Data(SharedRrset),
    Cname(SharedRr),
    NoData
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


