//! Quering for zone data.
use core::iter;

use std::sync::Arc;

use bytes::Bytes;

use crate::base::iana::{Rcode, Rtype};
use crate::base::name::Label;
use crate::base::Name;
use crate::zonetree::answer::{Answer, AnswerAuthority};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::types::ZoneCut;
use crate::zonetree::walk::WalkState;
use crate::zonetree::{ReadableZone, Rrset, SharedRr, SharedRrset, WalkOp};

use super::nodes::{NodeChildren, NodeRrsets, Special, ZoneApex, ZoneNode};
use super::versioned::Version;
use super::versioned::VersionMarker;

//------------ ReadZone ------------------------------------------------------

#[derive(Clone)]
pub struct ReadZone {
    apex: Arc<ZoneApex>,
    version: Version,
    _version_marker: Arc<VersionMarker>,
}

impl ReadZone {
    pub(super) fn new(
        apex: Arc<ZoneApex>,
        version: Version,
        _version_marker: Arc<VersionMarker>,
    ) -> Self {
        ReadZone {
            apex,
            version,
            _version_marker,
        }
    }
}

impl ReadZone {
    fn query_below_apex<'l>(
        &self,
        label: &Label,
        qname: impl Iterator<Item = &'l Label> + Clone,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        self.query_children(self.apex.children(), label, qname, qtype, walk)
    }

    fn query_node<'l>(
        &self,
        node: &ZoneNode,
        mut qname: impl Iterator<Item = &'l Label> + Clone,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        if walk.enabled() {
            // Make sure we visit everything when walking the tree.
            self.query_rrsets(node.rrsets(), qtype, walk.clone());
            self.query_node_here_and_below(
                node,
                Label::root(),
                qname,
                qtype,
                walk,
            )
        } else if let Some(label) = qname.next() {
            self.query_node_here_and_below(node, label, qname, qtype, walk)
        } else {
            self.query_node_here_but_not_below(node, qtype, walk)
        }
    }

    fn query_node_here_and_below<'l>(
        &self,
        node: &ZoneNode,
        label: &Label,
        qname: impl Iterator<Item = &'l Label> + Clone,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        node.with_special(self.version, |special| match special {
            Some(Special::Cut(ref cut)) => {
                let answer = NodeAnswer::authority(AnswerAuthority::new(
                    cut.name.clone(),
                    None,
                    Some(cut.ns.clone()),
                    cut.ds.as_ref().cloned(),
                ));

                walk.op(&cut.ns);
                if let Some(ds) = &cut.ds {
                    walk.op(ds);
                }

                answer
            }
            Some(Special::NxDomain) => NodeAnswer::nx_domain(),
            Some(Special::Cname(_)) | None => self.query_children(
                node.children(),
                label,
                qname,
                qtype,
                walk,
            ),
        })
    }

    fn query_node_here_but_not_below(
        &self,
        node: &ZoneNode,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        node.with_special(self.version, |special| match special {
            Some(Special::Cut(cut)) => {
                let answer = self.query_at_cut(cut, qtype);
                if walk.enabled() {
                    walk.op(&cut.ns);
                    if let Some(ds) = &cut.ds {
                        walk.op(ds);
                    }
                }
                answer
            }
            Some(Special::Cname(cname)) => {
                let answer = NodeAnswer::cname(cname.clone());
                if walk.enabled() {
                    let mut rrset = Rrset::new(Rtype::CNAME, cname.ttl());
                    rrset.push_data(cname.data().clone());
                    walk.op(&SharedRrset::new(rrset));
                }
                answer
            }
            Some(Special::NxDomain) => NodeAnswer::nx_domain(),
            None => self.query_rrsets(node.rrsets(), qtype, walk),
        })
    }

    fn query_rrsets(
        &self,
        rrsets: &NodeRrsets,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        if walk.enabled() {
            // Walk the zone, don't match by qtype.
            let guard = rrsets.iter();
            for (_rtype, rrset) in guard.iter() {
                if let Some(shared_rrset) = rrset.get(self.version) {
                    walk.op(shared_rrset);
                }
            }
            NodeAnswer::no_data()
        } else if qtype == Rtype::ANY {
            // https://datatracker.ietf.org/doc/html/rfc8482#section-4.2
            // 4. Behavior of DNS Responders
            //
            //   "Below are the three different modes of behavior by DNS
            //    responders when processing queries with QNAMEs that exist,
            //    QCLASS=IN, and QTYPE=ANY.  Operators and implementers are
            //    free to choose whichever mechanism best suits their
            //    environment.
            //
            //    1.  A DNS responder can choose to select one or a larger
            //    subset of the available RRsets at the QNAME.
            //
            //    2.  A DNS responder can return a synthesized HINFO resource
            //    record. See Section 6 for discussion of the use of HINFO.
            //
            //    3.  A resolver can try to give out the most likely records
            //    the requester wants.  This is not always possible, and the
            //    result might well be a large response.
            //
            //    Except as described below in this section, the DNS responder
            //    MUST follow the standard algorithms when constructing a
            //    response."
            //
            // We choose for option 1 because option 2 would create lots of
            // extra work in the offline signing case (because lots of HFINO
            // records would need to be synthesized prior to signing) and
            // option 3 as stated may still result in a large response.
            let guard = rrsets.iter();
            guard
                .iter()
                .next()
                .and_then(|(_rtype, rrset)| rrset.get(self.version))
                .map(|rrset| NodeAnswer::data(rrset.clone()))
                .unwrap_or_else(NodeAnswer::no_data)
        } else {
            match rrsets.get(qtype, self.version) {
                Some(rrset) => NodeAnswer::data(rrset),
                None => NodeAnswer::no_data(),
            }
        }
    }

    fn query_at_cut(&self, cut: &ZoneCut, qtype: Rtype) -> NodeAnswer {
        match qtype {
            Rtype::DS => {
                if let Some(rrset) = cut.ds.as_ref() {
                    NodeAnswer::data(rrset.clone())
                } else {
                    NodeAnswer::no_data()
                }
            }
            _ => NodeAnswer::authority(AnswerAuthority::new(
                cut.name.clone(),
                None,
                Some(cut.ns.clone()),
                cut.ds.as_ref().cloned(),
            )),
        }
    }

    fn query_children<'l>(
        &self,
        children: &NodeChildren,
        label: &Label,
        qname: impl Iterator<Item = &'l Label> + Clone,
        qtype: Rtype,
        walk: WalkState,
    ) -> NodeAnswer {
        if walk.enabled() {
            children.walk(walk, |walk, (label, node)| {
                walk.push(*label);
                self.query_node(
                    node,
                    std::iter::empty(),
                    qtype,
                    walk.clone(),
                );
                walk.pop();
            });
            return NodeAnswer::no_data();
        }

        // Step 1: See if we have a non-terminal child for label. If so,
        //         continue there.
        let answer = children.with(label, |node| {
            node.map(|node| self.query_node(node, qname, qtype, walk.clone()))
        });
        if let Some(answer) = answer {
            return answer;
        }

        // Step 2: Now see if we have an asterisk label. If so, query that
        // node.
        children.with(Label::wildcard(), |node| match node {
            Some(node) => {
                self.query_node_here_but_not_below(node, qtype, walk)
            }
            None => NodeAnswer::nx_domain(),
        })
    }
}

//--- impl ReadableZone

impl ReadableZone for ReadZone {
    fn is_async(&self) -> bool {
        false
    }

    fn query(
        &self,
        qname: Name<Bytes>,
        qtype: Rtype,
    ) -> Result<Answer, OutOfZone> {
        let mut qname = self.apex.prepare_name(&qname)?;

        let answer = if let Some(label) = qname.next() {
            self.query_below_apex(label, qname, qtype, WalkState::DISABLED)
        } else {
            self.query_rrsets(self.apex.rrsets(), qtype, WalkState::DISABLED)
        };

        Ok(answer.into_answer(self))
    }

    fn walk(&self, op: WalkOp) {
        // The presence of a callback `op` indicates that walking mode is
        // requested. We still have to pass an Rtype but it won't be used for
        // matching when in walk mode, so we set it to Any as it most closely
        // matches our intent and will be ignored anyway.
        //
        // The walk is single threaded. With an empty callback function on a
        // "13th Gen Intel(R) Core(TM) i9-13900K" over 43,347,447 resource
        // records the walk took ~6 seconds, compared to 47 seconds for the
        // callback function to emit the same records as DNS messages and for
        // dig to receive the entire zone via AXFR:
        //
        //   dig -4 @127.0.0.1 -p 8053 +noanswer +tries=1 +noidnout AXFR de.
        let walk = WalkState::new(op);
        self.query_rrsets(self.apex.rrsets(), Rtype::ANY, walk.clone());
        self.query_below_apex(Label::root(), iter::empty(), Rtype::ANY, walk);
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
        let mut answer = Answer::new(Rcode::NOERROR);
        answer.add_answer(rrset);
        NodeAnswer {
            answer,
            add_soa: false,
        }
    }

    fn no_data() -> Self {
        NodeAnswer {
            answer: Answer::new(Rcode::NOERROR),
            add_soa: true,
        }
    }

    fn cname(rr: SharedRr) -> Self {
        let mut answer = Answer::new(Rcode::NOERROR);
        answer.add_cname(rr);
        NodeAnswer {
            answer,
            add_soa: false,
        }
    }

    fn nx_domain() -> Self {
        NodeAnswer {
            answer: Answer::new(Rcode::NXDOMAIN),
            add_soa: true,
        }
    }

    fn authority(authority: AnswerAuthority) -> Self {
        NodeAnswer {
            answer: Answer::with_authority(Rcode::NOERROR, authority),
            add_soa: false,
        }
    }

    fn into_answer(mut self, zone: &ReadZone) -> Answer {
        if self.add_soa {
            if let Some(soa) = zone.apex.get_soa(zone.version) {
                self.answer.set_authority(AnswerAuthority::new(
                    zone.apex.name().clone(),
                    Some(soa),
                    None,
                    None,
                ))
            }
        }
        self.answer
    }
}
