// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use super::anchor::TrustAnchor;
use super::anchor::TrustAnchors;
use super::group::Group;
use super::group::GroupList;
use super::types::ValidationState;
use crate::base::name::Chain;
use crate::base::Dname;
use crate::base::MessageBuilder;
use crate::base::ParsedDname;
use crate::base::Record;
use crate::base::RelativeDname;
use crate::base::Rtype;
use crate::base::ToDname;
use bytes::Bytes;
//use crate::dep::octseq::Octets;
//use crate::base::ParsedDname;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::AllRecordData;
use crate::rdata::Dnskey;
use crate::rdata::Ds;
use crate::rdata::ZoneRecordData;
use crate::validate::supported_algorithm;
use crate::validate::supported_digest;
use crate::validate::DnskeyExt;
use std::collections::VecDeque;
use std::vec::Vec;

pub struct ValidationContext<Upstream> {
    ta: TrustAnchors,
    upstream: Upstream,
}

impl<Upstream> ValidationContext<Upstream> {
    pub fn new(ta: TrustAnchors, upstream: Upstream) -> Self {
        Self { ta, upstream }
    }

    pub async fn get_node(&self, name: &Dname<Bytes>) -> Node
    where
        Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
    {
        println!("get_node: for {name:?}");

        // Check the cache first
        if let Some(node) = self.cache_lookup(name) {
            return node;
        }

        // Find a trust anchor.
        let Some(ta) = self.ta.find(name) else {
            // Try to get an indeterminate node for the root
            return Node::indeterminate(Dname::root());
        };

        let ta_owner = ta.owner();
        if ta_owner.name_eq(name) {
            // The trust anchor is the same node we are looking for. Create
            // a node for the trust anchor.
            todo!();
        }

        // Walk from the parent of name back to trust anchor.
        // Keep a list of names we need to walk in the other direction.
        let (mut node, mut names) =
            self.find_closest_node(name, ta, ta_owner).await;

        // Walk from the closest node to name.
        println!("got names {names:?}");
        loop {
            match node.validation_state() {
                ValidationState::Secure => (), // continue
                ValidationState::Insecure
                | ValidationState::Bogus
                | ValidationState::Indeterminate => {
                    todo!();
                }
            }

            // Create the child node
            let child_name = names.pop_front().unwrap();
            node = self.create_child_node(child_name, &node).await;
            if names.is_empty() {
                return node;
            }
        }
    }

    async fn find_closest_node(
        &self,
        name: &Dname<Bytes>,
        ta: &TrustAnchor,
        ta_owner: Dname<Bytes>,
    ) -> (Node, VecDeque<Dname<Bytes>>)
    where
        Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
    {
        println!("find_closest_node for {name:?}");
        let mut names = VecDeque::new();
        names.push_front(name.clone());
        let mut curr = name.parent().unwrap();
        loop {
            if ta_owner.name_eq(&curr) {
                // We ended up at the trust anchor.
                let node =
                    Node::trust_anchor(ta, self.upstream.clone()).await;
                return (node, names);
            }

            // Try to find the node in the cache.
            if let Some(node) = self.cache_lookup(&curr) {
                todo!();
            }

            names.push_front(curr.clone());

            curr = curr.parent().unwrap();
        }
    }

    async fn create_child_node(&self, name: Dname<Bytes>, node: &Node) -> Node
    where
        Upstream: SendRequest<RequestMessage<Bytes>>,
    {
        // Start with a DS lookup.
        let mut msg = MessageBuilder::new_bytes();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((&name, Rtype::DS)).unwrap();
        let mut req = RequestMessage::new(msg);
        req.set_dnssec_ok(true);

        let mut request = self.upstream.send_request(req);
        let reply = request.get_response().await;

        let reply = reply.unwrap();
        println!("got reply for {name:?}/DS {reply:?}");

        // Group the answer and authority sections.
        let mut answers = GroupList::new();
        for rr in reply.answer().unwrap() {
            answers.add(rr.unwrap());
        }
        let mut authorities = GroupList::new();
        for rr in reply.authority().unwrap() {
            authorities.add(rr.unwrap());
        }

        let ds_group =
            match answers.iter().filter(|g| g.rtype() == Rtype::DS).next() {
                Some(g) => g,
                None => {
                    // Verify proof that DS doesn't exist for this name.
                    todo!();
                }
            };

        // TODO: Limit the size of the DS RRset.

        match ds_group.validate_with_node(node) {
            ValidationState::Secure => (),
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                todo!();
            }
        }

        // We got valid DS records.

        // RFC 4035, Section: 5.2:
        // If the validator does not support any of the algorithms listed in
        // an authenticated DS RRset, then the resolver has no supported
        // authentication path leading from the parent to the child.  The
        // resolver should treat this case as it would the case of an
        // authenticated NSEC RRset proving that no DS RRset exists, as
        // described above.

        // RFC 6840, Section 5.2:
        // In brief, DS records using unknown or unsupported message digest
        // algorithms MUST be treated the same way as DS records referring
        // to DNSKEY RRs of unknown or unsupported public key algorithms.
        //
        // In other words, when determining the security status of a zone, a
        // validator disregards any authenticated DS records that specify
        // unknown or unsupported DNSKEY algorithms.  If none are left, the
        // zone is treated as if it were unsigned.
        //
        // This document modifies the above text to additionally disregard
        // authenticated DS records using unknown or unsupported message
        // digest algorithms.
        let mut tmp_group = ds_group.clone();
        let valid_algs = tmp_group
            .rr_iter()
            .map(|r| {
                if let AllRecordData::Ds(ds) = r.data() {
                    (ds.algorithm(), ds.digest_type())
                } else {
                    panic!("DS record expected");
                }
            })
            .filter(|(alg, dig)| {
                supported_algorithm(alg) && supported_digest(dig)
            })
            .next()
            .is_some();

        if !valid_algs {
            // Delegation is insecure
            todo!();
        }

        // Get the DNSKEY RRset.
        let mut msg = MessageBuilder::new_bytes();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((&name, Rtype::DNSKEY)).unwrap();
        let mut req = RequestMessage::new(msg);
        req.set_dnssec_ok(true);

        let mut request = self.upstream.send_request(req);
        let reply = request.get_response().await;

        let reply = reply.unwrap();
        println!("got reply {reply:?}");

        // We need the DNSKEY RRset. Group only the answer section.
        let mut answers = GroupList::new();
        for rr in reply.answer().unwrap() {
            answers.add(rr.unwrap());
        }

        let dnskey_group = match answers
            .iter()
            .filter(|g| g.rtype() == Rtype::DNSKEY)
            .next()
        {
            Some(g) => g,
            None => {
                // No DNSKEY RRset, set validation state to bogus.
                todo!();
            }
        };

        // TODO: Limit the size of the DNSKEY RRset.

        // Try to find one DNSKEY record that matches a DS record and that
        // can be used to validate the DNSKEY RRset.

        for ds in tmp_group
            .rr_iter()
            .map(|r| {
                if let AllRecordData::Ds(ds) = r.data() {
                    ds
                } else {
                    panic!("DS record expected");
                }
            })
            .filter(|ds| {
                supported_algorithm(&ds.algorithm())
                    && supported_digest(&ds.digest_type())
            })
        {
            let r_dnskey = match find_key_for_ds(ds, dnskey_group) {
                None => continue,
                Some(r) => r,
            };
            let dnskey =
                if let AllRecordData::Dnskey(dnskey) = r_dnskey.data() {
                    dnskey
                } else {
                    panic!("expected DNSKEY");
                };
            let key_tag = dnskey.key_tag();
            let key_name = r_dnskey.owner().try_to_dname().unwrap();
            for sig in (*dnskey_group).clone().sig_iter() {
                if dnskey_group
                    .check_sig(sig, &key_name, dnskey, &key_name, key_tag)
                {
                    let dnskey_vec: Vec<_> = dnskey_group
                        .clone()
                        .rr_iter()
                        .map(|r| {
                            if let AllRecordData::Dnskey(key) = r.data() {
                                key
                            } else {
                                panic!("Dnskey expected");
                            }
                        })
                        .cloned()
                        .collect();
                    return Node::new_delegation(
                        key_name,
                        ValidationState::Secure,
                        dnskey_vec,
                    );
                /*
                             {
                                        if let AllRecordData::Dnskey(key) = key_rec.data() {
                                            new_node.keys.push(key.clone());
                                        }
                                    }
                                    let mut new_node = Self {
                                        state: ValidationState::Secure,
                                        keys: Vec::new(),
                                        signer_name: key_name,
                                    };
                                    return new_node;
                */
                } else {
                    // To avoid CPU exhaustion attacks such as KeyTrap
                    // (CVE-2023-50387) it is good to limit signature
                    // validation as much as possible. To be as strict as
                    // possible, we can make the following assumptions:
                    // 1) A trust anchor contains at least one key with a
                    // supported algorithm, so at least one signature is
                    // expected to be verifiable.
                    // 2) A DNSKEY RRset plus associated RRSIG is self-
                    // contained. Every signature is made with a key in the
                    // RRset and it is the current contents of the RRset
                    // that is signed. So we expect that signature
                    // verification cannot fail.
                    // 3) With one exception: keytag collisions could create
                    // confusion about which key was used. Collisions are
                    // rare so we assume at most two keys in the RRset to be
                    // involved in a collision.
                    // For these reasons we can limit the number of failures
                    // we tolerate to one. And declare the DNSKEY RRset
                    // bogus if we get two failures.
                    todo!();
                }
            }
            todo!();
        }

        todo!();
    }

    fn cache_lookup<Octs>(&self, _name: &Dname<Octs>) -> Option<Node> {
        None
    }
}

pub struct Node {
    state: ValidationState,

    // This should be part of the state of the node
    keys: Vec<Dnskey<Bytes>>,
    signer_name: Dname<Bytes>,
}

impl Node {
    fn indeterminate(name: Dname<Bytes>) -> Self {
        Self {
            state: ValidationState::Indeterminate,
            keys: Vec::new(),
            signer_name: name,
        }
    }

    async fn trust_anchor<Upstream>(
        ta: &TrustAnchor,
        upstream: Upstream,
    ) -> Self
    where
        Upstream: SendRequest<RequestMessage<Bytes>>,
    {
        // Get the DNSKEY RRset for the trust anchor.
        let ta_owner = ta.owner();

        let mut msg = MessageBuilder::new_bytes();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((&ta_owner, Rtype::DNSKEY)).unwrap();
        let mut req = RequestMessage::new(msg);
        req.set_dnssec_ok(true);

        let mut request = upstream.send_request(req);
        let reply = request.get_response().await;

        let reply = reply.unwrap();
        println!("got reply {reply:?}");

        // Turn answer section into a GroupList. We expect a positive reply
        // so the authority section can be ignored.
        let mut answers = GroupList::new();
        for rr in reply.answer().unwrap() {
            answers.add(rr.unwrap());
        }

        // Get the DNSKEY group. We expect exactly one.
        let dnskeys = answers
            .iter()
            .filter(|g| g.rtype() == Rtype::DNSKEY)
            .next()
            .unwrap();
        println!("dnskeys = {dnskeys:?}");

        // Try to find one trust anchor key that can be used to validate
        // the DNSKEY RRset.
        for tkey in (*ta).clone().iter() {
            if !has_key(dnskeys, tkey) {
                continue;
            }
            let tkey_dnskey =
                if let ZoneRecordData::Dnskey(dnskey) = tkey.data() {
                    dnskey
                } else {
                    continue;
                };
            let key_tag = tkey_dnskey.key_tag();
            let key_name = tkey.owner().try_to_dname().unwrap();
            for sig in (*dnskeys).clone().sig_iter() {
                if dnskeys.check_sig(
                    sig,
                    &ta_owner,
                    tkey_dnskey,
                    &key_name,
                    key_tag,
                ) {
                    let mut new_node = Self {
                        state: ValidationState::Secure,
                        keys: Vec::new(),
                        signer_name: ta_owner,
                    };
                    for key_rec in dnskeys.clone().rr_iter() {
                        if let AllRecordData::Dnskey(key) = key_rec.data() {
                            new_node.keys.push(key.clone());
                        }
                    }
                    return new_node;
                } else {
                    // To avoid CPU exhaustion attacks such as KeyTrap
                    // (CVE-2023-50387) it is good to limit signature
                    // validation as much as possible. To be as strict as
                    // possible, we can make the following assumptions:
                    // 1) A trust anchor contains at least one key with a
                    // supported algorithm, so at least one signature is
                    // expected to be verifiable.
                    // 2) A DNSKEY RRset plus associated RRSIG is self-
                    // contained. Every signature is made with a key in the
                    // RRset and it is the current contents of the RRset
                    // that is signed. So we expect that signature
                    // verification cannot fail.
                    // 3) With one exception: keytag collisions could create
                    // confusion about which key was used. Collisions are
                    // rare so we assume at most two keys in the RRset to be
                    // involved in a collision.
                    // For these reasons we can limit the number of failures
                    // we tolerate to one. And declare the DNSKEY RRset
                    // bogus if we get two failures.
                    todo!();
                }
            }
            todo!();
        }
        todo!();
    }

    pub fn new_delegation(
        signer_name: Dname<Bytes>,
        state: ValidationState,
        keys: Vec<Dnskey<Bytes>>,
    ) -> Self {
        Self {
            state,
            signer_name,
            keys,
        }
    }

    pub fn validation_state(&self) -> ValidationState {
        self.state
    }

    pub fn keys(&self) -> &[Dnskey<Bytes>] {
        &self.keys
    }

    pub fn signer_name(&self) -> &Dname<Bytes> {
        &self.signer_name
    }
}

fn has_key(
    dnskeys: &Group,
    tkey: &Record<
        Chain<RelativeDname<Bytes>, Dname<Bytes>>,
        ZoneRecordData<Bytes, Chain<RelativeDname<Bytes>, Dname<Bytes>>>,
    >,
) -> bool {
    let tkey_dnskey = if let ZoneRecordData::Dnskey(dnskey) = tkey.data() {
        dnskey
    } else {
        return false;
    };

    for key in (*dnskeys).clone().rr_iter() {
        let AllRecordData::Dnskey(key_dnskey) = key.data() else {
            continue;
        };
        if tkey.owner().try_to_dname::<Bytes>().unwrap() != key.owner() {
            continue;
        }
        if tkey.class() != key.class() {
            continue;
        }
        if tkey.rtype() != key.rtype() {
            continue;
        }
        if tkey_dnskey != key_dnskey {
            continue;
        }
        return true;
    }
    false
}

fn find_key_for_ds(
    ds: &Ds<Bytes>,
    dnskey_group: &Group,
) -> Option<Record<Dname<Bytes>, AllRecordData<Bytes, ParsedDname<Bytes>>>> {
    let ds_alg = ds.algorithm();
    let ds_tag = ds.key_tag();
    let digest_type = ds.digest_type();
    for key in dnskey_group.clone().rr_iter() {
        let AllRecordData::Dnskey(dnskey) = key.data() else {
	    panic!("Dnskey expected");
	};
        if dnskey.algorithm() != ds_alg {
            continue;
        }
        if dnskey.key_tag() != ds_tag {
            continue;
        }
        let digest = dnskey.digest(key.owner(), digest_type).unwrap();
        if ds.digest() == digest.as_ref() {
            return Some(key.clone());
        }
    }
    None
}
