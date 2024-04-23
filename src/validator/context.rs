// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use super::anchor::TrustAnchor;
use super::anchor::TrustAnchors;
use super::group::Group;
use super::group::GroupList;
use super::nsec::nsec3_hash;
use super::nsec::NSEC3_ITER_BOGUS;
use super::nsec::NSEC3_ITER_INSECURE;
use super::types::ValidationState;
use crate::base::name::Chain;
use crate::base::name::Label;
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
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::string::ToString;
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
            return Node::trust_anchor(ta, self.upstream.clone()).await;
        }

        // Walk from the parent of name back to trust anchor.
        // Keep a list of names we need to walk in the other direction.
        let (mut node, mut names) =
            self.find_closest_node(name, ta, ta_owner).await;

        // Assume that node is not an intermediate node. We have to make sure
        // in find_closest_node.
        let mut signer_node = node.clone();

        // Walk from the closest node to name.
        println!("got names {names:?}");
        loop {
            match node.validation_state() {
                ValidationState::Secure => (), // continue
                ValidationState::Insecure => return node,
                ValidationState::Bogus | ValidationState::Indeterminate => {
                    todo!();
                }
            }

            // Create the child node
            let child_name = names.pop_front().unwrap();

            // If this node is an intermediate node then get the node for
            // signer name.
            node = self.create_child_node(child_name, &signer_node).await;
            if !node.intermediate() {
                signer_node = node.clone();
            }

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
            if let Some(_node) = self.cache_lookup(&curr) {
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
        msg.header_mut().set_cd(true);
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
                    let state = nsec_for_ds(&name, &mut authorities, node);
                    match state {
                        NsecState::InsecureDelegation => {
                            return Node::new_delegation(
                                name,
                                ValidationState::Insecure,
                                Vec::new(),
                            )
                        }
                        NsecState::SecureIntermediate => {
                            return Node::new_intermediate(
                                name,
                                ValidationState::Secure,
                                node.signer_name().clone(),
                            )
                        }
                        NsecState::Nothing => (), // Try NSEC3 next.
                    }

                    let state = nsec3_for_ds(&name, &mut authorities, node);
                    match state {
                        NsecState::InsecureDelegation => {
                            return Node::new_delegation(
                                name,
                                ValidationState::Insecure,
                                Vec::new(),
                            )
                        }
                        NsecState::SecureIntermediate => {
                            return Node::new_intermediate(
                                name,
                                ValidationState::Secure,
                                node.signer_name().clone(),
                            )
                        }
                        NsecState::Nothing => (),
                    }

                    // Both NSEC and NSEC3 failed. Create a new node with
                    // bogus state.
                    todo!();
                }
            };

        // TODO: Limit the size of the DS RRset.

        let (state, _wildcard) = ds_group.validate_with_node(node);
        match state {
            ValidationState::Secure => (),
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                todo!();
            }
        }

        // Do we need to check if the DS record is a wildcard?

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
        msg.header_mut().set_cd(true);
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

#[derive(Clone)]
pub struct Node {
    state: ValidationState,

    // This should be part of the state of the node
    keys: Vec<Dnskey<Bytes>>,
    signer_name: Dname<Bytes>,
    intermediate: bool,
}

impl Node {
    fn indeterminate(name: Dname<Bytes>) -> Self {
        Self {
            state: ValidationState::Indeterminate,
            keys: Vec::new(),
            signer_name: name,
            intermediate: false,
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
                        intermediate: false,
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
            intermediate: false,
        }
    }

    pub fn new_intermediate(
        name: Dname<Bytes>,
        state: ValidationState,
        signer_name: Dname<Bytes>,
    ) -> Self {
        println!("new_intermediate: for {name:?} signer {signer_name:?}");
        Self {
            state,
            signer_name,
            keys: Vec::new(),
            intermediate: true,
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

    pub fn intermediate(&self) -> bool {
        self.intermediate
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

enum NsecState {
    InsecureDelegation,
    SecureIntermediate,
    Nothing,
}

// Find an NSEC record that proves that a DS record does not exist and
// return the delegation status based on the rtypes present. The NSEC
// processing is simplified compared to normal NSEC processing for three
// reasons:
// 1) We do not accept wildcards. We do not support wildcard delegations,
//    so if we find one, we return a bogus status.
// 2) The name exists, otherwise we wouldn't be here.
// 3) The parent exists and is secure, otherwise we wouldn't be here.
//
// So we have two possibilities: we find an exact match for the name and
// check the bitmap or we find the name as an empty non-terminal.
fn nsec_for_ds(
    target: &Dname<Bytes>,
    groups: &mut GroupList,
    node: &Node,
) -> NsecState {
    for g in groups.iter() {
        if g.rtype() != Rtype::NSEC {
            continue;
        }
        println!("nsec_for_ds: trying group {g:?}");
        let owner = g.owner();
        let rrs = g.rr_set();
        let AllRecordData::Nsec(nsec) = rrs[0].data() else {
            panic!("NSEC expected");
        };
        println!("nsec = {nsec:?}");
        if target.name_eq(&owner) {
            // Validate the signature
            let (state, wildcard) = g.validate_with_node(node);
            match state {
                ValidationState::Insecure
                | ValidationState::Bogus
                | ValidationState::Indeterminate => todo!(),
                ValidationState::Secure => (),
            }

            // Rule out wildcard
            if wildcard.is_some() {
                todo!();
            }

            // Check the bitmap.
            let types = nsec.types();

            // Check for DS.
            if types.contains(Rtype::DS) {
                // We didn't get a DS RRset but the NSEC record proves there
                // is one. Complain.
                todo!();
            }

            // Check for SOA.
            if types.contains(Rtype::SOA) {
                // This is an NSEC record from the APEX. Complain.
                todo!();
            }

            // Check for NS.
            if types.contains(Rtype::NS) {
                // We found NS and ruled out DS. This in an insecure delegation.
                return NsecState::InsecureDelegation;
            }

            // Anything else is a secure intermediate node.
            return NsecState::SecureIntermediate;
        }

        // Check that if the owner is a prefix:
        // - that the nsec does not have DNAME
        // - that if the nsec has NS, it also has SOA
        todo!();

        // Check that target is in the range of the NSEC and that owner is a
        // prefix of the next_name.
        if target.name_cmp(&owner) == Ordering::Greater
            && target.name_cmp(nsec.next_name()) == Ordering::Less
            && nsec.next_name().ends_with(target)
        {
            return NsecState::SecureIntermediate;
        }
        todo!();
    }
    NsecState::Nothing
}

// Find an NSEC3 record hat proves that a DS record does not exist and return
// the delegation status based on the rtypes present. The NSEC3 processing is
// simplified compared to normal NSEC3 processing for three reasons:
// 1) We do not accept wildcards. We do not support wildcard delegations,
//    so we don't look for wildcards.
// 2) The name exists, otherwise we wouldn't be here.
// 3) The parent exists and is secure, otherwise we wouldn't be here.
//
// So we have two possibilities: we find an exact match for the hash of the
// name and check the bitmap or we find that the name does not exist, but
// the NSEC3 record uses opt-out.
fn nsec3_for_ds(
    target: &Dname<Bytes>,
    groups: &mut GroupList,
    node: &Node,
) -> NsecState {
    for g in groups.iter() {
        if g.rtype() != Rtype::NSEC3 {
            continue;
        }
        println!("nsec3_for_ds: trying group {g:?}");

        let rrs = g.rr_set();
        let AllRecordData::Nsec3(nsec3) = rrs[0].data() else {
            panic!("NSEC3 expected");
        };

        let iterations = nsec3.iterations();

        // See RFC 9276, Appendix A for a recommendation on the maximum number
        // of iterations.
        if iterations > NSEC3_ITER_INSECURE || iterations > NSEC3_ITER_BOGUS {
            // High iteration count, verify the signature and abort.
            todo!();
        }

        // Create the hash with the parameters in this record. We should cache
        // the hash.
        let hash = nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            iterations,
            nsec3.salt(),
        );

        let owner = g.owner();
        let first = owner.first();

        println!("got hash {hash:?} and first {first:?}");

        // Make sure the NSEC3 record is from an appropriate zone.
        if !target.ends_with(&owner.parent().unwrap_or_else(|| Dname::root()))
        {
            // Matching hash but wrong zone. Skip.
            todo!();
        }

        if first == Label::from_slice(hash.to_string().as_ref()).unwrap() {
            // We found an exact match.

            // Validate the signature
            let (state, _) = g.validate_with_node(node);
            match state {
                ValidationState::Insecure
                | ValidationState::Bogus
                | ValidationState::Indeterminate => todo!(),
                ValidationState::Secure => (),
            }

            // Check the bitmap.
            let types = nsec3.types();

            // Check for DS.
            if types.contains(Rtype::DS) {
                // We didn't get a DS RRset but the NSEC3 record proves there
                // is one. Complain.
                todo!();
            }

            // Check for SOA.
            if types.contains(Rtype::SOA) {
                // This is an NSEC3 record from the APEX. Complain.
                todo!();
            }

            // Check for NS.
            if types.contains(Rtype::NS) {
                // We found NS and ruled out DS. This in an insecure delegation.
                return NsecState::InsecureDelegation;
            }

            // Anything else is a secure intermediate node.
            return NsecState::SecureIntermediate;
        }

        // Check if target is between the hash in the first label and the
        // next_owner field.
        if first < Label::from_slice(hash.to_string().as_ref()).unwrap()
            && hash < nsec3.next_owner()
        {
            // target does not exist. However, if the opt-out flag is set,
            // we are allowed to assume an insecure delegation (RFC 5155,
            // Section 6). First check the signature.
            let (state, _) = g.validate_with_node(node);
            match state {
                ValidationState::Insecure
                | ValidationState::Bogus
                | ValidationState::Indeterminate => todo!(),
                ValidationState::Secure => (),
            }

            if !nsec3.opt_out() {
                // Weird, target does not exist. Complain.
                todo!();
            }

            return NsecState::InsecureDelegation;
        }
    }
    NsecState::Nothing
}
