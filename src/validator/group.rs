// Group of resource records and associated signatures.

// For lack of a better term we call this a group. RR set refers to just
// the resource records without the signatures.

// Name suggested by Yorgos: SignedRrset. Problem, sometimes there are no
// signatures, sometimes there is a signature but no RRset.

use crate::base::Name;
use crate::base::ParsedName;
use crate::base::ParsedRecord;
use bytes::Bytes;
//use crate::base::ParseRecordData;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::class::Class;
use crate::base::iana::ExtendedErrorCode;
use crate::base::name::ToName;
use crate::base::opt::exterr::ExtendedError;
use crate::base::Record;
use crate::base::Rtype;
//use crate::base::UnknownRecordData;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::AllRecordData;
use crate::rdata::Dnskey;
use crate::rdata::Rrsig;
use crate::validate::RrsigExt;
use std::fmt::Debug;
//use std::marker::PhantomData;
use std::slice::Iter;
//use std::slice::IterMut;
use super::context::Node;
use super::context::ValidationContext;
use super::types::ValidationState;
use std::sync::Mutex;
use std::vec::Vec;

type RrType = Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;
type SigType = Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>;

#[derive(Debug)]
pub struct Group {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
    state: Mutex<Option<ValidationState>>,
    wildcard: Mutex<Option<Name<Bytes>>>,
    signer_name: Mutex<Option<Name<Bytes>>>,
}

impl Group {
    fn new(rr: ParsedRecord<'_, Bytes>) -> Self {
        if rr.rtype() != Rtype::RRSIG {
            return Self {
                rr_set: vec![to_bytes_record(&rr)],
                sig_set: Vec::new(),
                state: Mutex::new(None),
                wildcard: Mutex::new(None),
                signer_name: Mutex::new(None),
            };
        }
        todo!();
    }

    fn add(&mut self, rr: &ParsedRecord<'_, Bytes>) -> Result<(), ()> {
        // First check owner.
        if !self.rr_set.is_empty() {
            if self.rr_set[0].owner()
                != &rr.owner().try_to_name::<Bytes>().unwrap()
            {
                return Err(());
            }
        } else {
            if self.sig_set[0].owner().try_to_name::<Bytes>()
                != rr.owner().try_to_name()
            {
                return Err(());
            }
        }

        let (curr_class, curr_rtype) = if !self.rr_set.is_empty() {
            (self.rr_set[0].class(), self.rr_set[0].rtype())
        } else {
            (
                self.sig_set[0].class(),
                self.sig_set[0].data().type_covered(),
            )
        };

        if rr.rtype() == Rtype::RRSIG {
            let record = rr.to_record::<Rrsig<_, _>>().unwrap().unwrap();
            let rrsig = record.data();

            if curr_class == rr.class() && curr_rtype == rrsig.type_covered()
            {
                let rrsig: Rrsig<Bytes, Name<Bytes>> =
                    Rrsig::<Bytes, Name<Bytes>>::new(
                        rrsig.type_covered(),
                        rrsig.algorithm(),
                        rrsig.labels(),
                        rrsig.original_ttl(),
                        rrsig.expiration(),
                        rrsig.inception(),
                        rrsig.key_tag(),
                        rrsig.signer_name().try_to_name::<Bytes>().unwrap(),
                        Bytes::copy_from_slice(rrsig.signature().as_ref()),
                    )
                    .unwrap();

                let record: Record<Name<Bytes>, _> = Record::new(
                    record.owner().try_to_name::<Bytes>().unwrap(),
                    curr_class,
                    record.ttl(),
                    rrsig,
                );
                self.sig_set.push(record);
                return Ok(());
            }
            return Err(());
        }

        // We can add rr if owner, class and rtype match.
        if curr_class == rr.class() && curr_rtype == rr.rtype() {
            let rr = to_bytes_record(rr);
            self.rr_set.push(rr);
            return Ok(());
        }

        // No match.
        Err(())
    }

    pub fn set_state_wildcard_signer_name(
        &self,
        state: ValidationState,
        wildcard: Option<Name<Bytes>>,
        signer_name: Name<Bytes>,
    ) {
        let mut m_state = self.state.lock().unwrap();
        *m_state = Some(state);
        drop(m_state);
        let mut m_wildcard = self.wildcard.lock().unwrap();
        *m_wildcard = wildcard;
        drop(m_wildcard);
        let mut m_signer_name = self.signer_name.lock().unwrap();
        *m_signer_name = Some(signer_name);
        drop(m_signer_name);
    }

    pub fn validated(
        &self,
        state: ValidationState,
        signer_name: Name<Bytes>,
        wildcard: Option<Name<Bytes>>,
        ede: Option<ExtendedError<Bytes>>,
    ) -> ValidatedGroup {
        ValidatedGroup::new(
            self.rr_set.clone(),
            self.sig_set.clone(),
            state,
            signer_name,
            wildcard,
            ede,
        )
    }

    pub fn get_state(&self) -> Option<ValidationState> {
        let m_state = self.state.lock().unwrap();
        *m_state
    }

    pub fn wildcard(&self) -> Option<Name<Bytes>> {
        let m_wildcard = self.wildcard.lock().unwrap();
        (*m_wildcard).clone()
    }

    pub fn signer_name(&self) -> Name<Bytes> {
        let m_signer_name = self.signer_name.lock().unwrap();
        (*m_signer_name).clone().unwrap()
    }

    pub fn owner(&self) -> Name<Bytes> {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn class(&self) -> Class {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }

    pub fn rr_iter(&mut self) -> Iter<RrType> {
        self.rr_set.iter()
    }

    pub fn sig_iter(&mut self) -> Iter<SigType> {
        self.sig_set.iter()
    }

    pub async fn validate_with_vc<Upstream>(
        &self,
        vc: &ValidationContext<Upstream>,
    ) -> (
        ValidationState,
        Name<Bytes>,
        Option<Name<Bytes>>,
        Option<ExtendedError<Bytes>>,
    )
    where
        Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
    {
        // We have two cases, with an without RRSIGs. With RRSIGs we can
        // look at the signer_name. We need to find the DNSSEC status
        // of signer_name. If the status is secure, we can validate
        // the RRset against the keys in that zone. If the status is
        // insecure we can ignore the RRSIGs and return insecure.
        //
        // Without signatures we need to find the closest enclosing zone
        // that is insecure (and return the status insecure) or find that
        // the name is in a secure zone and return bogus.
        //
        // Note that the GetDNS validator issues a SOA query if there is
        // no signature. Is that better then just walking to the first
        // insecure delegation?
        //
        // Note that if the RRset is empty (and we only have RRSIG records)
        // then the status is insecure, because we cannot validate RRSIGs.
        // Is there an RFC that descibes this?
        if self.rr_set.is_empty() {
            return (
                ValidationState::Insecure,
                Name::root(),
                None,
                Some(
                    ExtendedError::new_with_str(
                        ExtendedErrorCode::DNSSEC_INDETERMINATE,
                        "RRSIG without RRset",
                    )
                    .unwrap(),
                ),
            );
        }

        let target = if !self.sig_set.is_empty() {
            self.sig_set[0].data().signer_name()
        } else {
            self.rr_set[0].owner()
        };
        let node = vc.get_node(target).await;
        let state = node.validation_state();
        match state {
            ValidationState::Secure => (), // Continue validating
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return (state, target.clone(), None, node.extended_error())
            }
        }
        let (state, wildcard, ede) = self.validate_with_node(&node);
        (state, target.clone(), wildcard, ede)
    }

    // Try to validate the signature using a node. Return the validation
    // state. Also return if the signature was expanded from a wildcard.
    // This is valid only if the validation state is secure.
    pub fn validate_with_node(
        &self,
        node: &Node,
    ) -> (
        ValidationState,
        Option<Name<Bytes>>,
        Option<ExtendedError<Bytes>>,
    ) {
        // Check the validation state of node. We can return directly if the
        // state is anything other than Secure.
        let state = node.validation_state();
        match state {
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return (state, None, node.extended_error())
            }
            ValidationState::Secure => (),
        }
        let keys = node.keys();
        let mut secure = false;
        let mut wildcard = None;
        for sig_rec in self.clone().sig_iter() {
            let sig = sig_rec.data();
            for key in keys {
                // See if this key matches the sig.
                if key.algorithm() != sig.algorithm() {
                    continue;
                }
                let key_tag = key.key_tag();
                if key_tag != sig.key_tag() {
                    continue;
                }
                if self.check_sig(
                    sig_rec,
                    node.signer_name(),
                    key,
                    node.signer_name(),
                    key_tag,
                ) {
                    secure = true;
                    wildcard = sig.wildcard_closest_encloser(&self.rr_set[0]);
                    break;
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
            if secure {
                break;
            }
        }
        if secure {
            (ValidationState::Secure, wildcard, None)
        } else {
            todo!(); // EDE
                     // (ValidationState::Bogus, None)
        }
    }

    // Follow RFC 4035, Section 5.3.
    pub fn check_sig(
        &self,
        sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
        signer_name: &Name<Bytes>,
        key: &Dnskey<Bytes>,
        key_name: &Name<Bytes>,
        key_tag: u16,
    ) -> bool {
        let ts_now = Timestamp::now();
        let rtype = self.rtype();
        let owner = self.owner();
        let labels = owner.iter().count() - 1;
        let rrsig = sig.data();

        println!("check_sig for {rrsig:?} and {key:?}");

        println!("{:?} and {:?}", rrsig.type_covered(), rtype);
        println!(
            "{:?} and {:?}: {:?}",
            rrsig.expiration(),
            ts_now,
            rrsig.expiration().canonical_lt(&ts_now)
        );
        println!(
            "{:?} and {:?}: {:?}",
            rrsig.inception(),
            ts_now,
            rrsig.inception().canonical_gt(&ts_now)
        );
        println!("{:?} and {:?}", rrsig.algorithm(), key.algorithm());
        println!("{:?} and {:?}", rrsig.key_tag(), key_tag);

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR and the RRset MUST have the same owner name and the same
        //   class.
        if !sig.owner().name_eq(&owner) || sig.class() != self.class() {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name field MUST be the name of the zone that
        //   contains the RRset.

        // We don't really know the name of the zone that contains an RRset. What
        // we can do is that the signer's name is a prefix of the owner name.
        // We assume that a zone will not sign things in space that is delegated
        // (except for the parent side of the delegation)
        if !owner.ends_with(&signer_name) {
            println!("failed at line {}", line!());
            println!(
                "check_sig: {:?} does not end with {signer_name:?}",
                owner
            );
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Type Covered field MUST equal the RRset's type.
        if rrsig.type_covered() != rtype {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The number of labels in the RRset owner name MUST be greater than
        //   or equal to the value in the RRSIG RR's Labels field.
        if labels < rrsig.labels() as usize {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The validator's notion of the current time MUST be less than or
        //   equal to the time listed in the RRSIG RR's Expiration field.
        // - The validator's notion of the current time MUST be greater than or
        //   equal to the time listed in the RRSIG RR's Inception field.
        if ts_now.canonical_gt(&rrsig.expiration())
            || ts_now.canonical_lt(&rrsig.inception())
        {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
        //   match the owner name, algorithm, and key tag for some DNSKEY RR in
        //   the zone's apex DNSKEY RRset.
        if signer_name != key_name
            || rrsig.algorithm() != key.algorithm()
            || rrsig.key_tag() != key_tag
        {
            println!("failed at line {}", line!());
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
        //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
        //   set.

        // We cannot check here if the key is in the zone's apex, that is up to
        // the caller. Just check the Zone Flag bit.
        if !key.is_zone_key() {
            println!("failed at line {}", line!());
            return false;
        }

        //signature
        let mut signed_data = Vec::<u8>::new();
        rrsig
            .signed_data(&mut signed_data, &mut self.rr_set())
            .unwrap();
        let res = rrsig.verify_signed_data(key, &signed_data);

        res.is_ok()
    }
}

impl Clone for Group {
    fn clone(&self) -> Self {
        let m_state = self.state.lock().unwrap();
        let state = *m_state;
        drop(m_state);
        let m_wildcard = self.wildcard.lock().unwrap();
        let wildcard = (*m_wildcard).clone();
        drop(m_wildcard);
        let m_signer_name = self.signer_name.lock().unwrap();
        let signer_name = (*m_signer_name).clone();
        drop(m_signer_name);
        Self {
            rr_set: self.rr_set.clone(),
            sig_set: self.sig_set.clone(),
            state: Mutex::new(state),
            wildcard: Mutex::new(wildcard),
            signer_name: Mutex::new(signer_name),
        }
    }
}

#[derive(Debug)]
pub struct GroupList(Vec<Group>);

impl GroupList {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, rr: ParsedRecord<'_, Bytes>) {
        // Very simplistic implementation of add. Assume resource records
        // are mostly in order. If this O(n^2) algorithm is not enough,
        // then we should use a small hash table or sort first.
        if self.0.is_empty() {
            self.0.push(Group::new(rr));
            return;
        }
        let len = self.0.len();
        let res = self.0[len - 1].add(&rr);
        if res.is_ok() {
            return;
        }

        // Try all existing groups except the last one
        for g in &mut self.0[..len - 1] {
            let res = g.add(&rr);
            if res.is_ok() {
                return;
            }
        }

        // Add a new group.
        self.0.push(Group::new(rr));
    }

    pub fn remove_redundant_cnames(&mut self) {
        // todo!();
    }

    pub fn iter(&mut self) -> Iter<Group> {
        self.0.iter()
    }
}

#[derive(Debug)]
pub struct ValidatedGroup {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
    state: ValidationState,
    signer_name: Name<Bytes>,
    wildcard: Option<Name<Bytes>>,
    ede: Option<ExtendedError<Bytes>>,
}

impl ValidatedGroup {
    fn new(
        rr_set: Vec<RrType>,
        sig_set: Vec<SigType>,
        state: ValidationState,
        signer_name: Name<Bytes>,
        wildcard: Option<Name<Bytes>>,
        ede: Option<ExtendedError<Bytes>>,
    ) -> ValidatedGroup {
        ValidatedGroup {
            rr_set,
            sig_set,
            state,
            signer_name,
            wildcard,
            ede,
        }
    }

    pub fn class(&self) -> Class {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn owner(&self) -> Name<Bytes> {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn state(&self) -> ValidationState {
        self.state
    }

    pub fn signer_name(&self) -> Name<Bytes> {
        self.signer_name.clone()
    }

    pub fn wildcard(&self) -> Option<Name<Bytes>> {
        self.wildcard.clone()
    }

    pub fn ede(&self) -> Option<ExtendedError<Bytes>> {
        self.ede.clone()
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }
}

fn to_bytes_record(
    rr: &ParsedRecord<'_, Bytes>,
) -> Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>> {
    let record = rr.to_record::<AllRecordData<_, _>>().unwrap().unwrap();
    Record::<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>::new(
        rr.owner().try_to_name::<Bytes>().unwrap(),
        rr.class(),
        rr.ttl(),
        record.data().clone(),
    )
}
