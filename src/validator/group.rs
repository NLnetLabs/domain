// Group of resource records and associated signatures.

// For lack of a better term we call this a group. RR set refers to just
// the resource records without the signatures.

use crate::base::Dname;
use bytes::Bytes;
//use crate::base::ParsedDname;
use crate::base::ParsedRecord;
//use crate::base::ParseRecordData;
use crate::base::iana::class::Class;
use crate::base::name::ToDname;
use crate::base::Record;
use crate::base::Rtype;
use crate::base::UnknownRecordData;
use crate::dep::octseq::Octets;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::rdata::AllRecordData;
use crate::rdata::Rrsig;
use std::fmt::Debug;
//use std::marker::PhantomData;
use std::slice::Iter;
//use std::slice::IterMut;
use super::context::ValidationContext;
use super::types::ValidationState;
use std::sync::Mutex;
use std::vec::Vec;

#[derive(Debug)]
pub struct Group {
    rr_set: Vec<Record<Dname<Bytes>, AllRecordData<Bytes, Dname<Bytes>>>>,
    sig_set: Vec<Record<Dname<Bytes>, Rrsig<Bytes, Dname<Bytes>>>>,
    state: Mutex<Option<ValidationState>>,
}

impl Group {
    fn new<'a, Octs>(rr: ParsedRecord<'a, Octs>) -> Self
    where
        Octs: Octets,
    {
        if rr.rtype() != Rtype::Rrsig {
            return Self {
                rr_set: vec![to_bytes_record(&rr)],
                sig_set: Vec::new(),
                state: Mutex::new(None),
            };
        }
        todo!();
    }

    fn add<'a, Octs>(&mut self, rr: &ParsedRecord<'a, Octs>) -> Result<(), ()>
    where
        Octs: Octets,
    {
        // First check owner. That is easier to do with a separate if
        // statement.
        if !self.rr_set.is_empty() {
            if self.rr_set[0].owner()
                != &rr.owner().to_dname::<Bytes>().unwrap()
            {
                return Err(());
            }
        } else {
            if self.sig_set[0].owner().to_dname::<Bytes>()
                != rr.owner().to_dname()
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

        if rr.rtype() == Rtype::Rrsig {
            let record = rr.to_record::<Rrsig<_, _>>().unwrap().unwrap();
            let rrsig = record.data();

            if curr_class == rr.class() && curr_rtype == rrsig.type_covered()
            {
                let rrsig: Rrsig<Bytes, Dname<Bytes>> =
                    Rrsig::<Bytes, Dname<Bytes>>::new(
                        rrsig.type_covered(),
                        rrsig.algorithm(),
                        rrsig.labels(),
                        rrsig.original_ttl(),
                        rrsig.expiration(),
                        rrsig.inception(),
                        rrsig.key_tag(),
                        rrsig.signer_name().to_dname::<Bytes>().unwrap(),
                        Bytes::copy_from_slice(rrsig.signature().as_ref()),
                    )
                    .unwrap();

                let record: Record<Dname<Bytes>, _> = Record::new(
                    record.owner().to_dname::<Bytes>().unwrap(),
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

    pub fn set_state(&self, state: ValidationState) {
        let mut m_state = self.state.lock().unwrap();
        *m_state = Some(state)
    }

    pub fn get_state(&self) -> Option<ValidationState> {
        let m_state = self.state.lock().unwrap();
        *m_state
    }

    pub fn name(&self) -> Dname<Bytes> {
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
        return self.sig_set[0].class();
    }

    pub fn rtype(&self) -> Rtype {
        if !self.rr_set.is_empty() {
            return self.rr_set[0].rtype();
        }

        // The type in sig_set is always Rrsig
        return Rtype::Rrsig;
    }

    pub fn validate_with_vc(
        &self,
        vc: &ValidationContext,
    ) -> ValidationState {
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
            return ValidationState::Insecure;
        }

        let target = if !self.sig_set.is_empty() {
            self.sig_set[0].owner()
        } else {
            self.rr_set[0].owner()
        };
        let node = vc.get_node(target);
        let state = node.validation_state();
        match state {
            ValidationState::Secure => (), // Continue validating
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => return state,
        }
        todo!();
    }
}

#[derive(Debug)]
pub struct GroupList(Vec<Group>);

impl GroupList {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add<'a, Octs>(&mut self, rr: ParsedRecord<'a, Octs>)
    where
        Octs: Octets,
    {
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

fn to_bytes_record<'a, Octs>(
    rr: &ParsedRecord<'a, Octs>,
) -> Record<Dname<Bytes>, AllRecordData<Bytes, Dname<Bytes>>>
where
    Octs: Octets,
    Octs::Range<'a>: Octets,
{
    let record = rr
        .to_record::<UnknownRecordData<Octs::Range<'a>>>()
        .unwrap()
        .unwrap();
    //Record::<Dname<Bytes>, Bytes>::new(rr.owner().to_dname::<Bytes>().unwrap(), rr.class(), rr.ttl(), rr.data())
    let unknown_rd: UnknownRecordData<Bytes> =
        UnknownRecordData::from_octets(
            record.rtype(),
            Bytes::copy_from_slice(record.data().data().as_ref()),
        )
        .unwrap();
    let all_rd: AllRecordData<Bytes, Dname<Bytes>> =
        AllRecordData::from(unknown_rd);
    Record::<Dname<Bytes>, AllRecordData<Bytes, Dname<Bytes>>>::new(
        rr.owner().to_dname::<Bytes>().unwrap(),
        rr.class(),
        rr.ttl(),
        all_rd,
    )
}
