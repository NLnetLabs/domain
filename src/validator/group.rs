// Group of resource records and associated signatures.

// For lack of a better term we call this a group. RR set refers to just
// the resource records without the signatures.

use crate::base::ParsedRecord;
use crate::base::Record;
use crate::base::Rtype;
use crate::dep::octseq::Octets;
use std::fmt::Debug;
use std::slice::Iter;
use std::vec::Vec;
use super::types::ValidationState;
use super::context::ValidationContext;

#[derive(Debug)]
pub struct Group<'a, Name, Octs>
where Octs: Debug + Octets
{
	rr_set: Vec<ParsedRecord<'a, Octs>>,
	sig_set: Vec<Record<Name, Octs>>,
}

impl<'a, Name, Octs> Group<'a, Name, Octs>
where Octs: Clone + Debug + Octets {
	fn new(rr: ParsedRecord<'a, Octs>) -> Self
	where Octs: Octets,
	{
		if rr.rtype() != Rtype::Rrsig {
		    return Self { rr_set: vec![rr],
			sig_set: Vec::new() };
		}
		todo!();
	}

	fn add(&mut self, rr: &ParsedRecord<'a, Octs>) -> Result<(), ()> {
	    if rr.rtype() == Rtype::Rrsig {
		todo!();
	    }

	    // We can add rr if owner, class and rtype match.
	    if self.rr_set[0].owner() == rr.owner() &&
		self.rr_set[0].class() == rr.class() &&
		self.rr_set[0].rtype() == rr.rtype() {
		self.rr_set.push(rr.clone());
		return Ok(());
	    }

	    // No match.
	    Err(())
	}

	pub fn validate_with_vc(&self, vc: &ValidationContext) -> ValidationState {
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
		todo!();
	    } else
	    {
		self.rr_set[0].owner()
	    };
	    let node = vc.get_node(&target);
	    todo!();
	}
}

#[derive(Debug)]
pub struct GroupList<'a, Name, Octs>(Vec<Group<'a, Name, Octs>>)
where Octs: Debug + Octets;

impl<'a, Name, Octs> GroupList<'a, Name, Octs>
where Octs: Clone + Debug + Octets
{
	pub fn new() -> Self {
		Self(Vec::new())
	}

	pub fn add(&mut self, rr: ParsedRecord<'a, Octs>)
	{
	    // Very simplistic implementation of add. Assume resource records 
	    // are mostly in order. If this O(n^2) algorithm is not enough,
	    // then we should use a small hash table or sort first.
	    if self.0.is_empty() {
		self.0.push(Group::new(rr));
		return;
	    }
	    let len = self.0.len();
	    let res = self.0[len-1].add(&rr);
	    if res.is_ok() {
		return;
	    }
	    
	    // Try all existing groups except the last one
	    for g in &mut self.0[..len-1] {
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

	pub fn iter(&mut self) -> Iter<Group<Name, Octs>> {
		self.0.iter()
	}
}

