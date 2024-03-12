// Validator

use bytes::Bytes;
use crate::base::Dname;
use crate::base::Message;
use crate::base::ParsedDname;
use crate::base::Rtype;
use crate::base::iana::Class;
use crate::base::iana::OptRcode::NoError;
use crate::base::name::ToDname;
use crate::dep::octseq::Octets;
use context::ValidationContext;
use group::Group;
use group::GroupList;
use std::fmt::Debug;
use types::Error;
use types::ValidationState;

pub fn validate_msg<'a, Octs>(msg: &Message<Octs>, vc: &ValidationContext) ->
	Result<ValidationState, Error>
where Octs: Clone + Debug + Octets + 'a,
	<Octs as Octets>::Range<'a>: Debug
{
    // First convert the Answer and Authority sections to lists of RR groups
    let mut answers = GroupList::<Dname<Octs>, _>::new();
    for rr in msg.answer().unwrap() {
	answers.add(rr.unwrap());
    }
    let mut authorities = GroupList::<Dname<Octs>, _>::new();
    for rr in msg.authority().unwrap() {
	authorities.add(rr.unwrap());
    }

    println!("Answer groups: {answers:?}");
    println!("Authority groups: {authorities:?}");

    // Get rid of redundant unsigned CNAMEs
    answers.remove_redundant_cnames();

    // Validate each group. We cannot use iter_mut because something gets
    // confused about mutable borrows. Group can handle this by hiding the
    // state behind a Mutex.
    for g in answers.iter() {
	println!("Validating group {g:?}");
	let state = g.validate_with_vc(vc);
	if let ValidationState::Bogus = state {
	    return Ok(state);
	}
	g.set_state(state);
    }
    for g in authorities.iter() {
	println!("Validating group {g:?}");
	todo!();
	//g.validate_with_vc();
    }

    // Go through the answers and use CNAME and DNAME records to update 'SNAME'
    // (see RFC 1034, Section 5.3.2) to the final name that results in an
    // answer, NODATA, or NXDOMAIN. First extract QNAME/QCLASS/QTYPE. Require
    // that the question section has only one entry. Return FormError if that
    // is not the case (following draft-bellis-dnsop-qdcount-is-one-00)

    // Extract Qname, Qclass, Qtype
    let mut question_section = msg.question();
    let question = match question_section.next() {
	None => {
	    return Err(Error::FormError);
	}
	Some(question) => question?,
    };
    if question_section.next().is_some() {
	return Err(Error::FormError);
    }
    let qname: Dname<Bytes> = question.qname().to_dname().unwrap();
    let qclass = question.qclass();
    let qtype = question.qtype();

    let sname = do_cname_dname(qname, qclass, qtype, &mut answers);

    // For NOERROR, check if the answer is positive. Then extract the status
    // of the group and be done.
    // For NODATA first get the SOA, this determines if the proof of a
    // negative result is signed or not.
    if let NoError = msg.opt_rcode() {
	let opt_group = get_answer(sname, qclass, qtype, &mut answers);
	if let Some(group) = opt_group {
	    return Ok(group.get_state().unwrap());
	}
    }
    todo!();
}

fn do_cname_dname<Name, Octs>(qname: Dname<Bytes>, qclass: Class, qtype: Rtype, groups: &mut GroupList<Name, Octs>) -> Dname<Bytes>
where Octs: Clone + Debug + Octets,
	Name: ToDname,
{
    for g in groups.iter() {
	if g.class() != qclass {
	    continue;
	}
	let rtype = g.rtype();
	if rtype != Rtype::Cname && rtype != Rtype::Dname {
	    continue;
	}
	todo!();
    }

    qname
}

fn get_answer<'a, Name, Octs>(qname: Dname<Bytes>, qclass: Class, qtype: Rtype, groups: &'a mut GroupList<'a, Name, Octs>) -> Option<&'a Group<'a, Name, Octs>>
where Octs: Clone + Debug + Octets,
	Name: ToDname
{
    for g in groups.iter() {
	if g.class() != qclass {
	    continue;
	}
	if g.rtype() != qtype {
	    continue;
	}
	if g.name() != qname {
	    continue;
	}
	return Some(g);
    }
    None
}

pub mod anchor;
pub mod context;
mod group;
pub mod types;
