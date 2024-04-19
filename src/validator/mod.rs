// Validator

#![cfg(feature = "net")]

use crate::base::Dname;
use crate::base::Message;
use bytes::Bytes;
//use crate::base::ParseRecordData;
use crate::base::iana::Class;
use crate::base::iana::OptRcode;
use crate::base::name::Label;
use crate::base::name::ToDname;
use crate::base::DnameBuilder;
use crate::base::ParsedDname;
use crate::base::Rtype;
use crate::dep::octseq::Octets;
//use crate::dep::octseq::OctetsInto;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::AllRecordData;
use crate::rdata::Nsec;
use context::ValidationContext;
//use group::Group;
use group::Group;
use group::GroupList;
use std::cmp::Ordering;
use std::fmt::Debug;
use types::Error;
use types::ValidationState;

pub async fn validate_msg<'a, Octs, Upstream>(
    msg: &'a Message<Octs>,
    vc: &ValidationContext<Upstream>,
) -> Result<ValidationState, Error>
where
    Octs: Clone + Debug + Octets + 'a,
    <Octs as Octets>::Range<'a>: Debug,
    Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
{
    // Convert to Bytes.
    let bytes = Bytes::copy_from_slice(msg.as_slice());
    let msg = Message::from_octets(bytes).unwrap();

    // First convert the Answer and Authority sections to lists of RR groups
    let mut answers = GroupList::new();
    for rr in msg.answer().unwrap() {
        answers.add(rr.unwrap());
    }
    let mut authorities = GroupList::new();
    for rr in msg.authority().unwrap() {
        authorities.add(rr.unwrap());
    }

    //println!("Answer groups: {answers:?}");
    //println!("Authority groups: {authorities:?}");

    // Get rid of redundant unsigned CNAMEs
    answers.remove_redundant_cnames();

    // Validate each group. We cannot use iter_mut because it requires a
    // reference with a lifetime that is too long.
    // Group can handle this by hiding the state behind a Mutex.
    match validate_groups(&mut answers, vc).await {
        Some(state) => return Ok(state),
        None => (),
    }
    match validate_groups(&mut authorities, vc).await {
        Some(state) => return Ok(state),
        None => (),
    }

    // We may need to update TTLs of signed RRsets

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
    let qname: Dname<Bytes> = question.qname().try_to_dname().unwrap();
    let qclass = question.qclass();
    let qtype = question.qtype();

    // A secure answer may actually be insecure if there is an insecure
    // CNAME or DNAME in the chain. Start by assume that secure is secure
    // and downgrade if required.
    let maybe_secure = ValidationState::Secure;

    let sname = do_cname_dname(qname, qclass, qtype, &mut answers);

    // For NOERROR, check if the answer is positive. Then extract the status
    // of the group and be done.
    // For NODATA first get the SOA, this determines if the proof of a
    // negative result is signed or not.
    if msg.opt_rcode() == OptRcode::NOERROR {
        let opt_state = get_answer_state(&sname, qclass, qtype, &mut answers);
        if let Some(state) = opt_state {
            return Ok(map_maybe_secure(state, maybe_secure));
        }
    }

    // For both NOERROR/NODATA and for NXDOMAIN we can first look at the SOA
    // record in the authority section. If there is no SOA, return bogus. If
    // there is one and the state is not secure, then return the state of the
    // SOA record.
    let signer_name = match get_soa_state(&sname, qclass, &mut authorities) {
        None => return Ok(ValidationState::Bogus), // No SOA, assume the worst.
        Some((state, signer_name)) => match state {
            ValidationState::Secure => signer_name, // Continue validation.
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => return Ok(state),
        },
    };

    if msg.opt_rcode() == OptRcode::NOERROR {
        // Try to prove that the name exists but the qtype doesn't. Start
        // with NSEC and assume the name exists.
        match nsec_for_nodata(&sname, &mut authorities, qtype, &signer_name) {
            NsecState::NoData => {
                return Ok(map_maybe_secure(
                    ValidationState::Secure,
                    maybe_secure,
                ))
            }
            NsecState::Nothing => (), // Try something else.
        }

        // Try to prove that the name does not exist and that a wildcard
        // exists but does not have the requested qtype.
        match nsec_for_nodata_wildcard(
            &sname,
            &mut authorities,
            qtype,
            &signer_name,
        ) {
            NsecState::NoData => {
                return Ok(map_maybe_secure(
                    ValidationState::Secure,
                    maybe_secure,
                ))
            }
            NsecState::Nothing => (), // Try something else.
        }

        todo!();
    }

    todo!();
}

fn do_cname_dname(
    qname: Dname<Bytes>,
    qclass: Class,
    _qtype: Rtype,
    groups: &mut GroupList,
) -> Dname<Bytes> {
    for g in groups.iter() {
        if g.class() != qclass {
            continue;
        }
        let rtype = g.rtype();
        if rtype != Rtype::CNAME && rtype != Rtype::DNAME {
            continue;
        }
        todo!();
    }

    qname
}

fn get_answer_state(
    qname: &Dname<Bytes>,
    qclass: Class,
    qtype: Rtype,
    groups: &mut GroupList,
) -> Option<ValidationState> {
    for g in groups.iter() {
        if g.class() != qclass {
            continue;
        }
        if g.rtype() != qtype {
            continue;
        }
        if g.owner() != qname {
            continue;
        }
        return Some(g.get_state().unwrap());
    }
    None
}

fn get_soa_state(
    qname: &Dname<Bytes>,
    qclass: Class,
    groups: &mut GroupList,
) -> Option<(ValidationState, Dname<Bytes>)> {
    for g in groups.iter() {
        println!("get_soa_state: trying {g:?} for {qname:?}");
        if g.class() != qclass {
            println!("get_soa_state: wrong class");
            continue;
        }
        if g.rtype() != Rtype::SOA {
            println!("get_soa_state: wrong type");
            continue;
        }
        if !qname.ends_with(&g.owner()) {
            println!(
                "get_soa_state: wrong name {qname:?} should end with {:?}",
                g.owner()
            );
            println!(
                "{:?}.ends_with({:?}): {:?}",
                qname,
                g.owner(),
                qname.ends_with(&g.owner())
            );
            println!(
                "{:?}.ends_with({:?}): {:?}",
                g.owner(),
                qname,
                g.owner().ends_with(&qname)
            );
            continue;
        }
        return Some((g.get_state().unwrap(), g.signer_name()));
    }
    None
}

async fn validate_groups<Upstream>(
    groups: &mut GroupList,
    vc: &ValidationContext<Upstream>,
) -> Option<ValidationState>
where
    Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
{
    for g in groups.iter() {
        //println!("Validating group {g:?}");
        let (state, wildcard, signer_name) = g.validate_with_vc(vc).await;
        if let ValidationState::Bogus = state {
            return Some(state);
        }
        g.set_state_wildcard_signer_name(state, wildcard, signer_name);
    }
    None
}

#[derive(Debug)]
enum NsecState {
    NoData,
    Nothing,
}

// Find an NSEC record for target that proves that no record that matches
// rtype exist.
//
// So we have two possibilities: we find an exact match for target and
// check the bitmap or we find target as an empty non-terminal.
fn nsec_for_nodata(
    target: &Dname<Bytes>,
    groups: &mut GroupList,
    rtype: Rtype,
    signer_name: &Dname<Bytes>,
) -> NsecState {
    for g in groups.iter() {
        let opt_nsec = get_checked_nsec(g, signer_name);
        let nsec = if let Some(nsec) = opt_nsec {
            nsec
        } else {
            continue;
        };

        let owner = g.owner();
        println!("nsec = {nsec:?}");
        if target.name_eq(&owner) {
            // Check the bitmap.
            let types = nsec.types();

            // Check for QTYPE.
            if types.contains(rtype) {
                // We didn't get a rtype RRset but the NSEC record proves
                // there is one. Complain.
                todo!();
            }

            // Avoid parent-side NSEC records. The parent-side record has NS
            // set but not SOA. With one exception, the DS record lives on the
            // parent side so there the check needs to be reversed.
            if rtype == Rtype::DS {
                if types.contains(Rtype::NS) && types.contains(Rtype::SOA) {
                    // This is an NSEC record from the child. Complain.
                    todo!();
                }
            } else {
                if types.contains(Rtype::NS) && !types.contains(Rtype::SOA) {
                    // This is an NSEC record from the parent. Complain.
                    todo!();
                }
            }

            // Anything else is a secure intermediate node.
            return NsecState::NoData;
        }

        // Check that target is in the range of the NSEC and that owner is a
        // prefix of the next_name.
        if target.name_cmp(&owner) == Ordering::Greater
            && target.name_cmp(nsec.next_name()) == Ordering::Less
            && nsec.next_name().ends_with(target)
        {
            return NsecState::NoData;
        }

        // No match, try the next one.
    }
    NsecState::Nothing
}

// Find an NSEC record for target that proves that the target does not
// exist. Then find an NSEC record for a wildcard that covers the target
// and check that nothing for rtype exists.
//
// So we have two possibilities: we find an exact match for the wildcard and
// check the bitmap or we find the wildcard as an empty non-terminal.
fn nsec_for_nodata_wildcard(
    target: &Dname<Bytes>,
    groups: &mut GroupList,
    rtype: Rtype,
    signer_name: &Dname<Bytes>,
) -> NsecState {
    let ce = match nsec_for_not_exists(target, groups, rtype, signer_name) {
        NsecNXState::DoesNotExist(ce) => ce,
        NsecNXState::Nothing => return NsecState::Nothing,
    };

    let mut star_name = DnameBuilder::new_bytes();
    star_name.append_label(Label::wildcard().as_ref());
    let star_name = star_name.append_origin(&ce).unwrap();
    nsec_for_nodata(&star_name, groups, rtype, signer_name)
}

#[derive(Debug)]
enum NsecNXState {
    DoesNotExist(Dname<Bytes>),
    Nothing,
}

// Find an NSEC record for target that proves that the target does not
// exist. Return the status and the closest encloser.
fn nsec_for_not_exists(
    target: &Dname<Bytes>,
    groups: &mut GroupList,
    rtype: Rtype,
    signer_name: &Dname<Bytes>,
) -> NsecNXState {
    for g in groups.iter() {
        let opt_nsec = get_checked_nsec(g, signer_name);
        let nsec = if let Some(nsec) = opt_nsec {
            nsec
        } else {
            continue;
        };

        println!("nsec_for_not_exists: trying group {g:?}");
        let owner = g.owner();

        if target.name_eq(&owner) {
            // We found an exact match. No need to keep looking.
            todo!();
        }

        // Check that target is in the range of the NSEC.
        if !(target.name_cmp(&owner) == Ordering::Greater
            && target.name_cmp(nsec.next_name()) == Ordering::Less)
        {
            // Not in this range.
            continue;
        }

        if nsec.next_name().ends_with(target) {
            // We found an empty non-terminal. No need to keep looking.
            todo!();
        }

        if target.ends_with(&owner) {
            // The owner name of this NSEC is a prefix of target. We need to
            // rule out delegations and DNAME.
            todo!();
        }

        // Get closest encloser.
        let ce = closest_encloser(target, &owner, &nsec);

        return NsecNXState::DoesNotExist(ce);
    }
    NsecNXState::Nothing
}

fn map_maybe_secure(
    result: ValidationState,
    maybe_secure: ValidationState,
) -> ValidationState {
    if let ValidationState::Secure = result {
        maybe_secure
    } else {
        result
    }
}

fn closest_encloser(
    target: &Dname<Bytes>,
    nsec_owner: &Dname<Bytes>,
    nsec: &Nsec<Bytes, ParsedDname<Bytes>>,
) -> Dname<Bytes> {
    // The closest encloser is the longer suffix of target that exists.
    // Both the owner and the nsec next_name exist. So we compute the
    // longest common suffix for target and each of them and return the longest
    // result.
    let mut owner_encloser = Dname::root(); // Assume the root if we can't find
                                            // anything.
    for n in nsec_owner.iter_suffixes() {
        if target.ends_with(&n) {
            owner_encloser = n;
            break;
        }
    }
    println!("found {owner_encloser:?}");

    let mut next_encloser: Dname<Bytes> = Dname::root(); // Assume the root if we can't find
                                                         // anything.
    for n in nsec.next_name().iter_suffixes() {
        if target.ends_with(&n) {
            next_encloser = n.to_dname();
            break;
        }
    }
    println!("found {next_encloser:?}");

    if owner_encloser.label_count() > next_encloser.label_count() {
        owner_encloser
    } else {
        next_encloser
    }
}

fn get_checked_nsec(
    group: &Group,
    signer_name: &Dname<Bytes>,
) -> Option<Nsec<Bytes, ParsedDname<Bytes>>> {
    if group.rtype() != Rtype::NSEC {
        return None;
    }

    let owner = group.owner();
    let rrs = group.rr_set();
    if rrs.len() != 1 {
        // There should be at most one NSEC record for a given owner name.
        // Ignore the entire RRset.
        println!("get_checked_nsec: line {}", line!());
        return None;
    }
    let AllRecordData::Nsec(nsec) = rrs[0].data() else {
        panic!("NSEC expected");
    };

    // Check if this group is secure.
    if let ValidationState::Secure = group.get_state().unwrap() {
    } else {
        return None;
    };

    // Check if the signer name matches the expected signer name.
    if group.signer_name() != signer_name {
        println!("get_checked_nsec: line {}", line!());
        return None;
    }

    // Rule out wildcard
    let opt_wildcard = group.wildcard();
    if let Some(closest_encloser) = opt_wildcard {
        // The signature is for a wildcard. Make sure that the owner name is
        // equal to the unexpanded wildcard.
        let mut star_name = DnameBuilder::new_bytes();
        star_name.append_label(Label::wildcard().as_ref());
        let star_name = star_name.append_origin(&closest_encloser).unwrap();
        println!("got star_name {star_name:?}");
        if owner != star_name {
            // The nsec is an expanded wildcard. Ignore.
            println!("get_checked_nsec: line {}", line!());
            todo!();
        }

        // Accept this nsec.
    }

    // All check pass, return NSEC record.
    Some(nsec.clone())
}

pub mod anchor;
pub mod context;
mod group;
pub mod types;
mod utilities;
