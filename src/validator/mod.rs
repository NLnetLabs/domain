// Validator

#![cfg(feature = "net")]

use crate::base::Name;
use crate::base::Message;
use bytes::Bytes;
//use crate::base::ParseRecordData;
use crate::base::iana::Class;
use crate::base::iana::OptRcode;
use crate::base::opt::ExtendedError;
//use crate::base::name::Label;
use crate::base::name::ToName;
//use crate::base::scan::IterScanner;
//use crate::base::NameBuilder;
use crate::base::ParsedName;
use crate::base::Rtype;
use crate::dep::octseq::Octets;
//use crate::dep::octseq::OctetsInto;
//use crate::dep::octseq::OctetsFrom;
//use crate::dep::octseq::OctetsInto;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::nsec3::OwnerHash;
use crate::rdata::AllRecordData;
use crate::rdata::Nsec;
use crate::rdata::Nsec3;
use context::ValidationContext;
//use group::Group;
use group::GroupList;
use group::ValidatedGroup;
use nsec::nsec3_hash;
use nsec::nsec3_in_range;
use nsec::nsec3_label_to_hash;
use nsec::star_closest_encloser;
use nsec::NSEC3_ITER_BOGUS;
use nsec::NSEC3_ITER_INSECURE;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt::Debug;
//use std::str;
//use std::str::FromStr;
//use std::string::ToString;
use std::vec::Vec;
use types::Error;
use types::ValidationState;

// On success, return the validation state and an optionally an extended DNS
// error.
pub async fn validate_msg<'a, Octs, Upstream>(
    msg: &'a Message<Octs>,
    vc: &ValidationContext<Upstream>,
) -> Result<(ValidationState, Option<ExtendedError<Bytes>>), Error>
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
    let mut answers = match validate_groups(&mut answers, vc).await {
        Ok(vgs) => vgs,
        Err(ValidationState::Bogus) => {
            todo!(); // Handle EDE
                     // return Ok(ValidationState::Bogus),
        }
        Err(_) => panic!("Invalid ValidationState"),
    };

    let mut authorities = match validate_groups(&mut authorities, vc).await {
        Ok(vgs) => vgs,
        Err(ValidationState::Bogus) => {
            todo!(); // Handle EDE
                     // return Ok(ValidationState::Bogus),
        }
        Err(_) => panic!("Invalid ValidationState"),
    };

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
    let qname: Name<Bytes> = question.qname().try_to_name().unwrap();
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
        if let Some((state, wildcard, ede)) = opt_state {
            if state != ValidationState::Secure || wildcard.is_none() {
                // No need to check the wildcard, either because the state is
                // not secure or because there is no wildcard.
                return Ok((map_maybe_secure(state, maybe_secure), ede));
            }
            todo!(); // wildcard
        }
    }

    // For both NOERROR/NODATA and for NXDOMAIN we can first look at the SOA
    // record in the authority section. If there is no SOA, return bogus. If
    // there is one and the state is not secure, then return the state of the
    // SOA record.
    let signer_name = match get_soa_state(&sname, qclass, &mut authorities) {
        None => {
            todo!(); // EDE
                     // return Ok(ValidationState::Bogus), // No SOA, assume the worst.
        }
        Some((state, signer_name)) => match state {
            ValidationState::Secure => signer_name, // Continue validation.
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                todo!(); // EDE
                         // return Ok(state),
            }
        },
    };

    println!("rcode = {:?}", msg.opt_rcode());
    if msg.opt_rcode() == OptRcode::NOERROR {
        // Try to prove that the name exists but the qtype doesn't. Start
        // with NSEC and assume the name exists.
        match nsec_for_nodata(&sname, &mut authorities, qtype, &signer_name) {
            NsecState::NoData => {
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    None,
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
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    None,
                ))
            }
            NsecState::Nothing => (), // Try something else.
        }

        // Try to prove that the name exists but the qtype doesn't. Continue
        // with NSEC3 and assume the name exists.
        match nsec3_for_nodata(&sname, &mut authorities, qtype, &signer_name)
        {
            NsecState::NoData => {
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    None,
                ))
            }
            NsecState::Nothing => (), // Try something else.
        }

        // RFC 5155, Section 8.6. If there is a closest encloser and
        // the NSEC3 RR that covers the "next closer" name has the Opt-Out
        // bit set then we have an insecure proof that the DS record does
        // not exist.
        // Then Errata 3441 says that we need to do the same thing for other
        // types.
        let ce = match nsec3_for_not_exists(
            &sname,
            &mut authorities,
            qtype,
            &signer_name,
        ) {
            Nsec3NXState::DoesNotExist(ce) => ce, // Continue with wildcard.
            Nsec3NXState::DoesNotExistInsecure(_) => {
                // Something might exist. Just return insecure here.
                todo!(); // EDE
                         // return Ok(ValidationState::Insecure);
            }
            Nsec3NXState::Nothing => todo!(), // We reached the end, return bogus.
        };

        let star_name = star_closest_encloser(&ce);
        match nsec3_for_nodata(
            &star_name,
            &mut authorities,
            qtype,
            &signer_name,
        ) {
            NsecState::NoData => {
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    None,
                ));
            }
            NsecState::Nothing => todo!(), // We reached the end, return bogus.
        }

        todo!();
    }

    // Prove NXDOMAIN.
    // Try to prove that the name does not exist using NSEC.
    match nsec_for_nxdomain(&sname, &mut authorities, qtype, &signer_name) {
        NsecNXState::DoesNotExist(_) => {
            return Ok((
                map_maybe_secure(ValidationState::Secure, maybe_secure),
                None,
            ))
        }
        NsecNXState::Nothing => (), // Try something else.
    }

    // Try to prove that the name does not exist using NSEC3.
    match nsec3_for_nxdomain(&sname, &mut authorities, qtype, &signer_name) {
        Nsec3NXState::DoesNotExist(_) => {
            return Ok((
                map_maybe_secure(ValidationState::Secure, maybe_secure),
                None,
            ))
        }
        Nsec3NXState::DoesNotExistInsecure(_) => {
            todo!(); // EDE
                     // return Ok(ValidationState::Insecure);
        }
        Nsec3NXState::Nothing => (), // Try something else.
    }

    todo!();
}

fn do_cname_dname(
    qname: Name<Bytes>,
    qclass: Class,
    _qtype: Rtype,
    groups: &mut Vec<ValidatedGroup>,
) -> Name<Bytes> {
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
    qname: &Name<Bytes>,
    qclass: Class,
    qtype: Rtype,
    groups: &mut Vec<ValidatedGroup>,
) -> Option<(
    ValidationState,
    Option<Name<Bytes>>,
    Option<ExtendedError<Bytes>>,
)> {
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
        return Some((g.state(), g.wildcard(), g.ede()));
    }
    None
}

fn get_soa_state(
    qname: &Name<Bytes>,
    qclass: Class,
    groups: &mut Vec<ValidatedGroup>,
) -> Option<(ValidationState, Name<Bytes>)> {
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
        return Some((g.state(), g.signer_name()));
    }
    None
}

async fn validate_groups<Upstream>(
    groups: &mut GroupList,
    vc: &ValidationContext<Upstream>,
) -> Result<Vec<ValidatedGroup>, ValidationState>
where
    Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
{
    let mut vgs = Vec::new();
    for g in groups.iter() {
        //println!("Validating group {g:?}");
        let (state, signer_name, wildcard, ede) =
            g.validate_with_vc(vc).await;
        if let ValidationState::Bogus = state {
            return Err(state);
        }
        vgs.push(g.validated(state, signer_name, wildcard, ede));
    }
    Ok(vgs)
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
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
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
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> NsecState {
    let ce = match nsec_for_not_exists(target, groups, signer_name) {
        NsecNXState::DoesNotExist(ce) => ce,
        NsecNXState::Nothing => return NsecState::Nothing,
    };

    let star_name = star_closest_encloser(&ce);
    nsec_for_nodata(&star_name, groups, rtype, signer_name)
}

#[derive(Debug)]
enum NsecNXState {
    DoesNotExist(Name<Bytes>),
    Nothing,
}

// Find an NSEC record for target that proves that the target does not
// exist. Return the status and the closest encloser.
fn nsec_for_not_exists(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
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
            let types = nsec.types();
            if types.contains(Rtype::DNAME)
                || (types.contains(Rtype::NS) && !types.contains(Rtype::SOA))
            {
                // This NSEC record cannot prove non-existance.
                todo!();
            }
        }

        // Get closest encloser.
        let ce = closest_encloser(target, &owner, &nsec);

        return NsecNXState::DoesNotExist(ce);
    }
    NsecNXState::Nothing
}

// Find an NSEC record for target that proves that the target does not
// exist. Then find an NSEC record that proves that the wildcard also does
// not exist.
fn nsec_for_nxdomain(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> NsecNXState {
    let ce = match nsec_for_not_exists(target, groups, signer_name) {
        NsecNXState::DoesNotExist(ce) => ce,
        NsecNXState::Nothing => return NsecNXState::Nothing,
    };

    let star_name = star_closest_encloser(&ce);
    nsec_for_not_exists(&star_name, groups, signer_name)
}

// Find an NSEC3 record for target that proves that no record that matches
// rtype exist. There is only one option: find an NSEC3 record that has an
// owner name where the first label match the NSEC3 hash of target and then
// check the bitmap.
fn nsec3_for_nodata(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> NsecState {
    for g in groups.iter() {
        let opt_nsec3_hash = get_checked_nsec3(g, signer_name);
        let (nsec3, ownerhash) = if let Some(nsec3_hash) = opt_nsec3_hash {
            nsec3_hash
        } else {
            continue;
        };

        // Create the hash with the parameters in this record. We should cache
        // the hash.
        let hash = nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            nsec3.iterations(),
            nsec3.salt(),
        );

        println!("got hash {hash:?} and ownerhash {ownerhash:?}");

        if ownerhash == hash {
            // We found an exact match.

            // Check the bitmap.
            let types = nsec3.types();

            // Check for QTYPE.
            if types.contains(rtype) {
                // We didn't get a rtype RRset but the NSEC3 record proves
                // there is one. Complain.
                todo!();
            }

            // Avoid parent-side NSEC3 records. The parent-side record has NS
            // set but not SOA. With one exception, the DS record lives on the
            // parent side so there the check needs to be reversed.
            if rtype == Rtype::DS {
                if types.contains(Rtype::NS) && types.contains(Rtype::SOA) {
                    // This is an NSEC3 record from the child. Complain.
                    todo!();
                }
            } else {
                if types.contains(Rtype::NS) && !types.contains(Rtype::SOA) {
                    // This is an NSEC3 record from the parent. Complain.
                    todo!();
                }
            }

            return NsecState::NoData;
        }

        // No match, try the next one.
    }
    NsecState::Nothing
}

#[derive(Debug)]
enum Nsec3State {
    NoData,
    NoDataInsecure,
    Nothing,
}

// Find a closest encloser target and then find an NSEC3 record for the
// wildcard that proves that no record that matches
// rtype exist.
fn nsec3_for_nodata_wildcard(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> Nsec3State {
    let (ce, secure) =
        match nsec3_for_not_exists(target, groups, rtype, signer_name) {
            Nsec3NXState::DoesNotExist(ce) => (ce, true),
            Nsec3NXState::DoesNotExistInsecure(ce) => (ce, false),
            Nsec3NXState::Nothing => return Nsec3State::Nothing,
        };

    let star_name = star_closest_encloser(&ce);
    match nsec3_for_nodata(&star_name, groups, rtype, signer_name) {
        NsecState::NoData => {
            if secure {
                Nsec3State::NoData
            } else {
                Nsec3State::NoDataInsecure
            }
        }
        NsecState::Nothing => Nsec3State::Nothing,
    }
}

#[derive(Debug)]
enum Nsec3NXState {
    DoesNotExist(Name<Bytes>),
    DoesNotExistInsecure(Name<Bytes>),
    Nothing,
}

// Prove that target does not exist using NSEC3 records. Return the status
// and the closest encloser.
fn nsec3_for_not_exists(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> Nsec3NXState {
    println!("nsec3_for_not_exists: proving {target:?} does not exist");

    // We assume the target does not exist and the signer_name does exist.
    // Starting from signer_name and going towards target we check if a name
    // exists or not. We assume signer_name exists. If we find a name that
    // does not exist but the parent name does, then the name that does
    // exist is the closes encloser.
    let mut names = VecDeque::new();
    for n in target.iter_suffixes() {
        if !n.ends_with(signer_name) {
            break;
        }
        names.push_front(n);
    }

    let mut maybe_ce = signer_name.clone();
    let mut maybe_ce_exists = false;
    'next_name: for n in names {
        println!("nsec3_for_not_exists: trying name {n:?}");
        if n == signer_name {
            println!("nsec3_for_not_exists: signer_name");
            maybe_ce = n;
            maybe_ce_exists = true;
            continue;
        }

        // Check whether the name exists, or is proven to not exist.
        for g in groups.iter() {
            let opt_nsec3_hash = get_checked_nsec3(g, signer_name);
            let (nsec3, ownerhash) = if let Some(nsec3_hash) = opt_nsec3_hash
            {
                nsec3_hash
            } else {
                continue;
            };

            // Create the hash with the parameters in this record. We should
            // cache the hash.
            let hash = nsec3_hash(
                &n,
                nsec3.hash_algorithm(),
                nsec3.iterations(),
                nsec3.salt(),
            );

            println!("got hash {hash:?} and ownerhash {ownerhash:?}");

            if ownerhash == hash {
                // We found an exact match.

                // RFC 5155, Section 8.3, Point 3: the DNAME type bit
                // must not be set and the NS type bit may only be set if the
                // SOA type bit is set.
                let types = nsec3.types();
                if types.contains(Rtype::DNAME)
                    || (types.contains(Rtype::NS)
                        && !types.contains(Rtype::SOA))
                {
                    // Name or delegation. What do we do?
                    todo!();
                }
                println!("nsec3_for_not_exists: found match");
                maybe_ce = n;
                maybe_ce_exists = true;
                continue 'next_name;
            }

            // Check if target is between the hash in the first label and the
            // next_owner field.
            println!(
                "nsec3_for_not_exists: range {ownerhash:?}..{:?}",
                nsec3.next_owner()
            );
            if nsec3_in_range(hash, ownerhash, nsec3.next_owner()) {
                println!("nsec3_for_not_exists: found not exist");

                // We found a name that does not exist. Do we have a candidate
                // closest encloser?
                if maybe_ce_exists {
                    // Yes.

                    if nsec3.opt_out() {
                        // Results based on an opt_out record are insecure.
                        return Nsec3NXState::DoesNotExistInsecure(maybe_ce);
                    }

                    return Nsec3NXState::DoesNotExist(maybe_ce);
                }

                // No. And this one doesn't exist either.
                maybe_ce_exists = false;
                continue 'next_name;
            }

            // No match, try the next one.
        }

        // We didn't find a match. Clear maybe_ce_exists and move on with the
        // next name.
        maybe_ce_exists = false;
    }

    todo!();
}

#[derive(Debug)]
enum Nsec3NXStateNoCE {
    DoesNotExist,
    DoesNotExistInsecure,
    Nothing,
}

// Prove that target does not exist using NSEC3 records. Assume that
// the closest encloser is already know and that we only have to check
// this specific name. This is typically used to prove that a wildcard does
// not exist.
fn nsec3_for_not_exists_no_ce(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> Nsec3NXStateNoCE {
    println!("nsec3_for_not_exists_no_ce: proving {target:?} does not exist");

    // Check whether the name exists, or is proven to not exist.
    for g in groups.iter() {
        let opt_nsec3_hash = get_checked_nsec3(g, signer_name);
        let (nsec3, ownerhash) = if let Some(nsec3_hash) = opt_nsec3_hash {
            nsec3_hash
        } else {
            continue;
        };

        // Create the hash with the parameters in this record. We should
        // cache the hash.
        let hash = nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            nsec3.iterations(),
            nsec3.salt(),
        );

        println!("got hash {hash:?} and ownerhash {ownerhash:?}");

        // Check if target is between the hash in the first label and the
        // next_owner field.
        println!(
            "nsec3_for_not_exists_no_ce: range {ownerhash:?}..{:?}",
            nsec3.next_owner()
        );
        if nsec3_in_range(hash, ownerhash, nsec3.next_owner()) {
            println!("nsec3_for_not_exists: found not exist");

            // We found a name that does not exist.
            if nsec3.opt_out() {
                // Results based on an opt_out record are insecure.
                return Nsec3NXStateNoCE::DoesNotExistInsecure;
            }

            return Nsec3NXStateNoCE::DoesNotExist;
        }

        // No match, try the next one.
    }

    todo!();
}

// Find a closest encloser for target and then find an NSEC3 record that proves
// that tthe wildcard does not exist.
// rtype exist.
fn nsec3_for_nxdomain(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> Nsec3NXState {
    let (ce, secure) =
        match nsec3_for_not_exists(target, groups, rtype, signer_name) {
            Nsec3NXState::DoesNotExist(ce) => (ce, true),
            Nsec3NXState::DoesNotExistInsecure(ce) => (ce, false),
            Nsec3NXState::Nothing => return Nsec3NXState::Nothing,
        };

    let star_name = star_closest_encloser(&ce);
    match nsec3_for_not_exists_no_ce(&star_name, groups, rtype, signer_name) {
        Nsec3NXStateNoCE::DoesNotExist => {
            if secure {
                Nsec3NXState::DoesNotExist(ce)
            } else {
                Nsec3NXState::DoesNotExistInsecure(ce)
            }
        }
        Nsec3NXStateNoCE::DoesNotExistInsecure => {
            Nsec3NXState::DoesNotExistInsecure(ce)
        }
        Nsec3NXStateNoCE::Nothing => return Nsec3NXState::Nothing,
    }
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
    target: &Name<Bytes>,
    nsec_owner: &Name<Bytes>,
    nsec: &Nsec<Bytes, ParsedName<Bytes>>,
) -> Name<Bytes> {
    // The closest encloser is the longer suffix of target that exists.
    // Both the owner and the nsec next_name exist. So we compute the
    // longest common suffix for target and each of them and return the longest
    // result.
    let mut owner_encloser = Name::root(); // Assume the root if we can't find
                                            // anything.
    for n in nsec_owner.iter_suffixes() {
        if target.ends_with(&n) {
            owner_encloser = n;
            break;
        }
    }
    println!("found {owner_encloser:?}");

    let mut next_encloser: Name<Bytes> = Name::root(); // Assume the root if we can't find
                                                         // anything.
    for n in nsec.next_name().iter_suffixes() {
        if target.ends_with(&n) {
            next_encloser = n.to_name();
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
    group: &ValidatedGroup,
    signer_name: &Name<Bytes>,
) -> Option<Nsec<Bytes, ParsedName<Bytes>>> {
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
    if let ValidationState::Secure = group.state() {
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
        let star_name = star_closest_encloser(&closest_encloser);
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

fn get_checked_nsec3(
    group: &ValidatedGroup,
    signer_name: &Name<Bytes>,
) -> Option<(Nsec3<Bytes>, OwnerHash<Vec<u8>>)> {
    let rrs = group.rr_set();
    if rrs.len() != 1 {
        // There should be at most one NSEC3 record for a given owner name.
        // Ignore the entire RRset.
        println!("get_checked_nsec3: line {}", line!());
        return None;
    }
    let AllRecordData::Nsec3(nsec3) = rrs[0].data() else {
        return None;
    };

    // Check if this group is secure.
    if let ValidationState::Secure = group.state() {
    } else {
        return None;
    };

    // Check if the signer name matches the expected signer name.
    if group.signer_name() != signer_name {
        println!("get_checked_nsec3: line {}", line!());
        return None;
    }

    let iterations = nsec3.iterations();

    // See RFC 9276, Appendix A for a recommendation on the maximum number
    // of iterations.
    if iterations > NSEC3_ITER_INSECURE || iterations > NSEC3_ITER_BOGUS {
        // High iteration count, abort.
        todo!();
    }

    // Convert first label to hash. Skip this NSEC3 record if that fails.
    let ownerhash = nsec3_label_to_hash(group.owner().first());

    // Check if the length of ownerhash matches to length in next_hash.
    // Otherwise, skip the NSEC3 record.
    if ownerhash.as_slice().len() != nsec3.next_owner().as_slice().len() {
        return None;
    }

    // All check pass, return the NSEC3 record and the owner hash.
    Some((nsec3.clone(), ownerhash))
}

pub mod anchor;
pub mod context;
mod group;
mod nsec;
pub mod types;
mod utilities;
