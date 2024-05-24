use crate::base::Name;
use crate::base::NameBuilder;
use crate::base::ParsedName;
use crate::base::Record;
use crate::base::Rtype;
use crate::base::ToName;
use crate::base::iana::Class;
use crate::base::iana::ExtendedErrorCode;
use crate::base::name::Label;
use crate::base::opt::ExtendedError;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::Dname;
use crate::rdata::Rrsig;
use crate::rdata::AllRecordData;
use bytes::Bytes;
use std::cmp::min;
use std::time::Duration;
use std::vec::Vec;
use super::group::ValidatedGroup;
use super::nsec::nsec_for_not_exists;
use super::nsec::NsecNXState;
use super::nsec::nsec3_for_not_exists_no_ce;
use super::nsec::Nsec3Cache;
use super::nsec::Nsec3NXStateNoCE;
use super::types::ValidationState;

// Maximum number of CNAME or DNAME records used for in answer.
const MAX_CNAME_DNAME: u8 = 12;

pub async fn do_cname_dname(
    qname: Name<Bytes>,
    qclass: Class,
    qtype: Rtype,
    answers: &mut Vec<ValidatedGroup>,
    authorities: &mut Vec<ValidatedGroup>,
    nsec3_cache: &Nsec3Cache,
) -> (Name<Bytes>, ValidationState, Option<ExtendedError<Bytes>>) {
    let mut name = qname;
    let mut count = 0;
    let mut maybe_secure = ValidationState::Secure;
    'name_loop: loop {
        for g in answers.iter() {
            if g.class() != qclass {
                continue;
            }
            let rtype = g.rtype();
            if rtype != Rtype::CNAME && rtype != Rtype::DNAME {
                continue;
            }
            if rtype == Rtype::CNAME && rtype == qtype {
                // A CNAME requested, do not process them here.
                continue;
            }

            let rr_set = g.rr_set();
            if rr_set.len() != 1 {
                todo!(); // Just return bogus?
            }

            if let AllRecordData::Cname(cname) = rr_set[0].data() {
                if g.owner() != name {
                    continue;
                }
                if let Some(ce) = g.closest_encloser() {
                    let (check, state, _ede) = check_not_exists_for_wildcard(
                        &name,
                        qtype,
                        authorities,
                        &g.signer_name(),
                        &ce,
                        nsec3_cache,
                    )
                    .await;
                    if check {
                        maybe_secure = map_maybe_secure(state, maybe_secure);
                    // Just continue.
                    } else {
                        // Report failure
                        todo!();
                    }
                }
                name = cname.cname().to_name();
                maybe_secure = map_maybe_secure(g.state(), maybe_secure);
                count += 1;
                if count > MAX_CNAME_DNAME {
                    let ede = Some(
                        ExtendedError::new_with_str(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "CNAME loop",
                        )
                        .unwrap(),
                    );
                    return (name, ValidationState::Bogus, ede);
                }
                continue 'name_loop;
            }

            if let AllRecordData::Dname(dname) = rr_set[0].data() {
                let owner = g.owner();
                if !name.ends_with(&owner) {
                    // This DNAME record is not suitable for the current name.
                    continue;
                }
                if owner == name {
                    // It cannot be an exact match.
                    continue;
                }

                if let Some(_ce) = g.closest_encloser() {
                    // wildcard DNAMEs are undefined.
                    todo!();
                }

                name = map_dname(&owner, dname, &name);
                maybe_secure = map_maybe_secure(g.state(), maybe_secure);
                count += 1;
                if count > MAX_CNAME_DNAME {
                    todo!();
                }
                continue 'name_loop;
            }

            todo!();
        }

        // No match CNAME or DNAME found.
        break;
    }

    (name, maybe_secure, None)
}

pub fn map_dname(
    owner: &Name<Bytes>,
    dname: &Dname<ParsedName<Bytes>>,
    name: &Name<Bytes>,
) -> Name<Bytes> {
    println!("map_dname: for name {name:?}, dname owner {owner:?}");
    let mut tmp_name = name.clone();
    let mut new_name = NameBuilder::new_bytes();
    let owner_labels = owner.label_count();
    while tmp_name.label_count() > owner_labels {
        println!("adding label {:?}", tmp_name.first());
        new_name.append_label(tmp_name.first().as_slice()).unwrap();
        tmp_name = tmp_name.parent().unwrap();
    }
    let name = new_name.append_origin(dname.dname()).unwrap();
    println!("Now at {:?}", name);
    name
}

pub fn ttl_for_sig(
    sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
) -> Duration {
    let ttl = sig.ttl().into_duration();
    println!("ttl_for_sig: record ttl {ttl:?}");
    let orig_ttl = sig.data().original_ttl().into_duration();
    let ttl = min(ttl, orig_ttl);
    println!("with orig_ttl {orig_ttl:?}, new ttl {ttl:?}");

    let until_expired =
        sig.data().expiration().into_int() - Timestamp::now().into_int();
    let expire_duration = Duration::from_secs(until_expired as u64);
    let ttl = min(ttl, expire_duration);

    println!("with until_expired {until_expired:?}, ttl {ttl:?}");

    ttl
}

pub fn get_answer_state(
    qname: &Name<Bytes>,
    qclass: Class,
    qtype: Rtype,
    groups: &mut Vec<ValidatedGroup>,
) -> Option<(
    ValidationState,
    Name<Bytes>,
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
        return Some((
            g.state(),
            g.signer_name(),
            g.closest_encloser(),
            g.ede(),
        ));
    }
    None
}

pub fn get_soa_state(
    qname: &Name<Bytes>,
    qclass: Class,
    groups: &mut Vec<ValidatedGroup>,
) -> (
    Option<(ValidationState, Name<Bytes>)>,
    Option<ExtendedError<bytes::Bytes>>,
) {
    let mut ede = None;
    for g in groups.iter() {
        println!("get_soa_state: trying {g:?} for {qname:?}");
        if g.class() != qclass {
            println!("get_soa_state: wrong class");
            todo!(); // EDE
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
            todo!(); // EDE
            continue;
        }
        return (Some((g.state(), g.signer_name())), g.ede());
    }
    (None, ede)
}

pub fn map_maybe_secure(
    result: ValidationState,
    maybe_secure: ValidationState,
) -> ValidationState {
    if let ValidationState::Secure = result {
        maybe_secure
    } else {
        result
    }
}

fn get_child_of_ce(target: &Name<Bytes>, ce: &Name<Bytes>) -> Name<Bytes> {
    let ce_label_count = ce.label_count();
    let mut name = target.clone();
    while name.label_count() > ce_label_count + 1 {
        name = name.parent().unwrap();
    }
    if name.label_count() == ce_label_count + 1 {
        // name is the child we are looking for.
        return name;
    }

    // Something weird.
    todo!();
}

pub async fn check_not_exists_for_wildcard(
    name: &Name<Bytes>,
    qtype: Rtype,
    group: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
    closest_encloser: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> (bool, ValidationState, Option<ExtendedError<Bytes>>) {
    let (state, ede) = nsec_for_not_exists(name, group, &signer_name);
    match state {
        NsecNXState::Exists => {
            // The name actually exists.
            return (false, ValidationState::Bogus, ede);
        }
        NsecNXState::DoesNotExist(ce) => {
            // Make sure that the wildcard that was used for the
            // answer matches the closest encloser we got from the NSEC.
            if *closest_encloser == ce {
                // It checks out, we have a secure wildcard.
                return (true, ValidationState::Secure, None);
            }

            // Failure.
            todo!();
        }
        NsecNXState::Nothing => (), // Continue with NSEC3
    }

    println!("compute the child for {name:?} and {closest_encloser:?}");
    let child_of_ce = get_child_of_ce(name, closest_encloser);
    println!("got child {child_of_ce:?}");

    let (state, ede) = nsec3_for_not_exists_no_ce(
        &child_of_ce,
        group,
        qtype,
        &signer_name,
        nsec3_cache,
    )
    .await;
    match state {
        Nsec3NXStateNoCE::DoesNotExist => {
            // It checks out, we have a secure wildcard.
            return (true, ValidationState::Secure, None);
        }
        Nsec3NXStateNoCE::DoesNotExistInsecure => {
            // Non-existance proof is insecure.
            return (true, ValidationState::Insecure, None);
        }
        Nsec3NXStateNoCE::Nothing => (), // Continue.
    }

    // Failure, no suitable NSEC or NSEC3 record found.
    (false, ValidationState::Bogus, ede)
}

pub fn star_closest_encloser(ce: &Name<Bytes>) -> Name<Bytes> {
    let mut star_name = NameBuilder::new_bytes();
    star_name.append_label(Label::wildcard().as_ref()).unwrap();
    let star_name = star_name.append_origin(&ce).unwrap();
    star_name
}
