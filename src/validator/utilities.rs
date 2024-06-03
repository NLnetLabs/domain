use super::context::Config;
use super::group::ValidatedGroup;
use super::nsec::nsec3_for_not_exists_no_ce;
use super::nsec::nsec_for_not_exists;
use super::nsec::Nsec3Cache;
use super::nsec::Nsec3NXStateNoCE;
use super::nsec::NsecNXState;
use super::types::Error;
use super::types::ValidationState;
use crate::base::iana::Class;
use crate::base::iana::ExtendedErrorCode;
use crate::base::name::Label;
use crate::base::opt::ExtendedError;
use crate::base::Name;
use crate::base::NameBuilder;
use crate::base::ParsedName;
use crate::base::Record;
use crate::base::Rtype;
use crate::base::ToName;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::AllRecordData;
use crate::rdata::Dname;
use crate::rdata::Rrsig;
use bytes::Bytes;
use std::cmp::min;
use std::time::Duration;
use std::vec::Vec;

pub async fn do_cname_dname(
    qname: Name<Bytes>,
    qclass: Class,
    qtype: Rtype,
    answers: &mut [ValidatedGroup],
    authorities: &mut [ValidatedGroup],
    nsec3_cache: &Nsec3Cache,
    config: &Config,
) -> (Name<Bytes>, ValidationState, Option<ExtendedError<Vec<u8>>>) {
    let mut name = qname;
    let mut count = 0;
    let mut maybe_secure = ValidationState::Secure;
    'name_loop: loop {
        for g in answers.iter() {
            if g.class() != qclass {
                continue;
            }
            let rtype = g.rtype();
            if rtype == Rtype::CNAME && rtype == qtype {
                // A CNAME requested, do not process them here.
                continue;
            }

            let rr_set = g.rr_set();
            if rr_set.len() != 1 {
                // totest, RRset with more than one CNAME or DNAME.
                // just skip this RRset. This is not an error because we
                // don't know the type of the record yet.
                continue;
            }

            if let AllRecordData::Cname(cname) = rr_set[0].data() {
                if g.owner() != name {
                    continue;
                }
                if let Some(ce) = g.closest_encloser() {
                    let (check, state, ede) = check_not_exists_for_wildcard(
                        &name,
                        authorities,
                        &g.signer_name(),
                        &ce,
                        nsec3_cache,
                        config,
                    )
                    .await;
                    if check {
                        maybe_secure = map_maybe_secure(state, maybe_secure);
                    // Just continue.
                    } else {
                        // totest, CNAME from wildcard with bad non-existance
                        // proof
                        // Report failure
                        return (name, ValidationState::Bogus, ede);
                    }
                }
                name = cname.cname().to_name();
                maybe_secure = map_maybe_secure(g.state(), maybe_secure);
                count += 1;
                if count > config.max_cname_dname() {
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "too many DNAME/CNAME records in sequence",
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
                    // totest, DNAME from wildcard
                    // wildcard DNAMEs are undefined.
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "DNAME from wildcard",
                    );
                    return (owner, ValidationState::Bogus, ede);
                }

                name = match map_dname(&owner, dname, &name) {
                    Ok(name) => name,
                    Err(_) => {
                        let ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "Failed to expand DNAME",
                        );
                        return (owner, ValidationState::Bogus, ede);
                    }
                };
                maybe_secure = map_maybe_secure(g.state(), maybe_secure);
                count += 1;
                if count > config.max_cname_dname() {
                    // totest, loop with too many DNAME records
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "too many DNAME/CNAME records in sequence",
                    );
                    return (owner, ValidationState::Bogus, ede);
                }
                continue 'name_loop;
            }

            // Just continue, not a CNAME or DNAME.
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
) -> Result<Name<Bytes>, Error> {
    let mut tmp_name = name.clone();
    let mut new_name = NameBuilder::new_bytes();
    let owner_labels = owner.label_count();
    while tmp_name.label_count() > owner_labels {
        new_name.append_label(tmp_name.first().as_slice())?;
        tmp_name = tmp_name.parent().expect("should not fail");
    }
    let name = new_name.append_origin(dname.dname())?;
    Ok(name)
}

pub fn ttl_for_sig(
    sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
) -> Duration {
    let ttl = sig.ttl().into_duration();
    let orig_ttl = sig.data().original_ttl().into_duration();
    let ttl = min(ttl, orig_ttl);

    let until_expired =
        sig.data().expiration().into_int() - Timestamp::now().into_int();
    let expire_duration = Duration::from_secs(until_expired as u64);
    min(ttl, expire_duration)
}

#[allow(clippy::type_complexity)]
pub fn get_answer_state(
    qname: &Name<Bytes>,
    qclass: Class,
    qtype: Rtype,
    groups: &mut [ValidatedGroup],
) -> Option<(
    ValidationState,
    Name<Bytes>,
    Option<Name<Bytes>>,
    Option<ExtendedError<Vec<u8>>>,
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

#[allow(clippy::type_complexity)]
pub fn get_soa_state(
    qname: &Name<Bytes>,
    qclass: Class,
    groups: &mut [ValidatedGroup],
) -> (
    Option<(ValidationState, Name<Bytes>)>,
    Option<ExtendedError<Vec<u8>>>,
) {
    let mut ede = None;
    for g in groups.iter() {
        if g.rtype() != Rtype::SOA {
            continue;
        }
        if g.class() != qclass {
            // totest, SOA with wrong class
            if ede.is_none() {
                ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "SOA with wrong class",
                );
            }
            continue;
        }
        if !qname.ends_with(&g.owner()) {
            // totest, SOA with wrong name
            ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "SOA with wrong name",
            );
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
        name = name.parent().expect("should not fail");
    }
    if name.label_count() == ce_label_count + 1 {
        // name is the child we are looking for.
        return name;
    }

    // Something weird.
    panic!("Get child of closest encloser(ce), maybe target is not a decendent of ce?");
}

pub async fn check_not_exists_for_wildcard(
    name: &Name<Bytes>,
    group: &mut [ValidatedGroup],
    signer_name: &Name<Bytes>,
    closest_encloser: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
    config: &Config,
) -> (bool, ValidationState, Option<ExtendedError<Vec<u8>>>) {
    let (state, ede) = nsec_for_not_exists(name, group, signer_name);
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

            // totest, expanded wildcard does not match NSEC CE
            // Failure.
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "wildcard does not match NSEC dereived closest encloser",
            );
            return (false, ValidationState::Bogus, ede);
        }
        NsecNXState::Nothing => (), // Continue with NSEC3
    }

    let child_of_ce = get_child_of_ce(name, closest_encloser);

    let (state, ede) = nsec3_for_not_exists_no_ce(
        &child_of_ce,
        group,
        signer_name,
        nsec3_cache,
        config,
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
        Nsec3NXStateNoCE::Bogus => {
            return (false, ValidationState::Bogus, ede)
        }
        Nsec3NXStateNoCE::Nothing => (), // Continue.
    }

    // Failure, no suitable NSEC or NSEC3 record found.
    (false, ValidationState::Bogus, ede)
}

pub fn star_closest_encloser(ce: &Name<Bytes>) -> Result<Name<Bytes>, Error> {
    let mut star_name = NameBuilder::new_bytes();
    star_name.append_label(Label::wildcard().as_ref())?;
    let star_name = star_name.append_origin(&ce)?;
    Ok(star_name)
}

pub fn make_ede(
    code: ExtendedErrorCode,
    reason: &str,
) -> Option<ExtendedError<Vec<u8>>> {
    match ExtendedError::new_with_str(code, reason) {
        Ok(ede) => Some(ede),
        Err(_) => {
            // Assume that the only reason this case fail is a string that
            // is way too long. Just return None.
            None
        }
    }
}
