// Helper functions and constants for NSEC and NSEC3 validation.

use super::group::ValidatedGroup;
use super::types::ValidationState;
use super::utilities::make_ede;
use super::utilities::star_closest_encloser;
use crate::base::iana::ExtendedErrorCode;
use crate::base::iana::Nsec3HashAlg;
use crate::base::name::Label;
use crate::base::name::ToName;
use crate::base::opt::ExtendedError;
use crate::base::Name;
use crate::base::ParsedName;
use crate::base::Rtype;
use crate::dep::octseq::Octets;
use crate::dep::octseq::OctetsBuilder;
use crate::rdata::nsec3::Nsec3Salt;
use crate::rdata::nsec3::OwnerHash;
use crate::rdata::AllRecordData;
use crate::rdata::Nsec;
use crate::rdata::Nsec3;
use bytes::Bytes;
use moka::future::Cache;
use ring::digest;
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::str::FromStr;
use std::str::Utf8Error;
use std::sync::Arc;
use std::vec::Vec;

// These need to be config variables.
pub const NSEC3_ITER_INSECURE: u16 = 100;
pub const NSEC3_ITER_BOGUS: u16 = 500;

#[derive(Debug)]
pub enum NsecState {
    NoData,
    Nothing,
}

// Find an NSEC record for target that proves that no record that matches
// rtype exist.
//
// So we have two possibilities: we find an exact match for target and
// check the bitmap or we find target as an empty non-terminal.
pub fn nsec_for_nodata(
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
            if types.contains(rtype) || types.contains(Rtype::CNAME) {
                // We didn't get a rtype RRset but the NSEC record proves
                // there is one. Complain.
                todo!();
            }

            // Avoid parent-side NSEC records. The parent-side record has NS
            // set but not SOA. With one exception, the DS record lives on the
            // parent side so there the check needs to be reversed. With one
            // more exception: the root doesn't have a parent. So in the case
            // of a DS query for the root, we accept the record at apex.
            if rtype == Rtype::DS && *target != Name::<Vec<u8>>::root() {
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
pub fn nsec_for_nodata_wildcard(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
) -> (NsecState, Option<ExtendedError<Vec<u8>>>) {
    let (state, ede) = nsec_for_not_exists(target, groups, signer_name);
    let ce = match state {
        NsecNXState::DoesNotExist(ce) => ce,
        NsecNXState::Nothing => return (NsecState::Nothing, ede),
        NsecNXState::Exists => {
            // We have proof that the name exists but we are trying to proof
            // that it doesn't exist. Just pretend that we didn't find proof
            // that it doesn't exist.
            return (NsecState::Nothing, ede);
        }
    };

    let star_name = match star_closest_encloser(&ce) {
        Ok(name) => name,
        Err(_) => {
            // We cannot create the wildcard name. Pretend that we didn't
            // find anything and return a suitable ExtendedError.
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "cannot create wildcard record",
            );
            return (NsecState::Nothing, ede);
        }
    };
    (
        nsec_for_nodata(&star_name, groups, rtype, signer_name),
        None,
    )
}

#[derive(Debug)]
pub enum NsecNXState {
    Exists,
    DoesNotExist(Name<Bytes>),
    Nothing,
}

// Find an NSEC record for target that proves that the target does not
// exist. Return the status and the closest encloser.
pub fn nsec_for_not_exists(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
) -> (NsecNXState, Option<ExtendedError<Vec<u8>>>) {
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
            return (
                NsecNXState::Exists,
                make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "Found matching NSEC while trying to proof non-existance",
                ),
            );
        }

        // Check that target is in the range of the NSEC.
        if !nsec_in_range(target, &owner, nsec.next_name()) {
            // Not in this range.
            println!("nsec_for_not_exists: target {target:?} not in range <{owner:?}>..<{:?}>", nsec.next_name());
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
        let ce = nsec_closest_encloser(target, &owner, &nsec);

        return (NsecNXState::DoesNotExist(ce), None);
    }
    (NsecNXState::Nothing, None)
}

// Find an NSEC record for target that proves that the target does not
// exist. Then find an NSEC record that proves that the wildcard also does
// not exist.
pub fn nsec_for_nxdomain(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
) -> (NsecNXState, Option<ExtendedError<Vec<u8>>>) {
    let (state, ede) = nsec_for_not_exists(target, groups, signer_name);
    let ce = match state {
        NsecNXState::Exists => {
            // We have proof that target exists, just pretend we found nothing.
            return (NsecNXState::Nothing, ede);
        }
        NsecNXState::DoesNotExist(ce) => ce,
        NsecNXState::Nothing => return (NsecNXState::Nothing, ede),
    };

    let star_name = match star_closest_encloser(&ce) {
        Ok(name) => name,
        Err(_) => {
            // We cannot create the wildcard name. Pretend that we didn't
            // find anything and return a suitable ExtendedError.
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "cannot create wildcard record",
            );
            return (NsecNXState::Nothing, ede);
        }
    };
    nsec_for_not_exists(&star_name, groups, signer_name)
}

// Check if a name is covered by an NSEC record.
fn nsec_in_range<TN>(
    target: &Name<Bytes>,
    owner: &Name<Bytes>,
    next_name: &TN,
) -> bool
where
    TN: ToName,
{
    if owner.name_cmp(next_name) == Ordering::Less {
        target.name_cmp(&owner) == Ordering::Greater
            && target.name_cmp(next_name) == Ordering::Less
    } else {
        target.name_cmp(&owner) == Ordering::Greater
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
    let opt_closest_encloser = group.closest_encloser();
    if let Some(closest_encloser) = opt_closest_encloser {
        // The signature is for a wildcard. Make sure that the owner name is
        // equal to the unexpanded wildcard.
        let star_name = match star_closest_encloser(&closest_encloser) {
            Ok(name) => name,
            Err(_) => {
                // Error constructing wildcard. Just assume that this NSEC
                // record is invalid.
                return None;
            }
        };
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

fn nsec_closest_encloser(
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

// Find an NSEC3 record for target that proves that no record that matches
// rtype exist. There is only one option: find an NSEC3 record that has an
// owner name where the first label match the NSEC3 hash of target and then
// check the bitmap.
pub async fn nsec3_for_nodata(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> NsecState {
    for g in groups.iter() {
        let res_opt_nsec3_hash = get_checked_nsec3(g, signer_name);
        let (nsec3, ownerhash) = match res_opt_nsec3_hash {
            Ok(opt_nsec3_hash) => {
                if let Some(nsec3_hash) = opt_nsec3_hash {
                    nsec3_hash
                } else {
                    continue;
                }
            }
            Err(_) => todo!(),
        };

        // Create the hash with the parameters in this record. We should cache
        // the hash.
        let hash = cached_nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            nsec3.iterations(),
            nsec3.salt(),
            nsec3_cache,
        )
        .await;

        println!("got hash {hash:?} and ownerhash {ownerhash:?}");

        if ownerhash == hash.as_ref() {
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
    Bogus,
    Nothing,
}

// Find a closest encloser target and then find an NSEC3 record for the
// wildcard that proves that no record that matches
// rtype exist.
async fn nsec3_for_nodata_wildcard(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    rtype: Rtype,
    signer_name: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> (Nsec3State, Option<ExtendedError<Vec<u8>>>) {
    let (state, ede) =
        nsec3_for_not_exists(target, groups, signer_name, nsec3_cache).await;
    let (ce, secure) = match state {
        Nsec3NXState::DoesNotExist(ce) => (ce, true),
        Nsec3NXState::DoesNotExistInsecure(ce) => (ce, false),
        Nsec3NXState::Bogus => return (Nsec3State::Bogus, ede),
        Nsec3NXState::Nothing => return (Nsec3State::Nothing, ede),
    };

    let star_name = match star_closest_encloser(&ce) {
        Ok(name) => name,
        Err(_) => {
            // We cannot create the wildcard name. Just return bogus.
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "cannot create wildcard record",
            );
            return (Nsec3State::Bogus, ede);
        }
    };
    match nsec3_for_nodata(
        &star_name,
        groups,
        rtype,
        signer_name,
        nsec3_cache,
    )
    .await
    {
        NsecState::NoData => {
            if secure {
                (Nsec3State::NoData, None)
            } else {
                (Nsec3State::NoDataInsecure, None)
            }
        }
        NsecState::Nothing => (Nsec3State::Nothing, None),
    }
}

#[derive(Debug)]
pub enum Nsec3NXState {
    DoesNotExist(Name<Bytes>),
    DoesNotExistInsecure(Name<Bytes>),
    Bogus,
    Nothing,
}

// Prove that target does not exist using NSEC3 records. Return the status
// and the closest encloser.
pub async fn nsec3_for_not_exists(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> (Nsec3NXState, Option<ExtendedError<Vec<u8>>>) {
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
            let res_opt_nsec3_hash = get_checked_nsec3(g, signer_name);
            let (nsec3, ownerhash) = match res_opt_nsec3_hash {
                Ok(opt_nsec3_hash) => {
                    if let Some(nsec3_hash) = opt_nsec3_hash {
                        nsec3_hash
                    } else {
                        continue;
                    }
                }
                Err((ValidationState::Bogus, ede)) => {
                    return (Nsec3NXState::Bogus, ede)
                }
                Err(_) => todo!(),
            };

            // Create the hash with the parameters in this record. We should
            // cache the hash.
            let hash = cached_nsec3_hash(
                &n,
                nsec3.hash_algorithm(),
                nsec3.iterations(),
                nsec3.salt(),
                nsec3_cache,
            )
            .await;

            println!("got hash {hash:?} and ownerhash {ownerhash:?}");

            if ownerhash == hash.as_ref() {
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
            if nsec3_in_range(hash.as_ref(), &ownerhash, nsec3.next_owner()) {
                println!("nsec3_for_not_exists: found not exist");

                // We found a name that does not exist. Do we have a candidate
                // closest encloser?
                if maybe_ce_exists {
                    // Yes.

                    if nsec3.opt_out() {
                        // Results based on an opt_out record are insecure.
                        return (
                            Nsec3NXState::DoesNotExistInsecure(maybe_ce),
                            make_ede(
                                ExtendedErrorCode::OTHER,
                                "NSEC3 with Opt-Out",
                            ),
                        );
                    }

                    return (Nsec3NXState::DoesNotExist(maybe_ce), None);
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

    (
        Nsec3NXState::Nothing,
        make_ede(ExtendedErrorCode::OTHER, "No NSEC3 proves non-existance"),
    )
}

#[derive(Debug)]
pub enum Nsec3NXStateNoCE {
    DoesNotExist,
    DoesNotExistInsecure,
    Nothing,
}

// Prove that target does not exist using NSEC3 records. Assume that
// the closest encloser is already known and that we only have to check
// this specific name. This is typically used to prove that a wildcard does
// not exist.
pub async fn nsec3_for_not_exists_no_ce(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> (Nsec3NXStateNoCE, Option<ExtendedError<Vec<u8>>>) {
    println!("nsec3_for_not_exists_no_ce: proving {target:?} does not exist");

    // Check whether the name exists, or is proven to not exist.
    for g in groups.iter() {
        let res_opt_nsec3_hash = get_checked_nsec3(g, signer_name);
        let (nsec3, ownerhash) = match res_opt_nsec3_hash {
            Ok(opt_nsec3_hash) => {
                if let Some(nsec3_hash) = opt_nsec3_hash {
                    nsec3_hash
                } else {
                    continue;
                }
            }
            Err(_) => todo!(),
        };

        // Create the hash with the parameters in this record. We should
        // cache the hash.
        let hash = cached_nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            nsec3.iterations(),
            nsec3.salt(),
            nsec3_cache,
        )
        .await;

        println!("got hash {hash:?} and ownerhash {ownerhash:?}");

        // Check if target is between the hash in the first label and the
        // next_owner field.
        println!(
            "nsec3_for_not_exists_no_ce: range {ownerhash:?}..{:?}",
            nsec3.next_owner()
        );
        if nsec3_in_range(hash.as_ref(), &ownerhash, nsec3.next_owner()) {
            println!("nsec3_for_not_exists: found not exist");

            // We found a name that does not exist.
            if nsec3.opt_out() {
                // Results based on an opt_out record are insecure. Opt-out
                // is common enough that we don't need an EDE.
                return (Nsec3NXStateNoCE::DoesNotExistInsecure, None);
            }

            return (Nsec3NXStateNoCE::DoesNotExist, None);
        }

        // No match, try the next one.
    }

    return (Nsec3NXStateNoCE::Nothing, None);
}

// Find a closest encloser for target and then find an NSEC3 record that proves
// that tthe wildcard does not exist.
// rtype exist.
pub async fn nsec3_for_nxdomain(
    target: &Name<Bytes>,
    groups: &mut Vec<ValidatedGroup>,
    signer_name: &Name<Bytes>,
    nsec3_cache: &Nsec3Cache,
) -> (Nsec3NXState, Option<ExtendedError<Vec<u8>>>) {
    let (state, ede) =
        nsec3_for_not_exists(target, groups, signer_name, nsec3_cache).await;
    let (ce, secure) = match state {
        Nsec3NXState::DoesNotExist(ce) => (ce, true),
        Nsec3NXState::DoesNotExistInsecure(ce) => (ce, false),
        Nsec3NXState::Bogus => return (Nsec3NXState::Bogus, ede),
        Nsec3NXState::Nothing => return (Nsec3NXState::Nothing, ede),
    };

    let star_name = match star_closest_encloser(&ce) {
        Ok(name) => name,
        Err(_) => {
            // We cannot create the wildcard name. Just return bogus.
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "cannot create wildcard record",
            );
            return (Nsec3NXState::Bogus, ede);
        }
    };
    let (state, ede) = nsec3_for_not_exists_no_ce(
        &star_name,
        groups,
        signer_name,
        nsec3_cache,
    )
    .await;
    match state {
        Nsec3NXStateNoCE::DoesNotExist => {
            if secure {
                (Nsec3NXState::DoesNotExist(ce), None)
            } else {
                todo!(); // EDE
                         // Nsec3NXState::DoesNotExistInsecure(ce)
            }
        }
        Nsec3NXStateNoCE::DoesNotExistInsecure => {
            (Nsec3NXState::DoesNotExistInsecure(ce), ede)
        }
        Nsec3NXStateNoCE::Nothing => {
            todo!(); // EDE
                     // return Nsec3NXState::Nothing,
        }
    }
}

pub struct Nsec3Cache {
    cache: Cache<
        (Name<Bytes>, Nsec3HashAlg, u16, Nsec3Salt<Bytes>),
        Arc<OwnerHash<Vec<u8>>>,
    >,
}

impl Nsec3Cache {
    pub fn new(size: u64) -> Self {
        Self {
            cache: Cache::new(size),
        }
    }
}

/// Compute the NSEC3 hash according to Section 5 of RFC 5155:
///
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
///
/// Then the calculated hash of an owner name is
///    IH(salt, owner name, iterations),
fn nsec3_hash<N, HashOcts>(
    owner: N,
    algorithm: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<HashOcts>,
) -> OwnerHash<Vec<u8>>
where
    N: ToName,
    HashOcts: AsRef<[u8]>,
{
    let mut buf = Vec::new();

    owner.compose_canonical(&mut buf).expect("infallible");
    buf.append_slice(salt.as_slice()).expect("infallible");

    let mut ctx = if algorithm == Nsec3HashAlg::SHA1 {
        digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
    } else {
        // Unsupported.
        todo!();
    };

    ctx.update(&buf);
    let mut h = ctx.finish();

    for _ in 0..iterations {
        buf.truncate(0);
        buf.append_slice(h.as_ref()).expect("infallible");
        buf.append_slice(salt.as_slice()).expect("infallible");

        let mut ctx = if algorithm == Nsec3HashAlg::SHA1 {
            digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
        } else {
            // Unsupported.
            todo!();
        };

        ctx.update(&buf);
        h = ctx.finish();
    }

    // For normal hash algorithms this should not fail.
    OwnerHash::from_octets(h.as_ref().to_vec()).expect("should not fail")
}

pub async fn cached_nsec3_hash(
    owner: &Name<Bytes>,
    algorithm: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<Bytes>,
    cache: &Nsec3Cache,
) -> Arc<OwnerHash<Vec<u8>>> {
    let key = (owner.clone(), algorithm, iterations, salt.clone());
    if let Some(ce) = cache.cache.get(&key).await {
        println!("cached_nsec3_hash: existing hash for {owner:?}, {algorithm:?}, {iterations:?}, {salt:?}");
        return ce;
    }
    println!("cached_nsec3_hash: new hash for {owner:?}, {algorithm:?}, {iterations:?}, {salt:?}");
    let hash = nsec3_hash(owner, algorithm, iterations, salt);
    let hash = Arc::new(hash);
    cache.cache.insert(key, hash.clone()).await;
    hash
}

pub fn nsec3_label_to_hash(
    label: &Label,
) -> Result<OwnerHash<Vec<u8>>, Utf8Error> {
    let label_str = std::str::from_utf8(label.as_ref())?;
    Ok(OwnerHash::<Vec<u8>>::from_str(&label_str).expect("should not fail"))
}

pub fn nsec3_in_range<O1, O2, O3>(
    targethash: &OwnerHash<O1>,
    ownerhash: &OwnerHash<O2>,
    nexthash: &OwnerHash<O3>,
) -> bool
where
    O1: Octets,
    O2: Octets,
    O3: Octets,
{
    if *nexthash > ownerhash {
        // Normal range.
        ownerhash < targethash && targethash < nexthash
    } else {
        // End range that wraps around.
        ownerhash < targethash || targethash < nexthash
    }
}

fn get_checked_nsec3(
    group: &ValidatedGroup,
    signer_name: &Name<Bytes>,
) -> Result<
    Option<(Nsec3<Bytes>, OwnerHash<Vec<u8>>)>,
    (ValidationState, Option<ExtendedError<Vec<u8>>>),
> {
    let rrs = group.rr_set();
    if rrs.len() != 1 {
        // There should be at most one NSEC3 record for a given owner name.
        // Ignore the entire RRset.
        println!("get_checked_nsec3: line {}", line!());
        return Ok(None);
    }
    let AllRecordData::Nsec3(nsec3) = rrs[0].data() else {
        return Ok(None);
    };

    // Check if this group is secure.
    if let ValidationState::Secure = group.state() {
    } else {
        return Ok(None);
    };

    // Check if the signer name matches the expected signer name.
    if group.signer_name() != signer_name {
        println!("get_checked_nsec3: line {}", line!());
        return Ok(None);
    }

    let iterations = nsec3.iterations();

    // See RFC 9276, Appendix A for a recommendation on the maximum number
    // of iterations.
    if iterations > NSEC3_ITER_INSECURE || iterations > NSEC3_ITER_BOGUS {
        // High iteration count, abort.
        if iterations > NSEC3_ITER_BOGUS {
            return Err((
                ValidationState::Bogus,
                make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 with too high iteration count",
                ),
            ));
        }
        todo!();
    }

    // Convert first label to hash. Skip this NSEC3 record if that fails.
    let ownerhash = match nsec3_label_to_hash(group.owner().first()) {
        Ok(hash) => hash,
        Err(_) => {
            return Err((
                ValidationState::Bogus,
                make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 with bad owner hash",
                ),
            ))
        }
    };

    // Check if the length of ownerhash matches to length in next_hash.
    // Otherwise, skip the NSEC3 record.
    if ownerhash.as_slice().len() != nsec3.next_owner().as_slice().len() {
        return Ok(None);
    }

    // All check pass, return the NSEC3 record and the owner hash.
    Ok(Some((nsec3.clone(), ownerhash)))
}
