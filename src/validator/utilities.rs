/*
use bytes::Bytes;
use crate::base::Dname;
use crate::base::Record;
use crate::base::Rtype;
use crate::base::cmp::CanonicalOrd;
use crate::base::name::ToDname;
use crate::rdata::Dnskey;
use crate::rdata::Rrsig;
use crate::rdata::dnssec::Timestamp;
use crate::validate::RrsigExt;
use std::vec::Vec;
use super::group::Group;

// Follow RFC 4035, Section 5.3.

pub fn check_sig(
    sig: &Record<Dname<Bytes>, Rrsig<Bytes, Dname<Bytes>>>,
    signer_name: &Dname<Bytes>,
    key: &Dnskey<Bytes>,
    key_name: &Dname<Bytes>,
    key_tag: u16,
    rrs: &Group,
) -> bool {
    let ts_now = Timestamp::now();
    let rtype = rrs.rtype();
    let rrs_owner = rrs.owner();
    let labels = rrs_owner.iter().count() - 1;
    let rrsig = sig.data();

    println!("check_sig for {rrsig:?} and {key:?}");

    println!("{:?} and {:?}", rrsig.type_covered(), rtype);
    println!("{:?} and {:?}: {:?}", rrsig.expiration(), ts_now, rrsig.expiration().canonical_lt(&ts_now));
    println!("{:?} and {:?}: {:?}", rrsig.inception(), ts_now, rrsig.inception().canonical_gt(&ts_now));
    println!("{:?} and {:?}", rrsig.algorithm(), key.algorithm());
    println!("{:?} and {:?}", rrsig.key_tag(), key_tag);

    // RFC 4035, Section 5.3.1:
    // - The RRSIG RR and the RRset MUST have the same owner name and the same
    //   class.
    if !sig.owner().name_eq(&rrs_owner)
    || sig.class() != rrs.class() {
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
    if !rrs_owner.ends_with(&signer_name) {
println!("failed at line {}", line!());
    println!("check_sig: {:?} does not end with {signer_name:?}",
        rrs_owner);
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
        || ts_now.canonical_lt(&rrsig.inception()) {
println!("failed at line {}", line!());
    return false;
    }

    // RFC 4035, Section 5.3.1:
    // - The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
    //   match the owner name, algorithm, and key tag for some DNSKEY RR in
    //   the zone's apex DNSKEY RRset.
    if signer_name != key_name
    || rrsig.algorithm() != key.algorithm()
    || rrsig.key_tag() != key_tag {
println!("failed at line {}", line!());
    return false;
    }

    // RFC 4035, Section 5.3.1:
    // - The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
    //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
    //   set.

    // We cannot check here if the key is in the zone's apex, that is up to
    // the caller. Just check the Zone Flag bit.
    // XXX is_zsk is the wrong name for this function.
    if !key.is_zsk() {
println!("failed at line {}", line!());
    return false;
    }

    //signature
    let mut signed_data = Vec::<u8>::new();
    rrsig.signed_data(&mut signed_data, &mut rrs.rr_set()).unwrap();
    let res = rrsig.verify_signed_data(key, &signed_data);

    match res {
    Ok(_) => true,
    Err(_) => false
    }
}
*/
