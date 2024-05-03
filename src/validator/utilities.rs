use crate::base::Name;
use crate::base::NameBuilder;
use crate::base::ParsedName;
use crate::base::Record;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::Dname;
use crate::rdata::Rrsig;
use bytes::Bytes;
use std::cmp::min;
use std::time::Duration;

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
