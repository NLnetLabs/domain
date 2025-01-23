use core::str::FromStr;

use std::io::Read;

use bytes::Bytes;

use crate::base::iana::{Class, SecAlg};
use crate::base::name::FlattenInto;
use crate::base::{Record, Rtype, Serial, Ttl};
use crate::rdata::dnssec::{RtypeBitmap, Timestamp};
use crate::rdata::{Dnskey, Ns, Nsec, Rrsig, Soa, A};
use crate::zonefile::inplace::{Entry, Zonefile};
use crate::zonetree::types::StoredRecordData;
use crate::zonetree::StoredName;

use super::records::SortedRecords;

pub(crate) const TEST_TTL: Ttl = Ttl::from_secs(3600);

pub(crate) fn bytes_to_records(
    mut zonefile: impl Read,
) -> SortedRecords<StoredName, StoredRecordData> {
    let reader = Zonefile::load(&mut zonefile).unwrap();
    let mut records = SortedRecords::default();
    for entry in reader {
        let entry = entry.unwrap();
        if let Entry::Record(record) = entry {
            records.insert(record.flatten_into()).unwrap()
        }
    }
    records
}

pub(crate) fn mk_name(name: &str) -> StoredName {
    StoredName::from_str(name).unwrap()
}

pub(crate) fn mk_record<D>(owner: &str, data: D) -> Record<StoredName, D> {
    Record::new(mk_name(owner), Class::IN, TEST_TTL, data)
}

pub(crate) fn mk_a_rr<R>(owner: &str) -> Record<StoredName, R>
where
    R: From<A>,
{
    mk_record(owner, A::from_str("1.2.3.4").unwrap().into())
}

pub(crate) fn mk_dnskey_rr<R>(
    owner: &str,
    flags: u16,
    algorithm: SecAlg,
    public_key: &Bytes,
) -> Record<StoredName, R>
where
    R: From<Dnskey<Bytes>>,
{
    // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.2
    // 2.1.2.  The Protocol Field
    //   "The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
    //    treated as invalid during signature verification if it is found to
    //    be some value other than 3."
    mk_record(
        owner,
        Dnskey::new(flags, 3, algorithm, public_key.clone())
            .unwrap()
            .into(),
    )
}

pub(crate) fn mk_ns_rr<R>(owner: &str, nsdname: &str) -> Record<StoredName, R>
where
    R: From<Ns<StoredName>>,
{
    let nsdname = mk_name(nsdname);
    mk_record(owner, Ns::new(nsdname).into())
}

pub(crate) fn mk_nsec_rr<R>(
    owner: &str,
    next_name: &str,
    types: &str,
) -> Record<StoredName, R>
where
    R: From<Nsec<Bytes, StoredName>>,
{
    let next_name = mk_name(next_name);
    let mut builder = RtypeBitmap::<Bytes>::builder();
    for rtype in types.split_whitespace() {
        builder.add(Rtype::from_str(rtype).unwrap()).unwrap();
    }
    let types = builder.finalize();
    mk_record(owner, Nsec::new(next_name, types).into())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn mk_rrsig_rr<R>(
    owner: &str,
    covered_rtype: Rtype,
    algorithm: &SecAlg,
    labels: u8,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer_name: &str,
    signature: Bytes,
) -> Record<StoredName, R>
where
    R: From<Rrsig<Bytes, StoredName>>,
{
    let signer_name = mk_name(signer_name);
    let expiration = Timestamp::from(expiration);
    let inception = Timestamp::from(inception);
    mk_record(
        owner,
        Rrsig::new(
            covered_rtype,
            *algorithm,
            labels,
            TEST_TTL,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        )
        .unwrap()
        .into(),
    )
}

pub(crate) fn mk_soa_rr<R>(
    owner: &str,
    mname: &str,
    rname: &str,
) -> Record<StoredName, R>
where
    R: From<Soa<StoredName>>,
{
    let soa = Soa::new(
        mk_name(mname),
        mk_name(rname),
        Serial::now(),
        TEST_TTL,
        TEST_TTL,
        TEST_TTL,
        TEST_TTL,
    );
    mk_record(owner, soa.into())
}

#[allow(clippy::type_complexity)]
pub(crate) fn contains_owner(
    nsecs: &[Record<StoredName, Nsec<Bytes, StoredName>>],
    name: &str,
) -> bool {
    let name = mk_name(name);
    nsecs.iter().any(|rr| rr.owner() == &name)
}
