//! Group of resource records and associated signatures.
//!
//! For lack of a better term we call this a group. RR set refers to just
//! the resource records without the signatures.
//!
//! Name suggested by Yorgos: SignedRrset. Problem, sometimes there are no
//! signatures, sometimes there is a signature but no RRset.

use super::context::Config;
use super::context::Node;
use super::context::ValidationContext;
use super::types::Error;
use super::types::ValidationState;
use super::utilities::make_ede;
use super::utilities::map_dname;
use super::utilities::ttl_for_sig;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::class::Class;
use crate::base::iana::ExtendedErrorCode;
use crate::base::name::ToName;
use crate::base::opt::exterr::ExtendedError;
use crate::base::rdata::ComposeRecordData;
use crate::base::Name;
use crate::base::ParsedName;
use crate::base::ParsedRecord;
use crate::base::Record;
use crate::base::Rtype;
use crate::base::Ttl;
use crate::dep::octseq::builder::with_infallible;
use crate::dep::octseq::Octets;
use crate::dep::octseq::OctetsFrom;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::AllRecordData;
use crate::rdata::Dnskey;
use crate::rdata::Rrsig;
use crate::validate::RrsigExt;
use bytes::Bytes;
use moka::future::Cache;
use ring::digest;
use std::cmp::{max, min};
use std::fmt::Debug;
use std::slice::Iter;
use std::time::Duration;
use std::vec::Vec;

type RrType = Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>;
type SigType = Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>;

/// A collection of records (rr_set), associated signatures (sig_set) and
/// space for extra records, currently only CNAME records that are associated
/// with DNAME records in rr_set. Keep track if there were duplicate records
/// in found_duplicate.
///
/// [Group::new] and [Group::add] maintain the following invariant: a
/// [Group] instance
/// has at least one record in rr_set or sig_set. Both cannot be empty
/// at the same time. Records in rr_set and sig_set all have the same
/// owner name. All signature records in sig_set cover the same rtype.
/// If both rr_set and sig_set and non-empty the the type convered by the
/// signatures in sig_set is equal to the type of the records in rr_set.
#[derive(Clone, Debug)]
pub struct Group {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
    extra_set: Vec<RrType>,
    found_duplicate: bool,
}

impl Group {
    fn new(rr: ParsedRecord<'_, Bytes>) -> Result<Self, Error> {
        let sig_record = match rr.to_record::<Rrsig<_, _>>()? {
            None => {
                return Ok(Self {
                    rr_set: vec![to_bytes_record(&rr)?],
                    sig_set: Vec::new(),
                    extra_set: Vec::new(),
                    found_duplicate: false,
                });
            }
            Some(record) => record,
        };
        let rrsig = sig_record.data();

        let rrsig: Rrsig<Bytes, Name<Bytes>> =
            Rrsig::<Bytes, Name<Bytes>>::new(
                rrsig.type_covered(),
                rrsig.algorithm(),
                rrsig.labels(),
                rrsig.original_ttl(),
                rrsig.expiration(),
                rrsig.inception(),
                rrsig.key_tag(),
                rrsig.signer_name().to_name::<Bytes>(),
                Bytes::copy_from_slice(rrsig.signature().as_ref()),
            )
            .expect("should not fail");

        let record: Record<Name<Bytes>, _> = Record::new(
            sig_record.owner().to_name::<Bytes>(),
            sig_record.class(),
            sig_record.ttl(),
            rrsig,
        );

        Ok(Self {
            rr_set: Vec::new(),
            sig_set: vec![record],
            extra_set: Vec::new(),
            found_duplicate: false,
        })
    }

    fn add(&mut self, rr: &ParsedRecord<'_, Bytes>) -> Result<(), ()> {
        // First check owner.
        if let Some(frr) = self.rr_set.first() {
            if frr.owner() != &rr.owner().to_name::<Bytes>() {
                return Err(());
            }
	} else if *self.sig_set[0].owner() != rr.owner()
        {
            return Err(());
        }

        let (curr_class, curr_rtype) = if let Some(rr) = self.rr_set.first() {
            (rr.class(), rr.rtype())
        } else {
            (
                self.sig_set[0].class(),
                self.sig_set[0].data().type_covered(),
            )
        };

        let opt_record = match rr.to_record::<Rrsig<_, _>>() {
            Ok(opt_record) => opt_record,
            Err(_) => {
                // Ignore parse errors and return failure. Later new will
                // report the error.
                return Err(());
            }
        };
        if let Some(record) = opt_record {
            let rrsig = record.data();

            if curr_class == rr.class() && curr_rtype == rrsig.type_covered()
            {
                let rrsig: Rrsig<Bytes, Name<Bytes>> =
                    Rrsig::<Bytes, Name<Bytes>>::new(
                        rrsig.type_covered(),
                        rrsig.algorithm(),
                        rrsig.labels(),
                        rrsig.original_ttl(),
                        rrsig.expiration(),
                        rrsig.inception(),
                        rrsig.key_tag(),
                        rrsig.signer_name().to_name::<Bytes>(),
                        Bytes::copy_from_slice(rrsig.signature().as_ref()),
                    )
                    .expect("should not fail");

                let record: Record<Name<Bytes>, _> = Record::new(
                    record.owner().to_name::<Bytes>(),
                    curr_class,
                    record.ttl(),
                    rrsig,
                );

                // Some recursors return duplicate records. Check.
                for r in &self.sig_set {
                    if *r == record {
                        // We already have this record.
                        self.found_duplicate = true;
                        return Ok(());
                    }
                }

                self.sig_set.push(record);
                return Ok(());
            }
            return Err(());
        }

        // We can add rr if owner, class and rtype match.
        if curr_class == rr.class() && curr_rtype == rr.rtype() {
            let rr = match to_bytes_record(rr) {
                Ok(rr) => rr,
                Err(_) => {
                    // Ignore parse errors and return failure. Later new will
                    // report the error.
                    return Err(());
                }
            };

            // Some recursors return duplicate records. Check.
            for r in &self.rr_set {
                if *r == rr {
                    // We already have this record.
                    self.found_duplicate = true;
                    return Ok(());
                }
            }

            self.rr_set.push(rr);
            return Ok(());
        }

        // No match.
        Err(())
    }

    /// Add extra records that are associated with a group.
    ///
    /// The main use at the moment is to store the courtesy CNAME that comes
    /// with a DNAME. We need to keep the CNAME around to be able to
    /// regenerate the reply message with updated TTLs or other types of
    /// sanitizing.
    fn add_extra(
        &mut self,
        rr: &Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>,
    ) {
        // Assume we don't have to check for duplicates. The source of this
        // record is a CNAME group. Duplicates have been removed already.
        self.extra_set.push(rr.clone());
    }

    pub async fn validated<Octs, Upstream>(
        &self,
        vc: &ValidationContext<Upstream>,
        config: &Config,
    ) -> Result<ValidatedGroup, Error>
    where
        Octs:
            AsRef<[u8]> + Debug + Octets + OctetsFrom<Vec<u8>> + Send + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        let (state, signer_name, wildcard, ede, adjust_ttl) =
            self.validate_with_vc(vc, config).await?;
        Ok(ValidatedGroup::new(
            self.rr_set.clone(),
            self.sig_set.clone(),
            self.extra_set.clone(),
            state,
            signer_name,
            wildcard,
            ede,
            adjust_ttl,
            self.found_duplicate,
        ))
    }

    pub fn owner(&self) -> Name<Bytes> {
        if let Some(rr) = self.rr_set.first() {
            return rr.owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn class(&self) -> Class {
        if let Some(rr) = self.rr_set.first() {
            return rr.class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if let Some(rr) = self.rr_set.first() {
            return rr.rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }

    pub fn rr_iter(&mut self) -> Iter<RrType> {
        self.rr_set.iter()
    }

    pub fn sig_set_len(&self) -> usize {
        self.sig_set.len()
    }

    pub fn sig_iter(&mut self) -> Iter<SigType> {
        self.sig_set.iter()
    }

    pub async fn validate_with_vc<Octs, Upstream>(
        &self,
        vc: &ValidationContext<Upstream>,
        config: &Config,
    ) -> Result<
        (
            ValidationState,
            Name<Bytes>,
            Option<Name<Bytes>>,
            Option<ExtendedError<Vec<u8>>>,
            Option<Ttl>,
        ),
        Error,
    >
    where
        Octs:
            AsRef<[u8]> + Debug + Octets + OctetsFrom<Vec<u8>> + Send + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
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
            return Ok((
                ValidationState::Insecure,
                Name::root(),
                None,
                make_ede(
                    ExtendedErrorCode::DNSSEC_INDETERMINATE,
                    "RRSIG without RRset",
                ),
                None,
            ));
        }

        let target = if let Some(sig_rr) = self.sig_set.first() {
            sig_rr.data().signer_name()
        } else {
            self.rr_set[0].owner()
        };
        let node = vc.get_node(target).await?;
        let state = node.validation_state();
        match state {
            ValidationState::Secure => (), // Continue validating
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return Ok((
                    state,
                    target.clone(),
                    None,
                    node.extended_error(),
                    None,
                ))
            }
        }
        let (state, wildcard, ede, _ttl, adjust_ttl) = self
            .validate_with_node(&node, vc.usig_cache(), config)
            .await;
        Ok((state, target.clone(), wildcard, ede, adjust_ttl))
    }

    // Try to validate the signature using a node. Return the validation
    // state. Also return if the signature was expanded from a wildcard.
    // This is valid only if the validation state is secure.
    pub(crate) async fn validate_with_node(
        &self,
        node: &Node,
        sig_cache: &SigCache,
        config: &Config,
    ) -> (
        ValidationState,
        Option<Name<Bytes>>,
        Option<ExtendedError<Vec<u8>>>,
        Duration,
        Option<Ttl>,
    ) {
        let mut opt_ede = None;

        // Check the validation state of node. We can return directly if the
        // state is anything other than Secure.
        let state = node.validation_state();
        match state {
            ValidationState::Insecure
            | ValidationState::Bogus
            | ValidationState::Indeterminate => {
                return (state, None, node.extended_error(), node.ttl(), None)
            }
            ValidationState::Secure => (),
        }
        let keys = node.keys();
        let ttl = node.ttl();
        let group_ttl = self.min_ttl();
        let group_max_ttl = self.max_ttl();
        let group_dur = group_ttl.into_duration();
        let ttl = min(ttl, group_dur);

        let mut bad_sigs = 0;
        for sig_rec in self.clone().sig_iter() {
            let sig = sig_rec.data();
            for key in keys {
                // See if this key matches the sig.
                if key.algorithm() != sig.algorithm() {
                    continue;
                }
                let key_tag = key.key_tag();
                if key_tag != sig.key_tag() {
                    continue;
                }

                if self
                    .check_sig_cached(
                        sig_rec,
                        node.signer_name(),
                        key,
                        node.signer_name(),
                        key_tag,
                        sig_cache,
                    )
                    .await
                {
                    let wildcard =
                        sig.wildcard_closest_encloser(&self.rr_set[0]);
                    let sig_ttl = ttl_for_sig(sig_rec);
                    let adjust_ttl = if sig_ttl < group_max_ttl {
                        Some(sig_ttl)
                    } else {
                        None
                    };
                    let ttl = min(ttl, sig_ttl.into_duration());

                    return (
                        ValidationState::Secure,
                        wildcard,
                        None,
                        ttl,
                        adjust_ttl,
                    );
                } else {
                    // To avoid CPU exhaustion attacks such as KeyTrap
                    // (CVE-2023-50387) it is good to limit signature
                    // validation as much as possible. To be as strict as
                    // possible, we can make the following assumptions:
                    // 1) A trust anchor contains at least one key with a
                    // supported algorithm, so at least one signature is
                    // expected to be verifiable.
                    // 2) A DNSKEY RRset plus associated RRSIG is self-
                    // contained. Every signature is made with a key in the
                    // RRset and it is the current contents of the RRset
                    // that is signed. So we expect that signature
                    // verification cannot fail.
                    // 3) With one exception: keytag collisions could create
                    // confusion about which key was used. Collisions are
                    // rare so we assume at most two keys in the RRset to be
                    // involved in a collision.
                    // For these reasons we can limit the number of failures
                    // we tolerate to one. And declare the DNSKEY RRset
                    // bogus if we get two failures.
                    bad_sigs += 1;
                    if bad_sigs > config.max_bad_signatures() {
                        // totest, too many bad signatures for rrset
                        let ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "too many bad signatures",
                        );
                        return (
                            ValidationState::Bogus,
                            None,
                            ede,
                            config.max_bogus_validity(),
                            None,
                        );
                    }
                    if opt_ede.is_none() {
                        opt_ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "Bad signature",
                        );
                    }
                }
            }
        }

        if opt_ede.is_none() {
            opt_ede =
                make_ede(ExtendedErrorCode::DNSSEC_BOGUS, "No signature");
        }
        (
            ValidationState::Bogus,
            None,
            opt_ede,
            config.max_bogus_validity(),
            None,
        )
    }

    // Follow RFC 4035, Section 5.3.
    fn check_sig(
        &self,
        sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
        signer_name: &Name<Bytes>,
        key: &Dnskey<Bytes>,
        key_name: &Name<Bytes>,
        key_tag: u16,
    ) -> bool {
        let ts_now = Timestamp::now();
        let rtype = self.rtype();
        let owner = self.owner();
        let labels = owner.iter().count() - 1;
        let rrsig = sig.data();

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR and the RRset MUST have the same owner name and the same
        //   class.
        if !sig.owner().name_eq(&owner) || sig.class() != self.class() {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name field MUST be the name of the zone that
        //   contains the RRset.

        // We don't really know the name of the zone that contains an RRset. What
        // we can do is that the signer's name is a prefix of the owner name.
        // We assume that a zone will not sign things in space that is delegated
        // (except for the parent side of the delegation)
        if !owner.ends_with(&signer_name) {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Type Covered field MUST equal the RRset's type.
        if rrsig.type_covered() != rtype {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The number of labels in the RRset owner name MUST be greater than
        //   or equal to the value in the RRSIG RR's Labels field.
        if labels < rrsig.labels() as usize {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The validator's notion of the current time MUST be less than or
        //   equal to the time listed in the RRSIG RR's Expiration field.
        // - The validator's notion of the current time MUST be greater than or
        //   equal to the time listed in the RRSIG RR's Inception field.
        if ts_now.canonical_gt(&rrsig.expiration())
            || ts_now.canonical_lt(&rrsig.inception())
        {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The RRSIG RR's Signer's Name, Algorithm, and Key Tag fields MUST
        //   match the owner name, algorithm, and key tag for some DNSKEY RR in
        //   the zone's apex DNSKEY RRset.
        if signer_name != key_name
            || rrsig.algorithm() != key.algorithm()
            || rrsig.key_tag() != key_tag
        {
            return false;
        }

        // RFC 4035, Section 5.3.1:
        // - The matching DNSKEY RR MUST be present in the zone's apex DNSKEY
        //   RRset, and MUST have the Zone Flag bit (DNSKEY RDATA Flag bit 7)
        //   set.

        // We cannot check here if the key is in the zone's apex, that is up to
        // the caller. Just check the Zone Flag bit.
        if !key.is_zone_key() {
            return false;
        }

        //signature
        let mut signed_data = Vec::<u8>::new();
        rrsig
            .signed_data(&mut signed_data, &mut self.rr_set())
            .expect("infallible");
        let res = rrsig.verify_signed_data(key, &signed_data);

        res.is_ok()
    }

    pub async fn check_sig_cached(
        &self,
        sig: &Record<Name<Bytes>, Rrsig<Bytes, Name<Bytes>>>,
        signer_name: &Name<Bytes>,
        key: &Dnskey<Bytes>,
        key_name: &Name<Bytes>,
        key_tag: u16,
        cache: &SigCache,
    ) -> bool {
        let mut signed_data = Vec::<u8>::new();
        sig.data()
            .signed_data(&mut signed_data, &mut self.rr_set())
            .expect("infallible");

        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| key.compose_canonical_rdata(&mut buf));
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(&buf);
        let key_hash = ctx.finish();

        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| sig.data().compose_canonical_rdata(&mut buf));
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(&buf);
        let sig_hash = ctx.finish();

        let cache_key = SigKey(
            signed_data,
            sig_hash.as_ref().to_vec(),
            key_hash.as_ref().to_vec(),
        );

        if let Some(ce) = cache.cache.get(&cache_key).await {
            return ce;
        }
        let res = self.check_sig(sig, signer_name, key, key_name, key_tag);
        cache.cache.insert(cache_key, res).await;
        res
    }

    pub fn min_ttl(&self) -> Ttl {
        if self.rr_set.is_empty() {
            return Ttl::ZERO;
        }
        let mut ttl = self.rr_set[0].ttl();
        for rr in &self.rr_set[1..] {
            ttl = min(ttl, rr.ttl());
        }
        ttl
    }

    pub fn max_ttl(&self) -> Ttl {
        let mut ttl = Ttl::ZERO;
        for rr in &self.rr_set {
            ttl = max(ttl, rr.ttl());
        }
        for rr in &self.sig_set {
            ttl = max(ttl, rr.ttl());
        }
        for rr in &self.extra_set {
            ttl = max(ttl, rr.ttl());
        }
        ttl
    }
}

#[derive(Clone, Debug)]
pub struct GroupSet(Vec<Group>);

impl GroupSet {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add(&mut self, rr: ParsedRecord<'_, Bytes>) -> Result<(), Error> {
        // Very simplistic implementation of add. Assume resource records
        // are mostly in order. If this O(n^2) algorithm is not enough,
        // then we should use a small hash table or sort first.
        if self.0.is_empty() {
            self.0.push(Group::new(rr)?);
            return Ok(());
        }
        let len = self.0.len();
        let res = self.0[len - 1].add(&rr);
        if res.is_ok() {
            return Ok(());
        }

        // Try all existing groups except the last one
        for g in &mut self.0[..len - 1] {
            let res = g.add(&rr);
            if res.is_ok() {
                return Ok(());
            }
        }

        // Add a new group.
        self.0.push(Group::new(rr)?);
        Ok(())
    }

    pub fn move_redundant_cnames(&mut self) {
        // Use indices to be able to mutate the array. Otherwise borrows
        // will get in the way. Iterate high to low to find CNAME groups
        // to be able to delete CNAME groups without affecting groups that
        // still need to be checked.
        for cname_ind in (0..self.0.len()).rev() {
            if self.0[cname_ind].rtype() != Rtype::CNAME {
                continue;
            }
            let rr_set = self.0[cname_ind].rr_set();
            if rr_set.len() != 1 {
                continue; // Let it fail if it is in secure zone.
            }
            if self.0[cname_ind].sig_set_len() != 0 {
                // Signed CNAME, no need to check.
                continue;
            }

            if self
                .moved_to_dname(&rr_set[0], self.0[cname_ind].found_duplicate)
            {
                // Courtesy CNAME has been moved, mark this group as
                // redundant.
                let _ = self.0.remove(cname_ind);
            }
        }
    }

    fn moved_to_dname(
        &mut self,
        cname_rr: &Record<
            Name<Bytes>,
            AllRecordData<Bytes, ParsedName<Bytes>>,
        >,
        found_duplicate: bool,
    ) -> bool {
        let cname_name = cname_rr.owner();
        for g in &mut self.0 {
            if g.rtype() != Rtype::DNAME {
                continue;
            }
            let rr_set = g.rr_set();
            for rr in rr_set {
                let owner = rr.owner();
                if !cname_name.ends_with(owner) {
                    continue;
                }
                if cname_name == owner {
                    // Weird, both a CNAME and a DNAME at the same name.
                    continue;
                }

                // Now check the target of the CNAME.
                let result_name =
                    if let AllRecordData::Dname(dname) = rr.data() {
                        match map_dname(owner, dname, cname_name) {
                            Ok(name) => name,
                            Err(_) => {
                                // Expanding the DNAME failed. This CNAME
                                // cannot be the result of expanding the
                                // DNAME.
                                return false;
                            }
                        }
                    } else {
                        panic!("DNAME expected");
                    };
                if let AllRecordData::Cname(cname) = cname_rr.data() {
                    if cname.cname().to_name::<Bytes>() == result_name {
                        g.add_extra(cname_rr);
                        g.found_duplicate |= found_duplicate;
                        return true;
                    }
                }
            }
        }

        false
    }

    pub fn iter(&mut self) -> Iter<Group> {
        self.0.iter()
    }
}

#[derive(Debug)]
pub struct ValidatedGroup {
    rr_set: Vec<RrType>,
    sig_set: Vec<SigType>,
    extra_set: Vec<RrType>,
    state: ValidationState,
    signer_name: Name<Bytes>,
    closest_encloser: Option<Name<Bytes>>,
    ede: Option<ExtendedError<Vec<u8>>>,
    adjust_ttl: Option<Ttl>,
    found_duplicate: bool,
}

#[allow(clippy::too_many_arguments)]
impl ValidatedGroup {
    fn new(
        rr_set: Vec<RrType>,
        sig_set: Vec<SigType>,
        extra_set: Vec<RrType>,
        state: ValidationState,
        signer_name: Name<Bytes>,
        closest_encloser: Option<Name<Bytes>>,
        ede: Option<ExtendedError<Vec<u8>>>,
        adjust_ttl: Option<Ttl>,
        found_duplicate: bool,
    ) -> ValidatedGroup {
        ValidatedGroup {
            rr_set,
            sig_set,
            extra_set,
            state,
            signer_name,
            closest_encloser,
            ede,
            adjust_ttl,
            found_duplicate,
        }
    }

    pub fn class(&self) -> Class {
        if let Some(rr) = self.rr_set.first() {
            return rr.class();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        self.sig_set[0].class()
    }

    pub fn rtype(&self) -> Rtype {
        if let Some(rr) = self.rr_set.first() {
            return rr.rtype();
        }

        // The type in sig_set is always Rrsig
        Rtype::RRSIG
    }

    pub fn owner(&self) -> Name<Bytes> {
        if let Some(rr) = self.rr_set.first() {
            return rr.owner().to_bytes();
        }

        // This may fail if sig_set is empty. But either rr_set or
        // sig_set is not empty.
        return self.sig_set[0].owner().to_bytes();
    }

    pub fn state(&self) -> ValidationState {
        self.state
    }

    pub fn signer_name(&self) -> Name<Bytes> {
        self.signer_name.clone()
    }

    pub fn closest_encloser(&self) -> Option<Name<Bytes>> {
        self.closest_encloser.clone()
    }

    pub fn ede(&self) -> Option<ExtendedError<Vec<u8>>> {
        self.ede.clone()
    }

    pub fn rr_set(&self) -> Vec<RrType> {
        self.rr_set.clone()
    }

    pub fn sig_set(&self) -> Vec<SigType> {
        self.sig_set.clone()
    }

    pub fn extra_set(&self) -> Vec<RrType> {
        self.extra_set.clone()
    }

    pub fn adjust_ttl(&self) -> Option<Ttl> {
        self.adjust_ttl
    }

    pub fn found_duplicate(&self) -> bool {
        self.found_duplicate
    }
}

#[allow(clippy::type_complexity)]
fn to_bytes_record(
    rr: &ParsedRecord<'_, Bytes>,
) -> Result<Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>, Error>
{
    let record = rr
        .to_record::<AllRecordData<_, _>>()?
        .expect("should not fail");
    Ok(
        Record::<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>::new(
            rr.owner().to_name::<Bytes>(),
            rr.class(),
            rr.ttl(),
            record.data().clone(),
        ),
    )
}

#[derive(Eq, Hash, PartialEq)]
struct SigKey(Vec<u8>, Vec<u8>, Vec<u8>);
pub struct SigCache {
    cache: Cache<SigKey, bool>,
}

impl SigCache {
    pub fn new(size: u64) -> Self {
        Self {
            cache: Cache::new(size),
        }
    }
}
