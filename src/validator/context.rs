// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use super::anchor::TrustAnchor;
use super::anchor::TrustAnchors;
use super::group::Group;
use super::group::GroupSet;
use super::group::SigCache;
use super::group::ValidatedGroup;
use super::nsec::cached_nsec3_hash;
use super::nsec::nsec3_for_nodata;
use super::nsec::nsec3_for_not_exists;
use super::nsec::nsec3_for_nxdomain;
use super::nsec::nsec3_in_range;
use super::nsec::nsec3_label_to_hash;
use super::nsec::nsec_for_nodata;
use super::nsec::nsec_for_nodata_wildcard;
use super::nsec::nsec_for_nxdomain;
use super::nsec::nsec_in_range;
use super::nsec::supported_nsec3_hash;
use super::nsec::Nsec3Cache;
use super::nsec::Nsec3NXState;
use super::nsec::Nsec3State;
use super::nsec::NsecNXState;
use super::nsec::NsecState;
use super::types::Error;
use super::types::ValidationState;
use super::utilities::check_not_exists_for_wildcard;
use super::utilities::do_cname_dname;
use super::utilities::get_answer_state;
use super::utilities::get_soa_state;
use super::utilities::make_ede;
use super::utilities::map_maybe_secure;
use super::utilities::rebuild_msg;
use super::utilities::star_closest_encloser;
use super::utilities::ttl_for_sig;
use crate::base::iana::ExtendedErrorCode;
use crate::base::iana::OptRcode;
use crate::base::name::Chain;
use crate::base::name::Label;
use crate::base::opt::ExtendedError;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::Name;
use crate::base::ParsedName;
use crate::base::Record;
use crate::base::RelativeName;
use crate::base::Rtype;
use crate::base::ToName;
use crate::dep::octseq::Octets;
use crate::dep::octseq::OctetsFrom;
use crate::dep::octseq::OctetsInto;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
use crate::rdata::AllRecordData;
use crate::rdata::Dnskey;
use crate::rdata::Ds;
use crate::rdata::ZoneRecordData;
use crate::utils::config::DefMinMax;
use crate::validate::supported_algorithm;
use crate::validate::supported_digest;
use crate::validate::DnskeyExt;
use bytes::Bytes;
use moka::future::Cache;
use std::cmp::min;
use std::collections::VecDeque;
use std::fmt::Debug;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::vec::Vec;

/// Configuration limit for the maximum number of entries in the node cache.
const MAX_NODE_CACHE: DefMinMax<u64> = DefMinMax::new(100, 1, 1_000_000_000);

/// Configuration limit for the maximum number of entries in the NSEC3 hash
/// cache.
const MAX_NSEC3_CACHE: DefMinMax<u64> = DefMinMax::new(100, 1, 1_000_000_000);

/// Configuration limit for the maximum number of entries in the internal
/// signature cache.
const MAX_ISIG_CACHE: DefMinMax<u64> = DefMinMax::new(1000, 1, 1_000_000_000);

/// Configuration limit for the maximum number of entries in the user
/// signature cache.
const MAX_USIG_CACHE: DefMinMax<u64> = DefMinMax::new(1000, 1, 1_000_000_000);

/// Limit on the maximum time a node cache entry is considered valid.
///
/// According to [RFC 8767](https://www.rfc-editor.org/info/rfc8767) the
/// limit should be on the order of days to weeks with a recommended cap of
/// 604800 seconds (7 days).
const MAX_NODE_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(604800),
    Duration::from_secs(60),
    Duration::from_secs(6048000),
);

/// Limit on the maximum time a bogus node cache entry is considered valid.
///
/// According to [RFC 9520](https://www.rfc-editor.org/info/rfc9520)
/// at least 1 second and at most 5 minutes.
const MAX_BOGUS_VALIDITY: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(30),
    Duration::from_secs(1),
    Duration::from_secs(5 * 60),
);

/// Limit on the number of signature validation errors during the validation
/// of an RRset.
///
/// The minimum is 1 to support tag collisions, the maximum is 8, because
/// this what unbound currently uses, the default is 1 because we expect at
/// most 1 key tag collision and we expect signatures to be valid.
const MAX_BAD_SIGNATURES: DefMinMax<u8> = DefMinMax::new(1, 1, 8);

/// Number of NSEC3 iterations above which the result is insecure.
///
/// The minimum is 0, the maximum is 500, because
/// this what [RFC 9276](https://www.rfc-editor.org/info/rfc9276) recommends
/// for bogus, the default as recommended in RFC 9276 is 100.
const NSEC3_ITER_INSECURE: DefMinMax<u16> = DefMinMax::new(100, 0, 500);

/// Number of NSEC3 iterations above which the result is bogus.
///
/// The minimum is 0, the maximum is 500, because
/// this what [RFC 9276](https://www.rfc-editor.org/info/rfc9276) recommends
/// for bogus, the default as recommended in RFC 9276 is 500.
const NSEC3_ITER_BOGUS: DefMinMax<u16> = DefMinMax::new(500, 0, 500);

/// Maximum number of CNAME and DNAME records that are followed during
/// validation.
///
/// The minimum is 0, the maximum is 100,
/// the default as used in unbound is 11.
const MAX_CNAME_DNAME: DefMinMax<u8> = DefMinMax::new(11, 0, 100);

//------------ Config ---------------------------------------------------------

/// Configuration of a validator.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum number of cache entries for the node cache.
    max_node_cache: u64,

    /// Maximum number of cache entries for the NSEC3 hash cache.
    max_nsec3_cache: u64,

    /// Maximum number of cache entries for the internal signature cache.
    max_isig_cache: u64,

    /// Maximum number of cache entries for the user signature cache.
    max_usig_cache: u64,

    /// Limit of the amount of time a node can be cached.
    max_node_validity: Duration,

    /// Limit of the amount of time a bogus node can be cached.
    max_bogus_validity: Duration,

    /// Limit on the number of signature validation failures
    max_bad_signatures: u8,

    /// NSEC3 interation count above which the NSEC3 hash is not checked
    /// and the validation status is considered insecure.
    nsec3_iter_insecure: u16,

    /// NSEC3 interation count above which the NSEC3 hash is not checked
    /// and the validation status is considered bogus.
    nsec3_iter_bogus: u16,

    /// Maximum number of CNAME and DNAME records that are followed
    /// during validation.
    max_cname_dname: u8,
}

impl Config {
    /// Creates a new config with default values.
    ///
    /// The default values are documented at the relevant set_* methods.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the maximum number of node cache entries.
    ///
    /// The value has to be at least one, at most 1,000,000,000 and the
    /// default is 100.
    ///
    /// The values are just best guesses at the moment. The upper limit is
    /// set to be somewhat safe without being too limiting. The default is
    /// meant to be reasonable for a small system.
    pub fn set_max_node_cache(&mut self, value: u64) {
        self.max_node_cache = MAX_NODE_CACHE.limit(value)
    }

    /// Set the maximum number of NSEC3 hash cache entries.
    ///
    /// The value has to be at least one, at most 1,000,000,000 and the
    /// default is 100.
    ///
    /// The values are just best guesses at the moment. The upper limit is
    /// set to be somewhat safe without being too limiting. The default is
    /// meant to be reasonable for a small system.
    pub fn set_max_nsec3_cache(&mut self, value: u64) {
        self.max_node_cache = MAX_NSEC3_CACHE.limit(value)
    }

    /// Set the maximum number of internal signature cache entries.
    ///
    /// The value has to be at least one, at most 1,000,000,000 and the
    /// default is 1000.
    ///
    /// The values are just best guesses at the moment. The upper limit is
    /// set to be somewhat safe without being too limiting. The default is
    /// meant to be reasonable for a small system.
    pub fn set_max_isig_cache(&mut self, value: u64) {
        self.max_isig_cache = MAX_ISIG_CACHE.limit(value)
    }

    /// Set the maximum number of user signature cache entries.
    ///
    /// The value has to be at least one, at most 1,000,000,000 and the
    /// default is 1000.
    ///
    /// The values are just best guesses at the moment. The upper limit is
    /// set to be somewhat safe without being too limiting. The default is
    /// meant to be reasonable for a small system.
    pub fn set_max_usig_cache(&mut self, value: u64) {
        self.max_usig_cache = MAX_USIG_CACHE.limit(value)
    }

    /// Set the maximum validity of node cache entries.
    ///
    /// The value has to be at least 60 seconds, at most 6,048,000 seconds
    /// (10 weeks) and the default is 604800 seconds (one week).
    pub fn set_max_validity(&mut self, value: Duration) {
        self.max_node_validity = MAX_NODE_VALIDITY.limit(value)
    }

    pub(crate) fn max_bogus_validity(&self) -> Duration {
        self.max_bogus_validity
    }

    /// Set the maximum validity of bogus node cache entries.
    ///
    /// The value has to be at least one second, at most 300 seconds
    /// (five minutes) and the default is 30 seconds.
    pub fn set_max_bogus_validity(&mut self, value: Duration) {
        self.max_bogus_validity = MAX_BOGUS_VALIDITY.limit(value)
    }

    pub(crate) fn max_bad_signatures(&self) -> u8 {
        self.max_bad_signatures
    }

    /// Set the maximum number of signature validation errors for validating
    /// a single RRset.
    ///
    /// The value has to be at least one, at most eight and the default is one.
    pub fn set_bad_signatures(&mut self, value: u8) {
        self.max_bad_signatures = MAX_BAD_SIGNATURES.limit(value)
    }

    pub(crate) fn nsec3_iter_insecure(&self) -> u16 {
        self.nsec3_iter_insecure
    }

    /// Set the number of NSEC3 iterations above which the result is
    /// considered insecure.
    ///
    /// The value has to be at least zero, at most five hundred and the
    /// default is one hundred.
    pub fn set_nsec3_iter_insecure(&mut self, value: u16) {
        self.nsec3_iter_insecure = NSEC3_ITER_INSECURE.limit(value)
    }

    pub(crate) fn nsec3_iter_bogus(&self) -> u16 {
        self.nsec3_iter_bogus
    }

    /// Set the number of NSEC3 iterations above which the result is
    /// considered bogus.
    ///
    /// The value has to be at least zero, at most five hundred and the
    /// default is one five hundred.
    pub fn set_nsec3_iter_bogus(&mut self, value: u16) {
        self.nsec3_iter_bogus = NSEC3_ITER_INSECURE.limit(value)
    }

    pub(crate) fn max_cname_dname(&self) -> u8 {
        self.max_cname_dname
    }

    /// Set the maximum number of CNAME and DNAME records that are followed
    /// during validation.
    ///
    /// The value has to be at least zero, at most one hundred and the
    /// default is one eleven.
    pub fn set_max_cname_dname(&mut self, value: u8) {
        self.max_cname_dname = MAX_CNAME_DNAME.limit(value)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_node_cache: MAX_NODE_CACHE.default(),
            max_nsec3_cache: MAX_NSEC3_CACHE.default(),
            max_isig_cache: MAX_ISIG_CACHE.default(),
            max_usig_cache: MAX_USIG_CACHE.default(),
            max_node_validity: MAX_NODE_VALIDITY.default(),
            max_bogus_validity: MAX_BOGUS_VALIDITY.default(),
            max_bad_signatures: MAX_BAD_SIGNATURES.default(),
            nsec3_iter_insecure: NSEC3_ITER_INSECURE.default(),
            nsec3_iter_bogus: NSEC3_ITER_BOGUS.default(),
            max_cname_dname: MAX_CNAME_DNAME.default(),
        }
    }
}

//------------ ValidationContext ----------------------------------------------

enum VGResult {
    Groups(Vec<ValidatedGroup>, bool),
    Bogus(Option<ExtendedError<Vec<u8>>>),
    Err(Error),
}

pub struct ValidationContext<Upstream> {
    ta: TrustAnchors,
    upstream: Upstream,
    config: Config,

    node_cache: Cache<Name<Bytes>, Arc<Node>>,
    nsec3_cache: Nsec3Cache,
    isig_cache: SigCache, // Signature cache for infrastructure.
    usig_cache: SigCache, // Signature cache for user requests.
}

impl<Upstream> ValidationContext<Upstream> {
    pub fn new(ta: TrustAnchors, upstream: Upstream) -> Self {
        Self::with_config(ta, upstream, Default::default())
    }

    pub fn with_config(
        ta: TrustAnchors,
        upstream: Upstream,
        config: Config,
    ) -> Self {
        Self {
            ta,
            upstream,
            node_cache: Cache::new(config.max_node_cache),
            nsec3_cache: Nsec3Cache::new(config.max_nsec3_cache),
            isig_cache: SigCache::new(config.max_isig_cache),
            usig_cache: SigCache::new(config.max_usig_cache),
            config,
        }
    }

    // On success, return the validation state and an optionally an extended DNS
    // error.
    pub async fn validate_msg<'a, MsgOcts, USOcts>(
        &self,
        msg: &'a mut Message<MsgOcts>,
    ) -> Result<(ValidationState, Option<ExtendedError<Vec<u8>>>), Error>
    where
        MsgOcts: Clone + Debug + Octets + OctetsFrom<Vec<u8>> + 'a,
        <MsgOcts as Octets>::Range<'a>: Debug,
        USOcts: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<USOcts>>,
    {
        // Convert to Bytes.
        let bytes = Bytes::copy_from_slice(msg.as_slice());
        let bytes_msg = Message::from_octets(bytes)?;

        // First convert the Answer and Authority sections to lists of RR groups
        let mut answers = GroupSet::new();
        for rr in bytes_msg.answer()? {
            answers.add(rr?)?;
        }
        let mut authorities = GroupSet::new();
        for rr in bytes_msg.authority()? {
            authorities.add(rr?)?;
        }

        // Mark redundant unsigned CNAMEs.
        answers.mark_redundant_cnames();

        let mut fix_reply = false;

        // Validate each group. We cannot use iter_mut because it requires a
        // reference with a lifetime that is too long.
        // Group can handle this by hiding the state behind a Mutex.
        let mut answers = match self.validate_groups(&mut answers).await {
            VGResult::Groups(vgs, needs_fix) => {
                fix_reply |= needs_fix;
                vgs
            }
            VGResult::Bogus(ede) => return Ok((ValidationState::Bogus, ede)),
            VGResult::Err(err) => return Err(err),
        };

        let mut authorities = match self
            .validate_groups(&mut authorities)
            .await
        {
            VGResult::Groups(vgs, needs_fix) => {
                fix_reply |= needs_fix;
                vgs
            }
            VGResult::Bogus(ede) => return Ok((ValidationState::Bogus, ede)),
            VGResult::Err(err) => return Err(err),
        };

        // We may need to update TTLs of signed RRsets
        if fix_reply {
            *msg = rebuild_msg(&bytes_msg, &answers, &authorities)?;
        }

        // Go through the answers and use CNAME and DNAME records to update 'SNAME'
        // (see RFC 1034, Section 5.3.2) to the final name that results in an
        // answer, NODATA, or NXDOMAIN. First extract QNAME/QCLASS/QTYPE. Require
        // that the question section has only one entry. Return FormError if that
        // is not the case (following draft-bellis-dnsop-qdcount-is-one-00)

        // Extract Qname, Qclass, Qtype
        let mut question_section = bytes_msg.question();
        let question = match question_section.next() {
            None => {
                return Err(Error::FormError);
            }
            Some(question) => question?,
        };
        if question_section.next().is_some() {
            return Err(Error::FormError);
        }
        let qname: Name<Bytes> = question.qname().to_name();
        let qclass = question.qclass();
        let qtype = question.qtype();

        // A secure answer may actually be insecure if there is an insecure
        // CNAME or DNAME in the chain. Start by assume that secure is secure
        // and downgrade if required.
        let maybe_secure = ValidationState::Secure;

        let (sname, state, ede) = do_cname_dname(
            qname,
            qclass,
            qtype,
            &mut answers,
            &mut authorities,
            self.nsec3_cache(),
            &self.config,
        )
        .await;

        let maybe_secure = map_maybe_secure(state, maybe_secure);
        if maybe_secure == ValidationState::Bogus {
            return Ok((maybe_secure, ede));
        }

        // For NOERROR, check if the answer is positive. Then extract the status
        // of the group and be done.
        // For NODATA first get the SOA, this determines if the proof of a
        // negative result is signed or not.
        if bytes_msg.opt_rcode() == OptRcode::NOERROR {
            let opt_state =
                get_answer_state(&sname, qclass, qtype, &mut answers);
            if let Some((state, signer_name, closest_encloser, ede)) =
                opt_state
            {
                if state != ValidationState::Secure {
                    // No need to check the wildcard, either because the state
                    // is not secure.
                    return Ok((map_maybe_secure(state, maybe_secure), ede));
                }
                let closest_encloser = match closest_encloser {
                    None => {
                        // There is no wildcard.
                        return Ok((
                            map_maybe_secure(state, maybe_secure),
                            ede,
                        ));
                    }
                    Some(ce) => ce,
                };

                // It is possible that the request was for the actualy wildcard.
                // In that we we do not need to prove that sname does not exist.
                let star_name = match star_closest_encloser(&closest_encloser)
                {
                    Ok(name) => name,
                    Err(_) => {
                        // We cannot create the wildcard name.
                        let ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "cannot create wildcard record",
                        );
                        return Ok((ValidationState::Bogus, ede));
                    }
                };

                if sname == star_name {
                    // We are done.
                    return Ok((map_maybe_secure(state, maybe_secure), ede));
                }

                let (check, state, ede) = check_not_exists_for_wildcard(
                    &sname,
                    &mut authorities,
                    &signer_name,
                    &closest_encloser,
                    self.nsec3_cache(),
                    &self.config,
                )
                .await;

                if check {
                    return Ok((map_maybe_secure(state, maybe_secure), ede));
                }

                // Report failure
                return Ok((ValidationState::Bogus, ede));
            }
        }

        // For both NOERROR/NODATA and for NXDOMAIN we can first look at the SOA
        // record in the authority section. If there is no SOA, return bogus. If
        // there is one and the state is not secure, then return the state of the
        // SOA record.
        let signer_name =
            match get_soa_state(&sname, qclass, &mut authorities) {
                (None, ede) => {
                    let ede = match ede {
                        Some(ede) => Some(ede),
                        None => make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "Missing SOA record for NODATA or NXDOMAIN",
                        ),
                    };
                    return Ok((ValidationState::Bogus, ede)); // No SOA, assume the worst.
                }
                (Some((state, signer_name)), ede) => match state {
                    ValidationState::Secure => signer_name, // Continue validation.
                    ValidationState::Insecure
                    | ValidationState::Bogus
                    | ValidationState::Indeterminate => {
                        return Ok((state, ede));
                    }
                },
            };

        if bytes_msg.opt_rcode() == OptRcode::NOERROR {
            // Try to prove that the name exists but the qtype doesn't. Start
            // with NSEC and assume the name exists.
            let (state, ede) = nsec_for_nodata(
                &sname,
                &mut authorities,
                qtype,
                &signer_name,
            );
            match state {
                NsecState::NoData => {
                    return Ok((
                        map_maybe_secure(
                            ValidationState::Secure,
                            maybe_secure,
                        ),
                        ede,
                    ))
                }
                NsecState::Nothing => (), // Try something else.
            }

            // Try to prove that the name does not exist and that a wildcard
            // exists but does not have the requested qtype.
            let (state, ede) = nsec_for_nodata_wildcard(
                &sname,
                &mut authorities,
                qtype,
                &signer_name,
            );
            match state {
                NsecState::NoData => {
                    return Ok((
                        map_maybe_secure(
                            ValidationState::Secure,
                            maybe_secure,
                        ),
                        ede,
                    ))
                }
                NsecState::Nothing => (), // Try something else.
            }

            // Try to prove that the name exists but the qtype doesn't. Continue
            // with NSEC3 and assume the name exists.
            let (state, ede) = nsec3_for_nodata(
                &sname,
                &mut authorities,
                qtype,
                &signer_name,
                self.nsec3_cache(),
                &self.config,
            )
            .await;
            match state {
                Nsec3State::NoData => {
                    return Ok((
                        map_maybe_secure(
                            ValidationState::Secure,
                            maybe_secure,
                        ),
                        None,
                    ))
                }
                Nsec3State::Nothing => (), // Try something else.
                Nsec3State::NoDataInsecure =>
                // totest, NSEC3 NODATA with opt-out
                {
                    return Ok((ValidationState::Insecure, ede))
                }
                Nsec3State::Bogus => {
                    return Ok((ValidationState::Bogus, ede))
                }
            }

            // RFC 5155, Section 8.6. If there is a closest encloser and
            // the NSEC3 RR that covers the "next closer" name has the Opt-Out
            // bit set then we have an insecure proof that the DS record does
            // not exist.
            // Then Errata 3441 says that we need to do the same thing for other
            // types.
            let (state, ede) = nsec3_for_not_exists(
                &sname,
                &mut authorities,
                &signer_name,
                self.nsec3_cache(),
                &self.config,
            )
            .await;
            let ce = match state {
                Nsec3NXState::DoesNotExist(ce) => ce, // Continue with wildcard.
                Nsec3NXState::DoesNotExistInsecure(_) => {
                    // Something might exist. Just return insecure here.
                    return Ok((ValidationState::Insecure, ede));
                }
                Nsec3NXState::Bogus => {
                    return Ok((ValidationState::Bogus, ede))
                }
                Nsec3NXState::Insecure => {
                    return Ok((ValidationState::Insecure, ede))
                }
                Nsec3NXState::Nothing =>
                // totest, missing NSEC3 for not exist.
                {
                    return Ok((ValidationState::Bogus, ede))
                }
            };

            let star_name = match star_closest_encloser(&ce) {
                Ok(name) => name,
                Err(_) => {
                    // The wildcard cannot be constructed. Just return bogus.
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "cannot create wildcard record",
                    );
                    return Ok((ValidationState::Bogus, ede));
                }
            };
            let (state, ede) = nsec3_for_nodata(
                &star_name,
                &mut authorities,
                qtype,
                &signer_name,
                self.nsec3_cache(),
                &self.config,
            )
            .await;
            match state {
                Nsec3State::NoData => {
                    return Ok((
                        map_maybe_secure(
                            ValidationState::Secure,
                            maybe_secure,
                        ),
                        None,
                    ));
                }
                Nsec3State::Nothing =>
                // totest, missing NSEC3 for wildcard.
                {
                    return Ok((ValidationState::Bogus, ede))
                }
                Nsec3State::NoDataInsecure => {
                    return Ok((ValidationState::Insecure, ede))
                }
                Nsec3State::Bogus => {
                    return Ok((ValidationState::Bogus, ede))
                }
            }
        }

        // Prove NXDOMAIN.
        // Try to prove that the name does not exist using NSEC.
        let (state, ede) =
            nsec_for_nxdomain(&sname, &mut authorities, &signer_name);
        match state {
            NsecNXState::Exists => {
                return Ok((ValidationState::Bogus, ede));
            }
            NsecNXState::DoesNotExist(_) => {
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    ede,
                ))
            }
            NsecNXState::Nothing => (), // Try something else.
        }

        // Try to prove that the name does not exist using NSEC3.
        let (state, mut ede) = nsec3_for_nxdomain(
            &sname,
            &mut authorities,
            &signer_name,
            self.nsec3_cache(),
            &self.config,
        )
        .await;
        match state {
            Nsec3NXState::DoesNotExist(_) => {
                return Ok((
                    map_maybe_secure(ValidationState::Secure, maybe_secure),
                    None,
                ))
            }
            Nsec3NXState::DoesNotExistInsecure(_) => {
                return Ok((ValidationState::Insecure, ede));
            }
            Nsec3NXState::Bogus => return Ok((ValidationState::Bogus, ede)),
            Nsec3NXState::Insecure => {
                return Ok((ValidationState::Insecure, ede))
            }
            Nsec3NXState::Nothing => (), // Try something else.
        }

        if ede.is_none() {
            ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "No NEC/NSEC3 proof for non-existance",
            );
        }
        Ok((ValidationState::Bogus, ede))
    }

    pub(crate) async fn get_node<Octs>(
        &self,
        name: &Name<Bytes>,
    ) -> Result<Arc<Node>, Error>
    where
        Octs: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        // Check the cache first
        if let Some(node) = self.cache_lookup(name).await {
            return Ok(node);
        }

        // Find a trust anchor.
        let Some(ta) = self.ta.find(name) else {
            // Try to get an indeterminate node for the root
            let node = Node::indeterminate(
                Name::root(),
                make_ede(
                    ExtendedErrorCode::DNSSEC_INDETERMINATE,
                    "No trust anchor for root.",
                ),
                self.config.max_node_validity,
            );
            let node = Arc::new(node);
            self.node_cache.insert(Name::root(), node.clone()).await;
            return Ok(node);
        };

        let ta_owner = ta.owner();
        if ta_owner.name_eq(name) {
            // The trust anchor is the same node we are looking for. Create
            // a node for the trust anchor.
            let node = Node::trust_anchor(
                ta,
                &self.upstream,
                &self.isig_cache,
                &self.config,
            )
            .await?;
            let node = Arc::new(node);
            self.node_cache.insert(name.clone(), node.clone()).await;
            return Ok(node);
        }

        // Walk from the parent of name back to trust anchor.
        // Keep a list of names we need to walk in the other direction.
        let (mut node, mut names) =
            self.find_closest_node(name, ta, ta_owner).await?;

        // Assume that node is not an intermediate node. We have to make sure
        // in find_closest_node.
        let mut signer_node = node.clone();

        // Walk from the closest node to name.
        loop {
            match node.validation_state() {
                ValidationState::Secure => (), // continue
                ValidationState::Insecure | ValidationState::Bogus => {
                    return Ok(node)
                }
                ValidationState::Indeterminate => {
                    // totest, negative trust anchors
                    return Ok(node);
                }
            }

            // Create the child node
            let child_name = match names.pop_front() {
                Some(name) => name,
                None => {
                    // This should not happen. But the easy way out is to
                    // just return node.
                    return Ok(node);
                }
            };

            // If this node is an intermediate node then get the node for
            // signer name.
            node = Arc::new(
                self.create_child_node(child_name.clone(), &signer_node)
                    .await?,
            );
            self.node_cache.insert(child_name, node.clone()).await;
            if !node.intermediate() {
                signer_node = node.clone();
            }

            if names.is_empty() {
                return Ok(node);
            }
        }
    }

    async fn find_closest_node<Octs>(
        &self,
        name: &Name<Bytes>,
        ta: &TrustAnchor,
        ta_owner: Name<Bytes>,
    ) -> Result<(Arc<Node>, VecDeque<Name<Bytes>>), Error>
    where
        Octs: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        let mut names = VecDeque::new();
        names.push_front(name.clone());
        let mut curr = name
            .parent()
            .expect("name has to be a decendent of ta_owner");
        loop {
            if ta_owner.name_eq(&curr) {
                // We ended up at the trust anchor.
                let node = Node::trust_anchor(
                    ta,
                    &self.upstream,
                    &self.isig_cache,
                    &self.config,
                )
                .await?;
                let node = Arc::new(node);
                self.node_cache.insert(curr, node.clone()).await;
                return Ok((node, names));
            }

            // Try to find the node in the cache.
            if let Some(node) = self.cache_lookup(&curr).await {
                return Ok((node, names));
            }

            names.push_front(curr.clone());

            curr = curr
                .parent()
                .expect("curr has to be a decendent of ta_owner");
        }
    }

    async fn create_child_node<Octs>(
        &self,
        name: Name<Bytes>,
        node: &Node,
    ) -> Result<Node, Error>
    where
        Octs: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        // Start with a DS lookup.
        let (mut answers, mut authorities, ede) =
            request_as_groups(&self.upstream, &name, Rtype::DS).await?;

        if ede.is_some() {
            // We cannot continue if we need a reply to DS query but didn't
            // get one.
            return Ok(Node::new_delegation(
                name,
                ValidationState::Bogus,
                Vec::new(),
                ede,
                self.config.max_bogus_validity,
            ));
        }

        // Limit the validity of the child node to the one of the parent.
        let parent_ttl = node.ttl();

        let ds_group = match answers
            .iter()
            .find(|g| g.rtype() == Rtype::DS && g.owner() == name)
        {
            Some(g) => g,
            None => {
                // It is possible that we asked for a non-terminal that
                // contains a CNAME. In that case the answer section should
                // contain a signed CNAME and we can conclude a
                // secure intermediate node.
                for g in answers.iter().filter(|g| g.rtype() == Rtype::CNAME)
                {
                    if g.owner() != name {
                        continue;
                    }
                    // Found matching CNAME.
                    let g_ttl = g.min_ttl().into_duration();
                    let ttl = min(parent_ttl, g_ttl);

                    let (state, _wildcard, ede, sig_ttl, _) = g
                        .validate_with_node(
                            node,
                            &self.isig_cache,
                            &self.config,
                        )
                        .await;

                    let ttl = min(ttl, sig_ttl);

                    match state {
                        ValidationState::Secure => (),
                        ValidationState::Insecure
                        | ValidationState::Indeterminate => {
                            // totest, insecure CNAME when looking for DS
                            return Ok(Node::new_intermediate(
                                name,
                                ValidationState::Insecure,
                                node.signer_name().clone(),
                                ede,
                                ttl,
                            ));
                        }
                        ValidationState::Bogus => {
                            return Ok(Node::new_delegation(
                                name,
                                ValidationState::Bogus,
                                Vec::new(),
                                ede,
                                ttl,
                            ));
                        }
                    }

                    // Do we need to check if the CNAME record is a
                    // wildcard?
                    return Ok(Node::new_intermediate(
                        name,
                        ValidationState::Secure,
                        node.signer_name().clone(),
                        ede,
                        ttl,
                    ));
                }

                // Verify proof that DS doesn't exist for this name.
                let (state, ttl, ede) = nsec_for_ds(
                    &name,
                    &mut authorities,
                    node,
                    &self.isig_cache,
                    &self.config,
                )
                .await;
                match state {
                    CNsecState::InsecureDelegation => {
                        // An insecure delegation is normal enough that
                        // it does not need an EDE.
                        let ttl = min(parent_ttl, ttl);
                        return Ok(Node::new_delegation(
                            name,
                            ValidationState::Insecure,
                            Vec::new(),
                            ede,
                            ttl,
                        ));
                    }
                    CNsecState::SecureIntermediate => {
                        return Ok(Node::new_intermediate(
                            name,
                            ValidationState::Secure,
                            node.signer_name().clone(),
                            ede,
                            ttl,
                        ))
                    }
                    CNsecState::Bogus => {
                        return Ok(Node::new_delegation(
                            name,
                            ValidationState::Bogus,
                            Vec::new(),
                            ede,
                            ttl,
                        ))
                    }
                    CNsecState::Nothing => (), // Try NSEC3 next.
                }

                let (state, ede, ttl) = nsec3_for_ds(
                    &name,
                    &mut authorities,
                    node,
                    self.nsec3_cache(),
                    &self.isig_cache,
                    &self.config,
                )
                .await;
                match state {
                    CNsecState::InsecureDelegation => {
                        return Ok(Node::new_delegation(
                            name,
                            ValidationState::Insecure,
                            Vec::new(),
                            ede,
                            ttl,
                        ))
                    }
                    CNsecState::SecureIntermediate => {
                        return Ok(Node::new_intermediate(
                            name,
                            ValidationState::Secure,
                            node.signer_name().clone(),
                            ede,
                            ttl,
                        ))
                    }
                    CNsecState::Bogus => {
                        return Ok(Node::new_delegation(
                            name,
                            ValidationState::Bogus,
                            Vec::new(),
                            ede,
                            ttl,
                        ))
                    }
                    CNsecState::Nothing => (),
                }

                // Both NSEC and NSEC3 failed. Create a new node with
                // bogus state.
                return Ok(Node::new_delegation(
                    name,
                    ValidationState::Bogus,
                    Vec::new(),
                    ede,
                    ttl,
                ));
            }
        };

        // TODO: Limit the size of the DS RRset.
        let ds_ttl = ds_group.min_ttl().into_duration();
        let ttl = min(parent_ttl, ds_ttl);

        let (state, _wildcard, ede, sig_ttl, _) = ds_group
            .validate_with_node(node, &self.isig_cache, &self.config)
            .await;

        let ttl = min(ttl, sig_ttl);

        match state {
            ValidationState::Secure => (),
            ValidationState::Insecure
            | ValidationState::Indeterminate
            | ValidationState::Bogus => {
                // Insecure or Indeterminate cannot happen. But it is better
                // to return bogus than to panic.
                return Ok(Node::new_delegation(
                    name,
                    ValidationState::Bogus,
                    Vec::new(),
                    ede,
                    ttl,
                ));
            }
        }

        // Do we need to check if the DS record is a wildcard?

        // We got valid DS records.

        // RFC 4035, Section: 5.2:
        // If the validator does not support any of the algorithms listed in
        // an authenticated DS RRset, then the resolver has no supported
        // authentication path leading from the parent to the child.  The
        // resolver should treat this case as it would the case of an
        // authenticated NSEC RRset proving that no DS RRset exists, as
        // described above.

        // RFC 6840, Section 5.2:
        // In brief, DS records using unknown or unsupported message digest
        // algorithms MUST be treated the same way as DS records referring
        // to DNSKEY RRs of unknown or unsupported public key algorithms.
        //
        // In other words, when determining the security status of a zone, a
        // validator disregards any authenticated DS records that specify
        // unknown or unsupported DNSKEY algorithms.  If none are left, the
        // zone is treated as if it were unsigned.
        //
        // This document modifies the above text to additionally disregard
        // authenticated DS records using unknown or unsupported message
        // digest algorithms.
        let mut tmp_group = ds_group.clone();
        let valid_algs = tmp_group
            .rr_iter()
            .map(|r| {
                if let AllRecordData::Ds(ds) = r.data() {
                    (ds.algorithm(), ds.digest_type())
                } else {
                    panic!("DS record expected");
                }
            })
            .any(|(alg, dig)| {
                supported_algorithm(&alg) && supported_digest(&dig)
            });

        if !valid_algs {
            // Delegation is insecure
            let ede = make_ede(
                ExtendedErrorCode::OTHER,
                "No supported algorithm in DS RRset",
            );
            return Ok(Node::new_delegation(
                name,
                ValidationState::Insecure,
                Vec::new(),
                ede,
                ttl,
            ));
        }

        // Get the DNSKEY RRset.
        let (mut answers, _, ede) =
            request_as_groups(&self.upstream, &name, Rtype::DNSKEY).await?;

        if ede.is_some() {
            // We cannot continue if we need a reply to DNSKEY query but didn't
            // get one.
            return Ok(Node::new_delegation(
                name,
                ValidationState::Bogus,
                Vec::new(),
                ede,
                self.config.max_bogus_validity,
            ));
        }

        let dnskey_group =
            match answers.iter().find(|g| g.rtype() == Rtype::DNSKEY) {
                Some(g) => g,
                None => {
                    // totest, no DNSKEY in reply to DNSKEY request
                    // No DNSKEY RRset, set validation state to bogus.
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "No DNSKEY found",
                    );
                    return Ok(Node::new_delegation(
                        name,
                        ValidationState::Bogus,
                        Vec::new(),
                        ede,
                        self.config.max_bogus_validity,
                    ));
                }
            };

        let dnskey_ttl = dnskey_group.min_ttl().into_duration();
        let ttl = min(ttl, dnskey_ttl);

        // TODO: Limit the size of the DNSKEY RRset.

        // Try to find one DNSKEY record that matches a DS record and that
        // can be used to validate the DNSKEY RRset.

        let mut bad_sigs = 0;
        let mut ede = None;
        for ds in tmp_group
            .rr_iter()
            .map(|r| {
                if let AllRecordData::Ds(ds) = r.data() {
                    ds
                } else {
                    panic!("DS record expected");
                }
            })
            .filter(|ds| {
                supported_algorithm(&ds.algorithm())
                    && supported_digest(&ds.digest_type())
            })
        {
            let r_dnskey = match find_key_for_ds(ds, dnskey_group) {
                None => continue,
                Some(r) => r,
            };
            let dnskey =
                if let AllRecordData::Dnskey(dnskey) = r_dnskey.data() {
                    dnskey
                } else {
                    panic!("expected DNSKEY");
                };
            let key_tag = dnskey.key_tag();
            let key_name = r_dnskey.owner().to_name();
            for sig in (*dnskey_group).clone().sig_iter() {
                if sig.data().key_tag() != key_tag {
                    continue; // Signature from wrong key
                }
                if dnskey_group
                    .check_sig_cached(
                        sig,
                        &key_name,
                        dnskey,
                        &key_name,
                        key_tag,
                        &self.isig_cache,
                    )
                    .await
                {
                    let dnskey_vec: Vec<_> = dnskey_group
                        .clone()
                        .rr_iter()
                        .map(|r| {
                            if let AllRecordData::Dnskey(key) = r.data() {
                                key
                            } else {
                                panic!("Dnskey expected");
                            }
                        })
                        .cloned()
                        .collect();

                    let sig_ttl = ttl_for_sig(sig).into_duration();
                    let ttl = min(ttl, sig_ttl);

                    return Ok(Node::new_delegation(
                        key_name,
                        ValidationState::Secure,
                        dnskey_vec,
                        None,
                        ttl,
                    ));
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
                    if bad_sigs > self.config.max_bad_signatures {
                        // totest, too many bad signatures for DNSKEY
                        let ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "too many bad signatures for DNSKEY",
                        );
                        return Ok(Node::new_delegation(
                            name,
                            ValidationState::Bogus,
                            Vec::new(),
                            ede,
                            self.config.max_bogus_validity,
                        ));
                    }
                    if ede.is_none() {
                        ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "too many bad signature for DNSKEY",
                        );
                    }
                }
            }

            // We found a DNSKEY that match a DS, but no valid signatures
            // from this key on the DNSKEY RRset. Try the next key.
        }

        // totest, no DNSKEY without signatures
        // totest, DNSKEY with 1 failing signatures
        if ede.is_none() {
            ede = make_ede(ExtendedErrorCode::DNSSEC_BOGUS, "No signature");
        }
        Ok(Node::new_delegation(
            name,
            ValidationState::Bogus,
            Vec::new(),
            ede,
            self.config.max_bogus_validity,
        ))
    }

    async fn cache_lookup(&self, name: &Name<Bytes>) -> Option<Arc<Node>> {
        let ce = self.node_cache.get(name).await?;
        if ce.expired() {
            return None;
        }
        Some(ce)
    }

    pub(crate) fn nsec3_cache(&self) -> &Nsec3Cache {
        &self.nsec3_cache
    }

    pub(crate) fn usig_cache(&self) -> &SigCache {
        &self.usig_cache
    }

    async fn validate_groups<Octs>(&self, groups: &mut GroupSet) -> VGResult
    where
        Octs: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        let mut fix_reply = false;
        let mut vgs = Vec::new();
        for g in groups.iter() {
            let vg = match g.validated(self, &self.config).await {
                Ok(vg) => vg,
                Err(err) => return VGResult::Err(err),
            };
            if let ValidationState::Bogus = vg.state() {
                return VGResult::Bogus(vg.ede());
            }
            if vg.adjust_ttl().is_some() {
                fix_reply = true;
            }
            vgs.push(vg);
        }
        VGResult::Groups(vgs, fix_reply)
    }
}

#[derive(Clone)]
pub(crate) struct Node {
    state: ValidationState,

    // This should be part of the state of the node
    keys: Vec<Dnskey<Bytes>>,
    signer_name: Name<Bytes>,
    intermediate: bool,
    ede: Option<ExtendedError<Vec<u8>>>,

    // Time to live
    created_at: Instant,
    valid_for: Duration,
}

impl Node {
    fn indeterminate(
        name: Name<Bytes>,
        ede: Option<ExtendedError<Vec<u8>>>,
        valid_for: Duration,
    ) -> Self {
        Self {
            state: ValidationState::Indeterminate,
            keys: Vec::new(),
            signer_name: name,
            intermediate: false,
            ede,
            created_at: Instant::now(),
            valid_for,
        }
    }

    async fn trust_anchor<Octs, Upstream>(
        ta: &TrustAnchor,
        upstream: &Upstream,
        sig_cache: &SigCache,
        config: &Config,
    ) -> Result<Self, Error>
    where
        Octs: AsRef<[u8]>
            + Debug
            + Octets
            + OctetsFrom<Vec<u8>>
            + Send
            + Sync,
        Upstream: SendRequest<RequestMessage<Octs>>,
    {
        // Get the DNSKEY RRset for the trust anchor.
        let ta_owner = ta.owner();

        // We expect a positive reply so the authority section can be ignored.
        let (mut answers, _, _ede) =
            request_as_groups(upstream, &ta_owner, Rtype::DNSKEY).await?;
        // Get the DNSKEY group. We expect exactly one.
        let dnskeys =
            match answers.iter().find(|g| g.rtype() == Rtype::DNSKEY) {
                Some(dnskeys) => dnskeys,
                None => {
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "No DNSKEY RRset for trust anchor",
                    );
                    return Ok(Node::new_delegation(
                        ta_owner,
                        ValidationState::Bogus,
                        Vec::new(),
                        ede,
                        config.max_bogus_validity,
                    ));
                }
            };

        let mut bad_sigs = 0;
        let mut opt_ede: Option<ExtendedError<Vec<u8>>> = None;

        // Try to find one trust anchor key that can be used to validate
        // the DNSKEY RRset.
        for ta_rr in (*ta).clone().iter() {
            let opt_dnskey_rr = if ta_rr.rtype() == Rtype::DNSKEY {
                has_key(dnskeys, ta_rr)
            } else if ta_rr.rtype() == Rtype::DS {
                has_ds(dnskeys, ta_rr)
            } else {
                None
            };
            let dnskey_rr = if let Some(dnskey_rr) = opt_dnskey_rr {
                dnskey_rr
            } else {
                continue;
            };

            let ttl = config.max_node_validity;

            let dnskey_ttl = dnskeys.min_ttl().into_duration();
            let ttl = min(ttl, dnskey_ttl);

            let dnskey =
                if let AllRecordData::Dnskey(dnskey) = dnskey_rr.data() {
                    dnskey
                } else {
                    continue;
                };
            let key_tag = dnskey.key_tag();
            let key_name = dnskey_rr.owner().to_name();
            for sig in (*dnskeys).clone().sig_iter() {
                if sig.data().key_tag() != key_tag {
                    continue; // Signature from wrong key
                }
                if dnskeys
                    .check_sig_cached(
                        sig, &ta_owner, dnskey, &key_name, key_tag, sig_cache,
                    )
                    .await
                {
                    let sig_ttl = ttl_for_sig(sig).into_duration();
                    let ttl = min(ttl, sig_ttl);

                    let mut new_node = Self {
                        state: ValidationState::Secure,
                        keys: Vec::new(),
                        signer_name: ta_owner,
                        intermediate: false,
                        ede: None,
                        created_at: Instant::now(),
                        valid_for: ttl,
                    };
                    for key_rec in dnskeys.clone().rr_iter() {
                        if let AllRecordData::Dnskey(key) = key_rec.data() {
                            new_node.keys.push(key.clone());
                        }
                    }
                    return Ok(new_node);
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
                    if bad_sigs > config.max_bad_signatures {
                        // totest, too many bad signatures for DNSKEY for trust anchor
                        let ede = make_ede(
                            ExtendedErrorCode::DNSSEC_BOGUS,
                            "too many bad signatures for DNSKEY",
                        );
                        return Ok(Node::new_delegation(
                            ta_owner,
                            ValidationState::Bogus,
                            Vec::new(),
                            ede,
                            config.max_bogus_validity,
                        ));
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
        // totest, no DNSKEY without signatures for trust anchor
        // totest, DNSKEY with 1 failing signatures for trust anchor
        if opt_ede.is_none() {
            opt_ede =
                make_ede(ExtendedErrorCode::DNSSEC_BOGUS, "No signature");
        }
        Ok(Node::new_delegation(
            ta_owner,
            ValidationState::Bogus,
            Vec::new(),
            opt_ede,
            config.max_bogus_validity,
        ))
    }

    pub fn new_delegation(
        signer_name: Name<Bytes>,
        state: ValidationState,
        keys: Vec<Dnskey<Bytes>>,
        ede: Option<ExtendedError<Vec<u8>>>,
        valid_for: Duration,
    ) -> Self {
        Self {
            state,
            signer_name,
            keys,
            intermediate: false,
            ede,
            created_at: Instant::now(),
            valid_for,
        }
    }

    pub fn new_intermediate(
        _name: Name<Bytes>,
        state: ValidationState,
        signer_name: Name<Bytes>,
        ede: Option<ExtendedError<Vec<u8>>>,
        valid_for: Duration,
    ) -> Self {
        Self {
            state,
            signer_name,
            keys: Vec::new(),
            intermediate: true,
            ede,
            created_at: Instant::now(),
            valid_for,
        }
    }

    pub fn validation_state(&self) -> ValidationState {
        self.state
    }

    pub fn extended_error(&self) -> Option<ExtendedError<Vec<u8>>> {
        self.ede.clone()
    }

    pub fn keys(&self) -> &[Dnskey<Bytes>] {
        &self.keys
    }

    pub fn signer_name(&self) -> &Name<Bytes> {
        &self.signer_name
    }

    pub fn intermediate(&self) -> bool {
        self.intermediate
    }

    pub fn expired(&self) -> bool {
        let elapsed = self.created_at.elapsed();
        elapsed > self.valid_for
    }

    pub fn ttl(&self) -> Duration {
        self.valid_for - self.created_at.elapsed()
    }
}

#[allow(clippy::type_complexity)]
fn has_key(
    dnskeys: &Group,
    tkey: &Record<
        Chain<RelativeName<Bytes>, Name<Bytes>>,
        ZoneRecordData<Bytes, Chain<RelativeName<Bytes>, Name<Bytes>>>,
    >,
) -> Option<Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>> {
    let tkey_dnskey = if let ZoneRecordData::Dnskey(dnskey) = tkey.data() {
        dnskey
    } else {
        return None;
    };

    for key in (*dnskeys).clone().rr_iter() {
        let AllRecordData::Dnskey(key_dnskey) = key.data() else {
            continue;
        };
        if tkey.owner().to_name::<Bytes>() != key.owner() {
            continue;
        }
        if tkey.class() != key.class() {
            continue;
        }
        if tkey.rtype() != key.rtype() {
            continue;
        }
        if tkey_dnskey != key_dnskey {
            continue;
        }
        return Some(key.clone());
    }
    None
}

#[allow(clippy::type_complexity)]
fn has_ds(
    dnskeys: &Group,
    ta_rr: &Record<
        Chain<RelativeName<Bytes>, Name<Bytes>>,
        ZoneRecordData<Bytes, Chain<RelativeName<Bytes>, Name<Bytes>>>,
    >,
) -> Option<Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>> {
    let ds = if let ZoneRecordData::Ds(ds) = ta_rr.data() {
        ds
    } else {
        return None;
    };

    for key in (*dnskeys).clone().rr_iter() {
        let AllRecordData::Dnskey(key_dnskey) = key.data() else {
            continue;
        };
        if ta_rr.owner().to_name::<Bytes>() != key.owner() {
            continue;
        }
        if ta_rr.class() != key.class() {
            continue;
        }
        if ds.algorithm() != key_dnskey.algorithm() {
            continue;
        }
        if ds.key_tag() != key_dnskey.key_tag() {
            continue;
        }

        // No need to check key.rtype(). We know it is DNSKEY

        let digest = match key_dnskey.digest(key.owner(), ds.digest_type()) {
            Ok(d) => d,
            Err(_) => {
                // Skip key if we get an error.
                continue;
            }
        };
        if digest.as_ref() != ds.digest() {
            continue;
        }
        return Some(key.clone());
    }
    None
}

#[allow(clippy::type_complexity)]
fn find_key_for_ds(
    ds: &Ds<Bytes>,
    dnskey_group: &Group,
) -> Option<Record<Name<Bytes>, AllRecordData<Bytes, ParsedName<Bytes>>>> {
    let ds_alg = ds.algorithm();
    let ds_tag = ds.key_tag();
    let digest_type = ds.digest_type();
    for key in dnskey_group.clone().rr_iter() {
        let AllRecordData::Dnskey(dnskey) = key.data() else {
            panic!("Dnskey expected");
        };
        if dnskey.algorithm() != ds_alg {
            continue;
        }
        if dnskey.key_tag() != ds_tag {
            continue;
        }
        let digest = match dnskey.digest(key.owner(), digest_type) {
            Ok(d) => d,
            Err(_) => {
                // Digest error, skip key.
                continue;
            }
        };
        if ds.digest() == digest.as_ref() {
            return Some(key.clone());
        }
    }
    None
}

#[derive(Debug)]
enum CNsecState {
    InsecureDelegation,
    SecureIntermediate,
    Nothing,
    Bogus,
}

// Find an NSEC record that proves that a DS record does not exist and
// return the delegation status based on the rtypes present. The NSEC
// processing is simplified compared to normal NSEC processing for three
// reasons:
// 1) We do not accept wildcards. We do not support wildcard delegations,
//    so if we find one, we return a bogus status.
// 2) The name exists, otherwise we wouldn't be here.
// 3) The parent exists and is secure, otherwise we wouldn't be here.
//
// So we have two possibilities: we find an exact match for the name and
// check the bitmap or we find the name as an empty non-terminal.
async fn nsec_for_ds(
    target: &Name<Bytes>,
    groups: &mut GroupSet,
    node: &Node,
    sig_cache: &SigCache,
    config: &Config,
) -> (CNsecState, Duration, Option<ExtendedError<Vec<u8>>>) {
    let mut ede = None;
    for g in groups.iter() {
        if g.rtype() != Rtype::NSEC {
            continue;
        }
        let owner = g.owner();
        let rrs = g.rr_set();
        let AllRecordData::Nsec(nsec) = rrs[0].data() else {
            panic!("NSEC expected");
        };
        if target.name_eq(&owner) {
            // Validate the signature
            let (state, wildcard, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Bogus
                | ValidationState::Indeterminate =>
                // insecure and indeterminate should not happen. But it is
                // easier to treat them as bogus.
                {
                    return (CNsecState::Bogus, ttl, ede)
                }
                ValidationState::Secure => (),
            }

            // Rule out wildcard. The NS record cannot be the result of a
            // wildcard expansion. So the NSEC cannot either.
            if wildcard.is_some() {
                // totest, NSEC that proves no DS is a wildcard.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC for DS is wildcard",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }

            // Check the bitmap.
            let types = nsec.types();

            // Check for DS.
            if types.contains(Rtype::DS) {
                // totest, no DS but NSEC proves DS
                // We didn't get a DS RRset but the NSEC record proves there
                // is one. Complain.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC proves DS",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }

            // Check for SOA.
            if types.contains(Rtype::SOA) {
                // totest, NSEC for DS from apex
                // This is an NSEC record from the APEX. Complain.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC for DS from apex",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }

            // Check for NS.
            if types.contains(Rtype::NS) {
                // We found NS and ruled out DS. This in an insecure delegation.
                return (CNsecState::InsecureDelegation, ttl, None);
            }

            // Anything else is a secure intermediate node.
            return (CNsecState::SecureIntermediate, ttl, None);
        }

        if target.ends_with(&owner) {
            // Validate the signature
            let (state, wildcard, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Indeterminate
                | ValidationState::Bogus => {
                    // insecure and indeterminate should not happen. But it is
                    // easier to treat them as bogus.
                    return (CNsecState::Bogus, ttl, ede);
                }
                ValidationState::Secure => (),
            }

            // Rule out wildcard. The NS record cannot be the result of a
            // wildcard expansion. So the NSEC cannot either.
            if wildcard.is_some() {
                // totest, prefix NSEC that proves no DS is a wildcard.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "prefix NSEC for DS is wildcard",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }

            // Check the bitmap.
            let types = nsec.types();

            // The owner is a prefix, check that
            // - that the nsec does not have DNAME
            // - that if the nsec has NS, it also has SOA
            if types.contains(Rtype::DNAME) {
                // totest, prefix NSEC for DS is DNAME
                // We should not be here. Return failure.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "prefix NSEC for DS is DNAME",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }
            if types.contains(Rtype::NS) && !types.contains(Rtype::SOA) {
                // totest, prefix NSEC for DS is delegation
                // We got a delegation NSEC. Return failure.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "prefix NSEC for DS is delegation",
                );
                return (CNsecState::Bogus, config.max_bogus_validity, ede);
            }
        }

        // Check that target is in the range of the NSEC and that owner is a
        // prefix of the next_name.
        if nsec_in_range(target, &owner, &nsec.next_name())
            && nsec.next_name().ends_with(target)
        {
            // Validate the signature
            let (state, wildcard, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Indeterminate
                | ValidationState::Bogus => {
                    // insecure and indeterminate should not happen. But it is
                    // easier to treat them as bogus.
                    return (CNsecState::Bogus, ttl, ede);
                }
                ValidationState::Secure => (),
            }

            // Rule out wildcard
            if let Some(wildcard) = wildcard {
                // totest, NSEC with wildcard owner for ENT for DS
                if *target != wildcard {
                    // totest, NSEC with expanded wildcard for ENT for DS
                    // Rule out expanded wildcard
                    let ede = make_ede(
                        ExtendedErrorCode::DNSSEC_BOGUS,
                        "ENT NSEC for DS is expanded wildcard",
                    );
                    return (
                        CNsecState::Bogus,
                        config.max_bogus_validity,
                        ede,
                    );
                }
            }

            return (CNsecState::SecureIntermediate, ttl, None);
        }

        // Just ignore this NSEC.
        ede = make_ede(ExtendedErrorCode::OTHER, "NSEC found but not usable");
    }
    (CNsecState::Nothing, config.max_node_validity, ede)
}

// Find an NSEC3 record hat proves that a DS record does not exist and return
// the delegation status based on the rtypes present. The NSEC3 processing is
// simplified compared to normal NSEC3 processing for three reasons:
// 1) We do not accept wildcards. We do not support wildcard delegations,
//    so we don't look for wildcards.
// 2) The name exists, otherwise we wouldn't be here.
// 3) The parent exists and is secure, otherwise we wouldn't be here.
//
// So we have two possibilities: we find an exact match for the hash of the
// name and check the bitmap or we find that the name does not exist, but
// the NSEC3 record uses opt-out.
async fn nsec3_for_ds(
    target: &Name<Bytes>,
    groups: &mut GroupSet,
    node: &Node,
    nsec3_cache: &Nsec3Cache,
    sig_cache: &SigCache,
    config: &Config,
) -> (CNsecState, Option<ExtendedError<Vec<u8>>>, Duration) {
    let mut ede = None;
    for g in groups.iter() {
        if g.rtype() != Rtype::NSEC3 {
            continue;
        }

        let rrs = g.rr_set();
        let AllRecordData::Nsec3(nsec3) = rrs[0].data() else {
            panic!("NSEC3 expected");
        };

        let iterations = nsec3.iterations();

        // See RFC 9276, Appendix A for a recommendation on the maximum number
        // of iterations.
        if iterations > config.nsec3_iter_insecure
            || iterations > config.nsec3_iter_bogus
        {
            // totest, NSEC3 for DS with very high iteration count
            // totest, NSEC3 for DS with high iteration count
            // High iteration count, verify the signature and abort.

            let (state, _wildcard, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Indeterminate
                | ValidationState::Bogus => {
                    // insecure and indeterminate should not happen. But it is
                    // easier to treat them as bogus.
                    return (CNsecState::Bogus, ede, ttl);
                }
                ValidationState::Secure => (),
            }

            // High iteration count, abort.
            if iterations > config.nsec3_iter_bogus {
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 with too high iteration count",
                );
                return (CNsecState::Bogus, ede, ttl);
            }
            let ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "NSEC3 with too high iteration count",
            );
            return (CNsecState::InsecureDelegation, ede, ttl);
        }

        // totest, unsupported NSEC3 hash algorithm for DS
        if !supported_nsec3_hash(nsec3.hash_algorithm()) {
            ede = make_ede(
                ExtendedErrorCode::DNSSEC_BOGUS,
                "NSEC3 with unsupported hash algorithm",
            );
            continue;
        }

        // Create the hash with the parameters in this record.
        let hash = cached_nsec3_hash(
            target,
            nsec3.hash_algorithm(),
            iterations,
            nsec3.salt(),
            nsec3_cache,
        )
        .await;

        let owner = g.owner();
        let first = owner.first();
        let ownerhash = match nsec3_label_to_hash(owner.first()) {
            Ok(hash) => hash,
            Err(_) => {
                ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 with bad owner hash",
                );
                continue;
            }
        };

        // Make sure the NSEC3 record is from an appropriate zone.
        if !target.ends_with(&owner.parent().unwrap_or_else(Name::root)) {
            // totest, NSEC3 from wrong zone for DS
            // Matching hash but wrong zone. Skip.
            ede = make_ede(ExtendedErrorCode::OTHER, "NSEC3 from wrong zone");
            continue;
        }

        if first
            == Label::from_slice(hash.to_string().as_ref())
                .expect("hash is expected to fit in a label")
        {
            // We found an exact match.

            // Validate the signature
            let (state, _, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Indeterminate
                | ValidationState::Bogus => {
                    // insecure and indeterminate should not happen. But it is
                    // easier to treat them as bogus.
                    return (CNsecState::Bogus, ede, ttl);
                }
                ValidationState::Secure => (),
            }

            // Check the bitmap.
            let types = nsec3.types();

            // Check for DS.
            if types.contains(Rtype::DS) {
                // totest, no DS but NSEC3 proves DS
                // We didn't get a DS RRset but the NSEC3 record proves there
                // is one. Complain.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 proves DS",
                );
                return (CNsecState::Bogus, ede, config.max_bogus_validity);
            }

            // Check for SOA.
            if types.contains(Rtype::SOA) {
                // totest, NSEC3 for DS from apex
                // This is an NSEC3 record from the APEX. Complain.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 for DS from apex",
                );
                return (CNsecState::Bogus, ede, config.max_bogus_validity);
            }

            // Check for NS.
            if types.contains(Rtype::NS) {
                // We found NS and ruled out DS. This in an insecure delegation.
                return (CNsecState::InsecureDelegation, None, ttl);
            }

            // Anything else is a secure intermediate node.
            return (CNsecState::SecureIntermediate, None, ttl);
        }

        // Check if target is between the hash in the first label and the
        // next_owner field.
        if nsec3_in_range(hash.as_ref(), &ownerhash, nsec3.next_owner()) {
            // target does not exist. However, if the opt-out flag is set,
            // we are allowed to assume an insecure delegation (RFC 5155,
            // Section 6). First check the signature.
            let (state, _, ede, ttl, _) =
                g.validate_with_node(node, sig_cache, config).await;
            match state {
                ValidationState::Insecure
                | ValidationState::Indeterminate
                | ValidationState::Bogus => {
                    // insecure and indeterminate should not happen. But it is
                    // easier to treat them as bogus.
                    return (CNsecState::Bogus, ede, ttl);
                }
                ValidationState::Secure => (),
            }

            if !nsec3.opt_out() {
                // totest, NSEC3 proves name does not exist for DS
                // Weird, target does not exist. Complain.
                let ede = make_ede(
                    ExtendedErrorCode::DNSSEC_BOGUS,
                    "NSEC3 proves name does not exist for DS",
                );
                return (CNsecState::Bogus, ede, config.max_bogus_validity);
            }

            return (CNsecState::InsecureDelegation, None, ttl);
        }
    }
    (CNsecState::Nothing, ede, config.max_node_validity)
}

async fn request_as_groups<Octs, Upstream>(
    upstream: &Upstream,
    name: &Name<Bytes>,
    rtype: Rtype,
) -> Result<(GroupSet, GroupSet, Option<ExtendedError<Vec<u8>>>), Error>
where
    Octs: AsRef<[u8]>
        + Debug
        + Octets
        + OctetsFrom<Vec<u8>>
        + Send
        + Sync,
    Upstream: SendRequest<RequestMessage<Octs>>,
{
    let mut msg = MessageBuilder::new_vec();
    msg.header_mut().set_cd(true);
    msg.header_mut().set_rd(true);
    let mut msg = msg.question();
    msg.push((&name, rtype)).expect("should not fail");
    let msg_as_octets = msg.into_message().into_octets();
    let octs: Octs = match msg_as_octets.try_octets_into() {
        Ok(octs) => octs,
        Err(_) => {
            // The error is an associated type of Octs. Just return that
            // octets conversion failed.
            return Err(Error::OctetsConversion);
        }
    };
    let msg = Message::from_octets(octs).expect("should not fail");
    let mut req = RequestMessage::new(msg);
    req.set_dnssec_ok(true);

    let mut request = upstream.send_request(req);
    let reply = request.get_response().await;

    // If there is anything wrong with the reply then pretend that we
    // didn't get anything. Try to keep an ede around with the reason.
    let mut ede = None;
    let mut answers = GroupSet::new();
    let mut authorities = GroupSet::new();
    let parse_error_ede = make_ede(
        ExtendedErrorCode::DNSSEC_BOGUS,
        "request for DS or DNSKEY failed, parse error",
    );
    if let Ok(reply) = reply {
        // Group the answer and authority sections.
        // Rewrite using an iterator.
        if let Ok(answer) = reply.answer() {
            for rr in answer {
                if let Some(e) = rr.map_or_else(
                    |_e| parse_error_ede.clone(),
                    |rr| {
                        answers.add(rr).map_or_else(
                            |_e| parse_error_ede.clone(),
                            |_| None,
                        )
                    },
                ) {
                    ede = Some(e);
                }
            }
        } else {
            ede.clone_from(&parse_error_ede);
        }

        if let Ok(authority) = reply.authority() {
            for rr in authority {
                if let Some(e) = rr.map_or_else(
                    |_e| parse_error_ede.clone(),
                    |rr| {
                        authorities.add(rr).map_or_else(
                            |_e| parse_error_ede.clone(),
                            |_| None,
                        )
                    },
                ) {
                    ede = Some(e);
                }
            }
        } else {
            ede = parse_error_ede;
        }
    } else {
        ede = make_ede(
            ExtendedErrorCode::DNSSEC_BOGUS,
            "request for DS or DNSKEY failed",
        );
    }
    Ok((answers, authorities, ede))
}
