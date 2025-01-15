use core::convert::From;

use std::vec::Vec;

use super::nsec3::{
    Nsec3Config, Nsec3HashProvider, OnDemandNsec3HashProvider,
};

//------------ NsecToNsec3TransitionState ------------------------------------

/// The current state of an RFC 5155 section 10.4 NSEC to NSEC3 transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NsecToNsec3TransitionState {
    /// 1.  Transition all DNSKEYs to DNSKEYs using the algorithm aliases
    ///     described in Section 2.  The actual method for safely and securely
    ///     changing the DNSKEY RRSet of the zone is outside the scope of this
    ///     specification.  However, the end result MUST be that all DS RRs in
    ///     the parent use the specified algorithm aliases.
    ///
    ///     After this transition is complete, all NSEC3-unaware clients will
    ///     treat the zone as insecure.  At this point, the authoritative
    ///     server still returns negative and wildcard responses that contain
    ///     NSEC RRs.
    TransitioningDnskeys,

    /// 2.  Add signed NSEC3 RRs to the zone, either incrementally or all at
    ///     once.  If adding incrementally, then the last RRSet added MUST be
    ///     the NSEC3PARAM RRSet.
    ///
    /// 3.  Upon the addition of the NSEC3PARAM RRSet, the server switches to
    ///     serving negative and wildcard responses with NSEC3 RRs according
    ///     to this specification.
    AddingNsec3Records,

    /// 4.  Remove the NSEC RRs either incrementally or all at once.
    RemovingNsecRecords,

    /// 5. Done.
    Transitioned,
}

//------------ Nsec3ToNsecTransitionState ------------------------------------

/// The current state of an RFC 5155 section 10.5 NSEC3 to NSEC transition.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Nsec3ToNsecTransitionState {
    /// 1.  Add NSEC RRs incrementally or all at once.
    AddingNsecRecords,

    /// 2.  Remove the NSEC3PARAM RRSet.  This will signal the server to use
    ///     the NSEC RRs for negative and wildcard responses.
    RemovingNsec3ParamRecord,

    /// 3.  Remove the NSEC3 RRs either incrementally or all at once.
    RemovingNsec3Records,

    /// 4. Transition all of the DNSKEYs to DNSSEC algorithm identifiers.
    ///    After this transition is complete, all NSEC3-unaware clients will
    ///    treat the zone as secure.
    TransitioningDnskeys,

    /// 5. Done.
    Transitioned,
}

//------------ HashingConfig -------------------------------------------------

/// Hashing configuration for a DNSSEC signed zone.
///
/// A DNSSEC signed zone must be hashed, either by NSEC or NSEC3.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum HashingConfig<N, O, HP = OnDemandNsec3HashProvider<O>>
where
    HP: Nsec3HashProvider<N, O>,
    O: AsRef<[u8]> + From<&'static [u8]>,
{
    /// The zone is already hashed.
    Prehashed,

    /// The zone is NSEC hashed.
    #[default]
    Nsec,

    /// The zone is NSEC3 hashed, possibly more than once.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5155#section-7.3
    /// 7.3.  Secondary Servers
    ///   ...
    ///   "If there are multiple NSEC3PARAM RRs present, there are multiple
    ///    valid NSEC3 chains present.  The server must choose one of them,
    ///    but may use any criteria to do so."
    ///
    /// https://datatracker.ietf.org/doc/html/rfc5155#section-12.1.3
    /// 12.1.3.  Transitioning to a New Hash Algorithm
    ///   "Although the NSEC3 and NSEC3PARAM RR formats include a hash
    ///    algorithm parameter, this document does not define a particular
    ///    mechanism for safely transitioning from one NSEC3 hash algorithm to
    ///    another.  When specifying a new hash algorithm for use with NSEC3,
    ///    a transition mechanism MUST also be defined.  It is possible that
    ///    the only practical and palatable transition mechanisms may require
    ///    an intermediate transition to an insecure state, or to a state that
    ///    uses NSEC records instead of NSEC3."
    Nsec3(Nsec3Config<N, O, HP>, Vec<Nsec3Config<N, O, HP>>),

    /// The zone is transitioning from NSEC to NSEC3 hashing.
    TransitioningNsecToNsec3(
        Nsec3Config<N, O, HP>,
        NsecToNsec3TransitionState,
    ),

    /// The zone is transitioning from NSEC3 to NSEC hashing.
    TransitioningNsec3ToNsec(
        Nsec3Config<N, O, HP>,
        Nsec3ToNsecTransitionState,
    ),
}
