//! Extended DNS errors.
//!
//! See [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914).

use core::fmt;

use domain_macros::*;

use crate::new_base::wire::U16;

//----------- ExtError -------------------------------------------------------

/// An extended DNS error.
#[derive(PartialEq, Eq, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy)]
#[repr(C)]
pub struct ExtError {
    /// The error code.
    pub code: ExtErrorCode,

    /// A human-readable description of the error.
    text: str,
}

impl ExtError {
    /// A human-readable description of the error.
    pub fn text(&self) -> Option<&str> {
        if !self.text.is_empty() {
            Some(self.text.strip_suffix('\0').unwrap_or(&self.text))
        } else {
            None
        }
    }
}

//--- Formatting

impl fmt::Debug for ExtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtError")
            .field("code", &self.code)
            .field("text", &self.text())
            .finish()
    }
}

//----------- ExtErrorCode ---------------------------------------------------

/// The code for an extended DNS error.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct ExtErrorCode {
    /// The error code.
    pub code: U16,
}

//--- Associated Constants

impl ExtErrorCode {
    /// Create a new [`ExtErrorCode`].
    const fn new(code: u16) -> Self {
        Self {
            code: U16::new(code),
        }
    }

    /// An unspecified extended error.
    ///
    /// This should be used when there is no other appropriate error code.
    pub const OTHER: Self = Self::new(0);

    /// DNSSEC validation failed because a DNSKEY used an unknown algorithm.
    pub const BAD_DNSKEY_ALG: Self = Self::new(1);

    /// DNSSEC validation failed because a DS set used an unknown algorithm.
    pub const BAD_DS_ALG: Self = Self::new(2);

    /// An up-to-date answer could not be retrieved in time.
    pub const STALE_ANSWER: Self = Self::new(3);

    /// Policy dictated that a forged answer be returned.
    pub const FORGED_ANSWER: Self = Self::new(4);

    /// The DNSSEC validity of the answer could not be determined.
    pub const DNSSEC_INDETERMINATE: Self = Self::new(5);

    /// The answer was invalid as per DNSSEC.
    pub const DNSSEC_BOGUS: Self = Self::new(6);

    /// The DNSSEC signature of the answer expired.
    pub const SIG_EXPIRED: Self = Self::new(7);

    /// The DNSSEC signature of the answer is valid in the future.
    pub const SIG_FUTURE: Self = Self::new(8);

    /// DNSSEC validation failed because a DNSKEY record was missing.
    pub const DNSKEY_MISSING: Self = Self::new(9);

    /// DNSSEC validation failed because RRSIGs were unexpectedly missing.
    pub const RRSIGS_MISSING: Self = Self::new(10);

    /// DNSSEC validation failed because a DNSKEY wasn't a ZSK.
    pub const NOT_ZSK: Self = Self::new(11);

    /// DNSSEC validation failed because an NSEC(3) record could not be found.
    pub const NSEC_MISSING: Self = Self::new(12);

    /// The server failure error was cached from an upstream.
    pub const CACHED_ERROR: Self = Self::new(13);

    /// The server is not ready to serve requests.
    pub const NOT_READY: Self = Self::new(14);

    /// The request is blocked by internal policy.
    pub const BLOCKED: Self = Self::new(15);

    /// The request is blocked by external policy.
    pub const CENSORED: Self = Self::new(16);

    /// The request is blocked by the client's own filters.
    pub const FILTERED: Self = Self::new(17);

    /// The client is prohibited from making requests.
    pub const PROHIBITED: Self = Self::new(18);

    /// An up-to-date answer could not be retrieved in time.
    pub const STALE_NXDOMAIN: Self = Self::new(19);

    /// The request cannot be answered authoritatively.
    pub const NOT_AUTHORITATIVE: Self = Self::new(20);

    /// The request / operation is not supported.
    pub const NOT_SUPPORTED: Self = Self::new(21);

    /// No upstream authorities answered the request (in time).
    pub const NO_REACHABLE_AUTHORITY: Self = Self::new(22);

    /// An unrecoverable network error occurred.
    pub const NETWORK_ERROR: Self = Self::new(23);

    /// The server's local zone data is invalid.
    pub const INVALID_DATA: Self = Self::new(24);

    /// An impure operation was stated in a DNS-over-QUIC 0-RTT packet.
    ///
    /// See [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250).
    pub const TOO_EARLY: Self = Self::new(26);

    /// DNSSEC validation failed because an NSEC3 parameter was unsupported.
    pub const BAD_NSEC3_ITERS: Self = Self::new(27);
}

//--- Inspection

impl ExtErrorCode {
    /// Whether this is a private-use code.
    ///
    /// Private-use codes occupy the range 49152 to 65535 (inclusive).
    pub fn is_private(&self) -> bool {
        self.code >= 49152
    }
}

//--- Formatting

impl fmt::Debug for ExtErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match *self {
            Self::OTHER => "other",
            Self::BAD_DNSKEY_ALG => "unsupported DNSKEY algorithm",
            Self::BAD_DS_ALG => "unspported DS digest type",
            Self::STALE_ANSWER => "stale answer",
            Self::FORGED_ANSWER => "forged answer",
            Self::DNSSEC_INDETERMINATE => "DNSSEC indeterminate",
            Self::DNSSEC_BOGUS => "DNSSEC bogus",
            Self::SIG_EXPIRED => "signature expired",
            Self::SIG_FUTURE => "signature not yet valid",
            Self::DNSKEY_MISSING => "DNSKEY missing",
            Self::RRSIGS_MISSING => "RRSIGs missing",
            Self::NOT_ZSK => "no zone key bit set",
            Self::NSEC_MISSING => "nsec missing",
            Self::CACHED_ERROR => "cached error",
            Self::NOT_READY => "not ready",
            Self::BLOCKED => "blocked",
            Self::CENSORED => "censored",
            Self::FILTERED => "filtered",
            Self::PROHIBITED => "prohibited",
            Self::STALE_NXDOMAIN => "stale NXDOMAIN answer",
            Self::NOT_AUTHORITATIVE => "not authoritative",
            Self::NOT_SUPPORTED => "not supported",
            Self::NO_REACHABLE_AUTHORITY => "no reachable authority",
            Self::NETWORK_ERROR => "network error",
            Self::INVALID_DATA => "invalid data",
            Self::TOO_EARLY => "too early",
            Self::BAD_NSEC3_ITERS => "unsupported NSEC3 iterations value",

            _ => {
                return f
                    .debug_tuple("ExtErrorCode")
                    .field(&self.code.get())
                    .finish();
            }
        };

        f.debug_tuple("ExtErrorCode")
            .field(&self.code.get())
            .field(&text)
            .finish()
    }
}
