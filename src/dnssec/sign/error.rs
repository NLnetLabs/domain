//! Signing related errors.
use core::fmt::{Debug, Display};

use crate::crypto::sign::SignError;
use crate::dnssec::common::Nsec3HashError;
use crate::rdata::dnssec::Timestamp;

//------------ SigningError --------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub enum SigningError {
    /// One or more keys does not have a signature validity period defined.
    NoSignatureValidityPeriodProvided,

    /// TODO
    OutOfMemory,

    /// At least one key must be provided to sign with.
    NoKeysProvided,

    /// None of the provided keys were deemed suitable by the
    /// [`SigningKeyUsageStrategy`] used.
    NoSuitableKeysFound,

    // The zone either lacks a SOA record or has more than one SOA record.
    SoaRecordCouldNotBeDetermined,

    /// Cannot create an Rrset from an empty slice.
    EmptyRecordSlice,

    // TODO
    Nsec3HashingError(Nsec3HashError),

    /// TODO
    ///
    /// https://www.rfc-editor.org/rfc/rfc4035.html#section-2.2
    /// 2.2.  Including RRSIG RRs in a Zone
    ///   ...
    ///   "An RRSIG RR itself MUST NOT be signed"
    RrsigRrsMustNotBeSigned,

    // TODO
    InvalidSignatureValidityPeriod(Timestamp, Timestamp),

    // TODO
    SigningError(SignError),
}

impl Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigningError::NoSignatureValidityPeriodProvided => {
                f.write_str("No signature validity period found for key")
            }
            SigningError::OutOfMemory => f.write_str("Out of memory"),
            SigningError::NoKeysProvided => {
                f.write_str("No signing keys provided")
            }
            SigningError::NoSuitableKeysFound => {
                f.write_str("No suitable keys found")
            }
            SigningError::SoaRecordCouldNotBeDetermined => {
                f.write_str("No apex SOA or too many apex SOA records found")
            }
	    SigningError::EmptyRecordSlice => {
                f.write_str("Empty slice of Record")
	    }
            SigningError::Nsec3HashingError(err) => {
                f.write_fmt(format_args!("NSEC3 hashing error: {err}"))
            }
            SigningError::RrsigRrsMustNotBeSigned => f.write_str(
                "RFC 4035 violation: RRSIG RRs MUST NOT be signed",
            ),
            SigningError::InvalidSignatureValidityPeriod(inception, expiration) => f.write_fmt(
                format_args!("RFC 4034 violation: RRSIG validity period ({inception} <= {expiration}) is invalid"),
            ),
            SigningError::SigningError(err) => {
                f.write_fmt(format_args!("Signing error: {err}"))
            }
        }
    }
}

impl From<SignError> for SigningError {
    fn from(err: SignError) -> Self {
        Self::SigningError(err)
    }
}

impl From<Nsec3HashError> for SigningError {
    fn from(err: Nsec3HashError) -> Self {
        Self::Nsec3HashingError(err)
    }
}
