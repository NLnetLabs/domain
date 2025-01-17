//! Signing related errors.
use core::fmt::{self, Debug, Display};

#[cfg(feature = "openssl")]
use crate::sign::crypto::openssl;

#[cfg(feature = "ring")]
use crate::sign::crypto::ring;

use crate::validate::Nsec3HashError;

//------------ SigningError --------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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
    InvalidSignatureValidityPeriod,

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
            SigningError::Nsec3HashingError(err) => {
                f.write_fmt(format_args!("NSEC3 hashing error: {err}"))
            }
            SigningError::RrsigRrsMustNotBeSigned => f.write_str(
                "RFC 4035 violation: RRSIG RRs MUST NOT be signed",
            ),
            SigningError::InvalidSignatureValidityPeriod => {
                f.write_str("RFC 4034 violation: RRSIG validity period is invalid")
            }
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

//----------- SignError ------------------------------------------------------

/// A signature failure.
///
/// In case such an error occurs, callers should stop using the key pair they
/// attempted to sign with.  If such an error occurs with every key pair they
/// have available, or if such an error occurs with a freshly-generated key
/// pair, they should use a different cryptographic implementation.  If that
/// is not possible, they must forego signing entirely.
///
/// # Failure Cases
///
/// Signing should be an infallible process.  There are three considerable
/// failure cases for it:
///
/// - The secret key was invalid (e.g. its parameters were inconsistent).
///
///   Such a failure would mean that all future signing (with this key) will
///   also fail.  In any case, the implementations provided by this crate try
///   to verify the key (e.g. by checking the consistency of the private and
///   public components) before any signing occurs, largely ruling this class
///   of errors out.
///
/// - Not enough randomness could be obtained.  This applies to signature
///   algorithms which use randomization (e.g. RSA and ECDSA).
///
///   On the vast majority of platforms, randomness can always be obtained.
///   The [`getrandom` crate documentation][getrandom] notes:
///
///   > If an error does occur, then it is likely that it will occur on every
///   > call to getrandom, hence after the first successful call one can be
///   > reasonably confident that no errors will occur.
///
///   [getrandom]: https://docs.rs/getrandom
///
///   Thus, in case such a failure occurs, all future signing will probably
///   also fail.
///
/// - Not enough memory could be allocated.
///
///   Signature algorithms have a small memory overhead, so an out-of-memory
///   condition means that the program is nearly out of allocatable space.
///
///   Callers who do not expect allocations to fail (i.e. who are using the
///   standard memory allocation routines, not their `try_` variants) will
///   likely panic shortly after such an error.
///
///   Callers who are aware of their memory usage will likely restrict it far
///   before they get to this point.  Systems running at near-maximum load
///   tend to quickly become unresponsive and staggeringly slow.  If memory
///   usage is an important consideration, programs will likely cap it before
///   the system reaches e.g. 90% memory use.
///
///   As such, memory allocation failure should never really occur.  It is far
///   more likely that one of the other errors has occurred.
///
/// It may be reasonable to panic in any such situation, since each kind of
/// error is essentially unrecoverable.  However, applications where signing
/// is an optional step, or where crashing is prohibited, may wish to recover
/// from such an error differently (e.g. by foregoing signatures or informing
/// an operator).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SignError;

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not create a cryptographic signature")
    }
}

impl std::error::Error for SignError {}

//----------- FromBytesError -----------------------------------------------

/// An error in importing a key pair from bytes.
#[derive(Clone, Debug)]
pub enum FromBytesError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The key's parameters were invalid.
    InvalidKey,

    /// The implementation does not allow such weak keys.
    WeakKey,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Conversions

#[cfg(feature = "ring")]
impl From<ring::FromBytesError> for FromBytesError {
    fn from(value: ring::FromBytesError) -> Self {
        match value {
            ring::FromBytesError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            ring::FromBytesError::InvalidKey => Self::InvalidKey,
            ring::FromBytesError::WeakKey => Self::WeakKey,
        }
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::FromBytesError> for FromBytesError {
    fn from(value: openssl::FromBytesError) -> Self {
        match value {
            openssl::FromBytesError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            openssl::FromBytesError::InvalidKey => Self::InvalidKey,
            openssl::FromBytesError::Implementation => Self::Implementation,
        }
    }
}

//--- Formatting

impl fmt::Display for FromBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
            Self::WeakKey => "key too weak to be supported",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for FromBytesError {}

//----------- GenerateError --------------------------------------------------

/// An error in generating a key pair.
#[derive(Clone, Debug)]
pub enum GenerateError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Conversion

#[cfg(feature = "ring")]
impl From<ring::GenerateError> for GenerateError {
    fn from(value: ring::GenerateError) -> Self {
        match value {
            ring::GenerateError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            ring::GenerateError::Implementation => Self::Implementation,
        }
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::GenerateError> for GenerateError {
    fn from(value: openssl::GenerateError) -> Self {
        match value {
            openssl::GenerateError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            openssl::GenerateError::Implementation => Self::Implementation,
        }
    }
}
