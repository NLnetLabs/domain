//! Actual signing.
use core::fmt::{Debug, Display};

use crate::validate::Nsec3HashError;

//------------ SigningError --------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SigningError {
    /// One or more keys does not have a signature validity period defined.
    KeyLacksSignatureValidityPeriod,

    /// TODO
    OutOfMemory,

    /// At least one key must be provided to sign with.
    NoKeysProvided,

    /// None of the provided keys were deemed suitable by the
    /// [`SigningKeyUsageStrategy`] used.
    NoSuitableKeysFound,

    NoSoaFound,

    Nsec3HashingError(Nsec3HashError),
    MissingSigningConfiguration,
}

impl Display for SigningError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SigningError::KeyLacksSignatureValidityPeriod => {
                f.write_str("KeyLacksSignatureValidityPeriod")
            }
            SigningError::OutOfMemory => f.write_str("OutOfMemory"),
            SigningError::NoKeysProvided => f.write_str("NoKeysProvided"),
            SigningError::NoSuitableKeysFound => {
                f.write_str("NoSuitableKeysFound")
            }
            SigningError::NoSoaFound => f.write_str("NoSoaFound"),
            SigningError::Nsec3HashingError(err) => {
                f.write_fmt(format_args!("Nsec3HashingError: {err}"))
            }
            SigningError::MissingSigningConfiguration => {
                f.write_str("MissingSigningConfiguration")
            }
        }
    }
}
