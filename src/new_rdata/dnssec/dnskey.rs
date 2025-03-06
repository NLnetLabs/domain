use domain_macros::*;

use crate::new_base::wire::U16;

use super::SecAlg;

//----------- DNSKey ---------------------------------------------------------

/// A cryptographic key for signing DNS records.
#[derive(AsBytes, BuildBytes, ParseBytesByRef)]
#[repr(C)]
pub struct DNSKey {
    /// Flags describing the usage of the key.
    pub flags: DNSKeyFlags,

    /// The protocol version of the key.
    pub protocol: u8,

    /// The cryptographic algorithm used by this key.
    pub algorithm: SecAlg,

    /// The serialized public key.
    pub key: [u8],
}

//----------- DNSKeyFlags ----------------------------------------------------

/// Flags describing a [`DNSKey`].
#[derive(
    Copy,
    Clone,
    Default,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct DNSKeyFlags {
    inner: U16,
}
