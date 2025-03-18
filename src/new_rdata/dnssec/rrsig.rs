use domain_macros::*;

use crate::new_base::{name::Name, wire::U16, RType, Serial, TTL};

use super::SecAlg;

//----------- RRSig ----------------------------------------------------------

/// A cryptographic signature on a DNS record set.
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes)]
pub struct RRSig<'a> {
    /// The type of the RRset being signed.
    pub rtype: RType,

    /// The cryptographic algorithm used to construct the signature.
    pub algorithm: SecAlg,

    /// The number of labels in the signed RRset's owner name.
    pub labels: u8,

    /// The (original) TTL of the signed RRset.
    pub ttl: TTL,

    /// The point in time when the signature expires.
    pub expiration: Serial,

    /// The point in time when the signature was created.
    pub inception: Serial,

    /// The key tag of the key used to make the signature.
    pub keytag: U16,

    /// The name identifying the signer.
    pub signer: &'a Name,

    /// The serialized cryptographic signature.
    pub signature: &'a [u8],
}

//--- Interaction

impl RRSig<'_> {
    /// Copy referenced data into the given [`Bump`] allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> RRSig<'r> {
        use crate::utils::clone_to_bump;

        RRSig {
            signer: clone_to_bump(self.signer, bump),
            signature: bump.alloc_slice_copy(self.signature),
            ..self.clone()
        }
    }
}
