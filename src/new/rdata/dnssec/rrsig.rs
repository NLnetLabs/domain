//! The RRSIG record data type.

use core::cmp::Ordering;

use domain_macros::*;

use crate::new::base::build::BuildInMessage;
use crate::new::base::name::{CanonicalName, Name, NameCompressor};
use crate::new::base::wire::{AsBytes, BuildBytes, TruncationError, U16};
use crate::new::base::{CanonicalRecordData, RType, Serial, TTL};

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
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> RRSig<'r> {
        use crate::utils::dst::copy_to_bump;

        RRSig {
            signer: copy_to_bump(self.signer, bump),
            signature: bump.alloc_slice_copy(self.signature),
            ..self.clone()
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for RRSig<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this_initial = (
            self.rtype,
            self.algorithm,
            self.labels,
            self.ttl,
            self.expiration.as_bytes(),
            self.inception.as_bytes(),
            self.keytag,
        );
        let that_initial = (
            that.rtype,
            that.algorithm,
            that.labels,
            that.ttl,
            that.expiration.as_bytes(),
            that.inception.as_bytes(),
            that.keytag,
        );
        this_initial
            .cmp(&that_initial)
            .then_with(|| self.signer.cmp_lowercase_composed(that.signer))
            .then_with(|| self.signature.cmp(that.signature))
    }
}

//--- Building in DNS messages

impl BuildInMessage for RRSig<'_> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = contents.get_mut(start..).ok_or(TruncationError)?;
        let rest = self.build_bytes(bytes)?.len();
        Ok(contents.len() - rest)
    }
}
