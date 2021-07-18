//! Key and Signer using OpenSSL.
#![cfg(feature = "openssl")]
#![cfg_attr(docsrs, doc(cfg(feature = "openssl")))]

use std::vec::Vec;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer as OpenSslSigner;
use unwrap::unwrap;
use crate::base::iana::DigestAlg;
use crate::base::name::ToDname;
use crate::base::octets::Compose;
use crate::rdata::{Ds, Dnskey};
use super::key::SigningKey;


pub struct Key {
    dnskey: Dnskey<Vec<u8>>,
    key: PKey<Private>,
    digest: MessageDigest,
}

impl SigningKey for Key {
    type Octets = Vec<u8>;
    type Signature = Vec<u8>;
    type Error = ErrorStack;

    fn dnskey(&self) -> Result<Dnskey<Self::Octets>, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToDname>(
        &self,
        owner: N
    ) -> Result<Ds<Self::Octets>, Self::Error> {
        let mut buf = Vec::new();
        unwrap!(owner.compose_canonical(&mut buf));
        unwrap!(self.dnskey.compose_canonical(&mut buf));
        let digest = Vec::from(sha256(&buf).as_ref());
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::Sha256,
            digest,
        ))
    }

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        let mut signer = OpenSslSigner::new(
            self.digest, &self.key
        )?;
        signer.update(data)?;
        signer.sign_to_vec()
    }
}

