//! Key and Signer using OpenSSL.
#![cfg(feature = "openssl")]

use bytes::Bytes;
use domain_core::{Compose, ToDname};
use domain_core::iana::DigestAlg;
use domain_core::rdata::{Ds, Dnskey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer as OpenSslSigner;
use crate::key::SigningKey;


pub struct Key {
    dnskey: Dnskey,
    key: PKey<Private>,
    digest: Option<MessageDigest>,
}

impl SigningKey for Key {
    type Error = ErrorStack;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        let mut buf = Vec::new();
        owner.compose_canonical(&mut buf);
        self.dnskey.compose_canonical(&mut buf);
        let digest = Bytes::from(sha256(&buf).as_ref());
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::Sha256,
            digest,
        ))
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error> {
        let mut signer = OpenSslSigner::new_intern(
            self.digest, &self.key
        )?;
        signer.update(data)?;
        signer.sign_to_vec().map(Into::into)
    }
}

