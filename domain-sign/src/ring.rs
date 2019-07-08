//! Key and Signer using ring.
#![cfg(feature = "ringsigner")]

use bytes::Bytes;
use domain_core::{Compose, ToDname};
use domain_core::iana::{DigestAlg, SecAlg};
use domain_core::rdata::{Ds, Dnskey};
use ring::digest;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaEncoding, RsaKeyPair,
    ECDSA_P256_SHA256_FIXED_SIGNING
};
use untrusted::Input;
use crate::key::SigningKey;


pub struct Key<'a> {
    dnskey: Dnskey,
    key: RingKey,
    rng: &'a dyn SecureRandom,
}

#[allow(dead_code)]
enum RingKey {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair, &'static dyn RsaEncoding),
}

impl<'a> Key<'a> {
    pub fn throwaway_13(
        flags: u16,
        rng: &'a dyn SecureRandom
    ) -> Result<Self, Unspecified> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING, rng
        )?;
        let keypair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            Input::from(pkcs8.as_ref())
        )?;
        let public_key = keypair.public_key().as_ref()[1..].into();
        Ok(Key {
            dnskey: Dnskey::new(
                flags, 3, SecAlg::EcdsaP256Sha256, public_key
            ),
            key: RingKey::Ecdsa(keypair),
            rng
        })
    }
}

impl<'a> SigningKey for Key<'a> {
    type Error = Unspecified;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        let mut buf = Vec::new();
        owner.compose_canonical(&mut buf);
        self.dnskey.compose_canonical(&mut buf);
        let digest = digest::digest(&digest::SHA256, &buf);
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::Sha256,
            Bytes::from(digest.as_ref())
        ))
    }

    fn sign(&self, msg: &[u8]) -> Result<Bytes, Self::Error> {
        match self.key {
            RingKey::Ecdsa(ref key) => {
                Ok(Bytes::from(key.sign(self.rng, Input::from(msg))?.as_ref()))
            }
            RingKey::Ed25519(ref key) => {
                Ok(Bytes::from(key.sign(msg).as_ref()))
            }
            RingKey::Rsa(ref key, encoding) => {
                let mut sig = vec![0; key.public_modulus_len()];
                key.sign(encoding, self.rng, msg, &mut sig)?;
                Ok(sig.into())
            }
        }
    }
}

