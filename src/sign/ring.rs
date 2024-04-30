//! Key and Signer using ring.
#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use super::key::SigningKey;
use crate::base::iana::{DigestAlg, SecAlg};
use crate::base::name::ToName;
use crate::base::rdata::ComposeRecordData;
use crate::rdata::{Dnskey, Ds};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use octseq::builder::infallible;
use ring::digest;
use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaEncoding, RsaKeyPair,
    Signature as RingSignature, ECDSA_P256_SHA256_FIXED_SIGNING,
};
use std::vec::Vec;

pub struct Key<'a> {
    dnskey: Dnskey<Vec<u8>>,
    key: RingKey,
    rng: &'a dyn SecureRandom,
}

#[allow(dead_code, clippy::large_enum_variant)]
enum RingKey {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair, &'static dyn RsaEncoding),
}

impl<'a> Key<'a> {
    pub fn throwaway_13(
        flags: u16,
        rng: &'a dyn SecureRandom,
    ) -> Result<Self, Unspecified> {
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            rng,
        )?;
        let keypair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            rng,
        )?;
        let public_key = keypair.public_key().as_ref()[1..].into();
        Ok(Key {
            dnskey: Dnskey::new(
                flags,
                3,
                SecAlg::ECDSAP256SHA256,
                public_key,
            )
            .expect("long key"),
            key: RingKey::Ecdsa(keypair),
            rng,
        })
    }
}

impl<'a> SigningKey for Key<'a> {
    type Octets = Vec<u8>;
    type Signature = Signature;
    type Error = Unspecified;

    fn dnskey(&self) -> Result<Dnskey<Self::Octets>, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToName>(
        &self,
        owner: N,
    ) -> Result<Ds<Self::Octets>, Self::Error> {
        let mut buf = Vec::new();
        infallible(owner.compose_canonical(&mut buf));
        infallible(self.dnskey.compose_canonical_rdata(&mut buf));
        let digest =
            Vec::from(digest::digest(&digest::SHA256, &buf).as_ref());
        Ok(Ds::new(
            self.key_tag()?,
            self.dnskey.algorithm(),
            DigestAlg::SHA256,
            digest,
        )
        .expect("long digest"))
    }

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        match self.key {
            RingKey::Ecdsa(ref key) => {
                key.sign(self.rng, msg).map(Signature::sig)
            }
            RingKey::Ed25519(ref key) => Ok(Signature::sig(key.sign(msg))),
            RingKey::Rsa(ref key, encoding) => {
                let mut sig = vec![0; key.public().modulus_len()];
                key.sign(encoding, self.rng, msg, &mut sig)?;
                Ok(Signature::vec(sig))
            }
        }
    }
}

pub struct Signature(SignatureInner);

enum SignatureInner {
    Sig(RingSignature),
    Vec(Vec<u8>),
}

impl Signature {
    fn sig(sig: RingSignature) -> Signature {
        Signature(SignatureInner::Sig(sig))
    }

    fn vec(vec: Vec<u8>) -> Signature {
        Signature(SignatureInner::Vec(vec))
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self.0 {
            SignatureInner::Sig(ref sig) => sig.as_ref(),
            SignatureInner::Vec(ref vec) => vec.as_slice(),
        }
    }
}

#[cfg(feature = "bytes")]
impl From<Signature> for Bytes {
    fn from(sig: Signature) -> Self {
        match sig.0 {
            SignatureInner::Sig(sig) => Bytes::copy_from_slice(sig.as_ref()),
            SignatureInner::Vec(sig) => Bytes::from(sig),
        }
    }
}
