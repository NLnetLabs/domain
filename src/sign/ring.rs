//! DNSSEC signing using `ring`.

#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use core::fmt;
use std::{boxed::Box, sync::Arc, vec::Vec};

use octseq::{EmptyBuilder, OctetsBuilder, Truncate};
use ring::{digest::SHA1_FOR_LEGACY_USE_ONLY, signature::KeyPair};

use crate::{
    base::{
        iana::{Nsec3HashAlg, SecAlg},
        ToName,
    },
    rdata::{
        nsec3::{Nsec3Salt, OwnerHash},
        Nsec3param,
    },
    validate::{RawPublicKey, RsaPublicKey, Signature},
};

use super::{
    generic::{self, GenerateParams},
    SignError, SignRaw,
};

//----------- SecretKey ------------------------------------------------------

/// A key pair backed by `ring`.
pub enum SecretKey {
    /// An RSA/SHA-256 keypair.
    RsaSha256 {
        key: ring::signature::RsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An ECDSA P-256/SHA-256 keypair.
    EcdsaP256Sha256 {
        key: ring::signature::EcdsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An ECDSA P-384/SHA-384 keypair.
    EcdsaP384Sha384 {
        key: ring::signature::EcdsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An Ed25519 keypair.
    Ed25519(ring::signature::Ed25519KeyPair),
}

//--- Conversion from generic keys

impl SecretKey {
    /// Use a generic keypair with `ring`.
    pub fn from_generic(
        secret: &generic::SecretKey,
        public: &RawPublicKey,
        rng: Arc<dyn ring::rand::SecureRandom>,
    ) -> Result<Self, FromGenericError> {
        match (secret, public) {
            (
                generic::SecretKey::RsaSha256(s),
                RawPublicKey::RsaSha256(p),
            ) => {
                // Ensure that the public and private key match.
                if p != &RsaPublicKey::from(s) {
                    return Err(FromGenericError::InvalidKey);
                }

                // Ensure that the key is strong enough.
                if p.n.len() < 2048 / 8 {
                    return Err(FromGenericError::WeakKey);
                }

                let components = ring::rsa::KeyPairComponents {
                    public_key: ring::rsa::PublicKeyComponents {
                        n: s.n.as_ref(),
                        e: s.e.as_ref(),
                    },
                    d: s.d.as_ref(),
                    p: s.p.as_ref(),
                    q: s.q.as_ref(),
                    dP: s.d_p.as_ref(),
                    dQ: s.d_q.as_ref(),
                    qInv: s.q_i.as_ref(),
                };
                ring::signature::RsaKeyPair::from_components(&components)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::RsaSha256 { key, rng })
            }

            (
                generic::SecretKey::EcdsaP256Sha256(s),
                RawPublicKey::EcdsaP256Sha256(p),
            ) => {
                let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
                ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                        alg, s.as_slice(), p.as_slice(), &*rng)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::EcdsaP256Sha256 { key, rng })
            }

            (
                generic::SecretKey::EcdsaP384Sha384(s),
                RawPublicKey::EcdsaP384Sha384(p),
            ) => {
                let alg = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
                ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                        alg, s.as_slice(), p.as_slice(), &*rng)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::EcdsaP384Sha384 { key, rng })
            }

            (generic::SecretKey::Ed25519(s), RawPublicKey::Ed25519(p)) => {
                ring::signature::Ed25519KeyPair::from_seed_and_public_key(
                    s.as_slice(),
                    p.as_slice(),
                )
                .map_err(|_| FromGenericError::InvalidKey)
                .map(Self::Ed25519)
            }

            (generic::SecretKey::Ed448(_), RawPublicKey::Ed448(_)) => {
                Err(FromGenericError::UnsupportedAlgorithm)
            }

            // The public and private key types did not match.
            _ => Err(FromGenericError::InvalidKey),
        }
    }
}

//--- SignRaw

impl SignRaw for SecretKey {
    fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::EcdsaP256Sha256 { .. } => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384 { .. } => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
        }
    }

    fn raw_public_key(&self) -> RawPublicKey {
        match self {
            Self::RsaSha256 { key, rng: _ } => {
                let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                    key.public().into();
                RawPublicKey::RsaSha256(RsaPublicKey {
                    n: components.n.into(),
                    e: components.e.into(),
                })
            }

            Self::EcdsaP256Sha256 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                RawPublicKey::EcdsaP256Sha256(key.try_into().unwrap())
            }

            Self::EcdsaP384Sha384 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                RawPublicKey::EcdsaP384Sha384(key.try_into().unwrap())
            }

            Self::Ed25519(key) => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                RawPublicKey::Ed25519(key.try_into().unwrap())
            }
        }
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        match self {
            Self::RsaSha256 { key, rng } => {
                let mut buf = vec![0u8; key.public().modulus_len()];
                let pad = &ring::signature::RSA_PKCS1_SHA256;
                key.sign(pad, &**rng, data, &mut buf)
                    .map(|()| Signature::RsaSha256(buf.into_boxed_slice()))
                    .map_err(|_| SignError)
            }

            Self::EcdsaP256Sha256 { key, rng } => key
                .sign(&**rng, data)
                .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                .map_err(|_| SignError)
                .and_then(|buf| {
                    buf.try_into()
                        .map(Signature::EcdsaP256Sha256)
                        .map_err(|_| SignError)
                }),

            Self::EcdsaP384Sha384 { key, rng } => key
                .sign(&**rng, data)
                .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                .map_err(|_| SignError)
                .and_then(|buf| {
                    buf.try_into()
                        .map(Signature::EcdsaP384Sha384)
                        .map_err(|_| SignError)
                }),

            Self::Ed25519(key) => {
                let sig = key.sign(data);
                let buf: Box<[u8]> = sig.as_ref().into();
                buf.try_into()
                    .map(Signature::Ed25519)
                    .map_err(|_| SignError)
            }
        }
    }
}

//----------- generate() -----------------------------------------------------

/// Generate a new secret key for the given algorithm.
pub fn generate(
    params: GenerateParams,
    rng: &dyn ring::rand::SecureRandom,
) -> Result<(generic::SecretKey, RawPublicKey), GenerateError> {
    use ring::signature::{EcdsaKeyPair, Ed25519KeyPair};

    match params {
        GenerateParams::EcdsaP256Sha256 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let doc = EcdsaKeyPair::generate_pkcs8(alg, rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[36..68]);
            let sk = sk.try_into().unwrap();
            let sk = generic::SecretKey::EcdsaP256Sha256(sk);

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[73..138]);
            let pk = pk.try_into().unwrap();
            let pk = RawPublicKey::EcdsaP256Sha256(pk);

            Ok((sk, pk))
        }

        GenerateParams::EcdsaP384Sha384 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let alg = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
            let doc = EcdsaKeyPair::generate_pkcs8(alg, rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[35..83]);
            let sk = sk.try_into().unwrap();
            let sk = generic::SecretKey::EcdsaP384Sha384(sk);

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[88..185]);
            let pk = pk.try_into().unwrap();
            let pk = RawPublicKey::EcdsaP384Sha384(pk);

            Ok((sk, pk))
        }

        GenerateParams::Ed25519 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let doc = Ed25519KeyPair::generate_pkcs8(rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[16..48]);
            let sk = sk.try_into().unwrap();
            let sk = generic::SecretKey::Ed25519(sk);

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[51..83]);
            let pk = pk.try_into().unwrap();
            let pk = RawPublicKey::Ed25519(pk);

            Ok((sk, pk))
        }

        _ => Err(GenerateError::UnsupportedAlgorithm),
    }
}

//============ Error Types ===================================================

/// An error in importing a key into `ring`.
#[derive(Clone, Debug)]
pub enum FromGenericError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided keypair was invalid.
    InvalidKey,

    /// The implementation does not allow such weak keys.
    WeakKey,
}

//--- Formatting

impl fmt::Display for FromGenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
            Self::WeakKey => "key too weak to be supported",
        })
    }
}

//--- Error

impl std::error::Error for FromGenericError {}

//----------- GenerateError --------------------------------------------------

/// An error in generating a key with Ring.
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

impl From<ring::error::Unspecified> for GenerateError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Implementation
    }
}

//--- Formatting

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for GenerateError {}

//------------ Nsec3HashError -------------------------------------------------

/// An error when creating an NSEC3 hash.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Nsec3HashError {
    /// The requested algorithm for NSEC3 hashing is not supported.
    UnsupportedAlgorithm,

    /// Data could not be appended to a buffer.
    ///
    /// This could indicate an out of memory condition.
    AppendError,

    /// The hashing process produced an invalid owner hash.
    ///
    /// See: [OwnerHashError](crate::rdata::nsec3::OwnerHashError)
    OwnerHashError,
}

/// Compute an [RFC 5155] NSEC3 hash using default settings.
///
/// See: [Nsec3param::default].
///
/// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155
pub fn nsec3_default_hash<N, HashOcts>(
    owner: N,
) -> Result<OwnerHash<HashOcts>, Nsec3HashError>
where
    N: ToName,
    HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
    for<'a> HashOcts: From<&'a [u8]>,
{
    let params = Nsec3param::<HashOcts>::default();
    nsec3_hash(
        owner,
        params.hash_algorithm(),
        params.iterations(),
        params.salt(),
    )
}

/// Compute an [RFC 5155] NSEC3 hash.
///
/// Computes an NSEC3 hash according to [RFC 5155] section 5:
///
/// > IH(salt, x, 0) = H(x || salt)
/// > IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
///
/// Then the calculated hash of an owner name is:
///
/// > IH(salt, owner name, iterations),
///
/// Note that the `iterations` parameter is the number of _additional_
/// iterations as defined in [RFC 5155] section 3.1.3.
///
/// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155
pub fn nsec3_hash<N, SaltOcts, HashOcts>(
    owner: N,
    algorithm: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<SaltOcts>,
) -> Result<OwnerHash<HashOcts>, Nsec3HashError>
where
    N: ToName,
    SaltOcts: AsRef<[u8]>,
    HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
    for<'a> HashOcts: From<&'a [u8]>,
{
    if algorithm != Nsec3HashAlg::SHA1 {
        return Err(Nsec3HashError::UnsupportedAlgorithm);
    }

    fn mk_hash<N, SaltOcts, HashOcts>(
        owner: N,
        iterations: u16,
        salt: &Nsec3Salt<SaltOcts>,
    ) -> Result<HashOcts, HashOcts::AppendError>
    where
        N: ToName,
        SaltOcts: AsRef<[u8]>,
        HashOcts: AsRef<[u8]> + EmptyBuilder + OctetsBuilder + Truncate,
        for<'a> HashOcts: From<&'a [u8]>,
    {
        let mut buf = HashOcts::empty();

        owner.compose_canonical(&mut buf)?;
        buf.append_slice(salt.as_slice())?;

        let mut ctx = ring::digest::Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
        ctx.update(buf.as_ref());
        let mut h = ctx.finish();

        for _ in 0..iterations {
            buf.truncate(0);
            buf.append_slice(h.as_ref())?;
            buf.append_slice(salt.as_slice())?;

            let mut ctx =
                ring::digest::Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
            ctx.update(buf.as_ref());
            h = ctx.finish();
        }

        Ok(h.as_ref().into())
    }

    let hash = mk_hash(owner, iterations, salt)
        .map_err(|_| Nsec3HashError::AppendError)?;

    let owner_hash = OwnerHash::from_octets(hash)
        .map_err(|_| Nsec3HashError::OwnerHashError)?;

    Ok(owner_hash)
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::{sync::Arc, vec::Vec};

    use crate::{
        base::iana::SecAlg,
        sign::{
            generic::{self, GenerateParams},
            SignRaw,
        },
        validate::Key,
    };

    use super::SecretKey;

    const KEYS: &[(SecAlg, u16)] = &[
        (SecAlg::RSASHA256, 60616),
        (SecAlg::ECDSAP256SHA256, 42253),
        (SecAlg::ECDSAP384SHA384, 33566),
        (SecAlg::ED25519, 56037),
    ];

    const GENERATE_PARAMS: &[GenerateParams] = &[
        GenerateParams::EcdsaP256Sha256,
        GenerateParams::EcdsaP384Sha384,
        GenerateParams::Ed25519,
    ];

    #[test]
    fn public_key() {
        let rng = Arc::new(ring::rand::SystemRandom::new());
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key = SecretKey::from_generic(&gen_key, pub_key, rng.clone())
                .unwrap();

            assert_eq!(key.raw_public_key(), *pub_key);
        }
    }

    #[test]
    fn generated_roundtrip() {
        let rng = Arc::new(ring::rand::SystemRandom::new());
        for params in GENERATE_PARAMS {
            let (sk, pk) = super::generate(params.clone(), &*rng).unwrap();
            let key = SecretKey::from_generic(&sk, &pk, rng.clone()).unwrap();
            assert_eq!(key.raw_public_key(), pk);
        }
    }

    #[test]
    fn sign() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let rng = Arc::new(ring::rand::SystemRandom::new());

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key =
                SecretKey::from_generic(&gen_key, pub_key, rng).unwrap();

            let _ = key.sign_raw(b"Hello, World!").unwrap();
        }
    }
}
