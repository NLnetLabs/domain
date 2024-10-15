//! DNSSEC signing using `ring`.

#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use core::fmt;

use std::fmt::Debug;
use std::vec::Vec;

use octseq::{EmptyBuilder, OctetsBuilder, Truncate};
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;

use crate::base::iana::{Nsec3HashAlg, SecAlg};
use crate::base::ToName;
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::Nsec3param;

use super::generic;

/// A key pair backed by `ring`.
pub enum SecretKey<'a> {
    /// An RSA/SHA-256 keypair.
    RsaSha256 {
        key: ring::signature::RsaKeyPair,
        rng: &'a dyn ring::rand::SecureRandom,
    },

    /// An Ed25519 keypair.
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl<'a> SecretKey<'a> {
    /// Use a generic keypair with `ring`.
    pub fn import<B: AsRef<[u8]> + AsMut<[u8]>>(
        key: generic::SecretKey<B>,
        rng: &'a dyn ring::rand::SecureRandom,
    ) -> Result<Self, ImportError> {
        match &key {
            generic::SecretKey::RsaSha256(k) => {
                let components = ring::rsa::KeyPairComponents {
                    public_key: ring::rsa::PublicKeyComponents {
                        n: k.n.as_ref(),
                        e: k.e.as_ref(),
                    },
                    d: k.d.as_ref(),
                    p: k.p.as_ref(),
                    q: k.q.as_ref(),
                    dP: k.d_p.as_ref(),
                    dQ: k.d_q.as_ref(),
                    qInv: k.q_i.as_ref(),
                };
                ring::signature::RsaKeyPair::from_components(&components)
                    .map_err(|_| ImportError::InvalidKey)
                    .map(|key| Self::RsaSha256 { key, rng })
            }
            // TODO: Support ECDSA.
            generic::SecretKey::Ed25519(k) => {
                let k = k.as_ref();
                ring::signature::Ed25519KeyPair::from_seed_unchecked(k)
                    .map_err(|_| ImportError::InvalidKey)
                    .map(Self::Ed25519)
            }
            _ => Err(ImportError::UnsupportedAlgorithm),
        }
    }

    /// Export this key into a generic public key.
    pub fn export_public<B>(&self) -> generic::PublicKey<B>
    where
        B: AsRef<[u8]> + From<Vec<u8>>,
    {
        match self {
            Self::RsaSha256 { key, rng: _ } => {
                let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                    key.public().into();
                generic::PublicKey::RsaSha256(generic::RsaPublicKey {
                    n: components.n.into(),
                    e: components.e.into(),
                })
            }
            Self::Ed25519(key) => {
                use ring::signature::KeyPair;
                let key = key.public_key().as_ref();
                generic::PublicKey::Ed25519(key.try_into().unwrap())
            }
        }
    }
}

/// An error in importing a key into `ring`.
#[derive(Clone, Debug)]
pub enum ImportError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided keypair was invalid.
    InvalidKey,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
        })
    }
}

impl<'a> super::Sign<Vec<u8>> for SecretKey<'a> {
    type Error = ring::error::Unspecified;

    fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::Ed25519(_) => SecAlg::ED25519,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::RsaSha256 { key, rng } => {
                let mut buf = vec![0u8; key.public().modulus_len()];
                let pad = &ring::signature::RSA_PKCS1_SHA256;
                key.sign(pad, *rng, data, &mut buf)?;
                Ok(buf)
            }
            Self::Ed25519(key) => Ok(key.sign(data).as_ref().to_vec()),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use crate::{
        base::{iana::SecAlg, scan::IterScanner},
        rdata::Dnskey,
        sign::generic,
    };

    const KEYS: &[(SecAlg, u16)] =
        &[(SecAlg::RSASHA256, 27096), (SecAlg::ED25519, 43769)];

    #[test]
    fn export_public() {
        type GenericSecretKey = generic::SecretKey<Vec<u8>>;
        type GenericPublicKey = generic::PublicKey<Vec<u8>>;

        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let sec_key = GenericSecretKey::from_dns(&data).unwrap();
            let rng = ring::rand::SystemRandom::new();
            let sec_key = super::SecretKey::import(sec_key, &rng).unwrap();
            let pub_key: GenericPublicKey = sec_key.export_public();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let mut data = std::fs::read_to_string(path).unwrap();
            // Remove a trailing comment, if any.
            if let Some(pos) = data.bytes().position(|b| b == b';') {
                data.truncate(pos);
            }
            // Skip '<domain-name> <record-class> <record-type>'
            let data = data.split_ascii_whitespace().skip(3);
            let mut data = IterScanner::new(data);
            let dns_key: Dnskey<Vec<u8>> = Dnskey::scan(&mut data).unwrap();

            assert_eq!(dns_key.key_tag(), key_tag);
            assert_eq!(pub_key.into_dns::<Vec<u8>>(256), dns_key)
        }
    }
}
