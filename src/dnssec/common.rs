// DNSSEC code that is used both by DNSSEC signing and DNSSEC validation.

use crate::base::iana::Nsec3HashAlg;
use crate::base::ToName;
use crate::crypto::common::{DigestContext, DigestType};
use crate::dep::octseq::{EmptyBuilder, OctetsBuilder, Truncate};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::Nsec3param;

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

    /// The hashing process produced a hash that already exists.
    CollisionDetected,

    /// The hash provider did not provide a hash for the given owner name.
    MissingHash,
}

//--- Display

impl std::fmt::Display for Nsec3HashError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Nsec3HashError::UnsupportedAlgorithm => {
                f.write_str("Unsupported algorithm")
            }
            Nsec3HashError::AppendError => {
                f.write_str("Append error: out of memory?")
            }
            Nsec3HashError::OwnerHashError => {
                f.write_str("Hashing produced an invalid owner hash")
            }
            Nsec3HashError::CollisionDetected => {
                f.write_str("Hash collision detected")
            }
            Nsec3HashError::MissingHash => {
                f.write_str("Missing hash for owner name")
            }
        }
    }
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
        let mut canonical_owner = HashOcts::empty();
        owner.compose_canonical(&mut canonical_owner)?;

        let mut ctx = DigestContext::new(DigestType::Sha1);
        ctx.update(canonical_owner.as_ref());
        ctx.update(salt.as_slice());
        let mut h = ctx.finish();

        for _ in 0..iterations {
            let mut ctx = DigestContext::new(DigestType::Sha1);
            ctx.update(h.as_ref());
            ctx.update(salt.as_slice());
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
