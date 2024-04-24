// Helper functions and constants for NSEC and NSEC3 validation.

use crate::base::iana::Nsec3HashAlg;
use crate::base::name::Label;
use crate::base::name::ToName;
use crate::base::Name;
use crate::base::NameBuilder;
use crate::dep::octseq::Octets;
use crate::dep::octseq::OctetsBuilder;
use crate::rdata::nsec3::Nsec3Salt;
use crate::rdata::nsec3::OwnerHash;
use bytes::Bytes;
use ring::digest;
use std::str::FromStr;
use std::vec::Vec;

// These need to be config variables.
pub const NSEC3_ITER_INSECURE: u16 = 100;
pub const NSEC3_ITER_BOGUS: u16 = 500;

/// Compute the NSEC3 hash according to Section 5 of RFC 5155:
///
/// IH(salt, x, 0) = H(x || salt)
/// IH(salt, x, k) = H(IH(salt, x, k-1) || salt), if k > 0
///
/// Then the calculated hash of an owner name is
///    IH(salt, owner name, iterations),
pub fn nsec3_hash<N, HashOcts>(
    owner: N,
    algorithm: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<HashOcts>,
) -> OwnerHash<Vec<u8>>
where
    N: ToName,
    HashOcts: AsRef<[u8]>,
{
    let mut buf = Vec::new();

    owner.compose_canonical(&mut buf).unwrap();
    buf.append_slice(salt.as_slice()).unwrap();

    let mut ctx = if algorithm == Nsec3HashAlg::SHA1 {
        digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
    } else {
        // Unsupported.
        todo!();
    };

    ctx.update(&buf);
    let mut h = ctx.finish();

    for _ in 0..iterations {
        buf.truncate(0);
        buf.append_slice(h.as_ref()).unwrap();
        buf.append_slice(salt.as_slice()).unwrap();

        let mut ctx = if algorithm == Nsec3HashAlg::SHA1 {
            digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
        } else {
            // Unsupported.
            todo!();
        };

        ctx.update(&buf);
        h = ctx.finish();
    }

    OwnerHash::from_octets(h.as_ref().to_vec()).unwrap()
}

pub fn nsec3_label_to_hash(label: &Label) -> OwnerHash<Vec<u8>> {
    let label_str = std::str::from_utf8(label.as_ref()).unwrap();
    OwnerHash::<Vec<u8>>::from_str(&label_str).unwrap()
}

pub fn nsec3_in_range<O1, O2, O3>(
    targethash: OwnerHash<O1>,
    ownerhash: OwnerHash<O2>,
    nexthash: &OwnerHash<O3>,
) -> bool
where
    O1: Octets,
    O2: Octets,
    O3: Octets,
{
    if *nexthash > ownerhash {
        // Normal range.
        ownerhash < targethash && targethash < nexthash
    } else {
        // End range that wraps around.
        ownerhash < targethash || targethash < nexthash
    }
}

pub fn star_closest_encloser(ce: &Name<Bytes>) -> Name<Bytes> {
    let mut star_name = NameBuilder::new_bytes();
    star_name.append_label(Label::wildcard().as_ref()).unwrap();
    let star_name = star_name.append_origin(&ce).unwrap();
    star_name
}
