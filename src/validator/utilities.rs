//use bytes::Bytes;
//use crate::base::Dname;
use crate::base::iana::Nsec3HashAlg;
use crate::base::name::ToDname;
use crate::dep::octseq::OctetsBuilder;
use crate::rdata::nsec3::Nsec3Salt;
use crate::rdata::nsec3::OwnerHash;
use ring::digest;
use std::vec::Vec;

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
    N: ToDname,
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

    println!("hashing {buf:?}");

    ctx.update(&buf);
    let mut h = ctx.finish();
    println!("got {h:?}");

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

        println!("hashing {buf:?}");

        ctx.update(&buf);
        h = ctx.finish();
        println!("got {h:?}");
    }

    OwnerHash::from_octets(h.as_ref().to_vec()).unwrap()
}
