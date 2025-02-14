//! Base functions for DNSSEC validation.

use crate::base::iana::DigestAlg;
use crate::base::rdata::ComposeRecordData;
use crate::base::ToName;
use crate::crypto::common::{Digest, DigestContext, DigestType};
use crate::dep::octseq::builder::with_infallible;
use crate::rdata::Dnskey;

use std::vec::Vec;
use std::{error, fmt};

//------------ Dnskey --------------------------------------------------------

/// Extensions for DNSKEY record type.
pub trait DnskeyExt {
    /// Calculates a digest from DNSKEY.
    ///
    /// See [RFC 4034, Section 5.1.4]:
    ///
    /// ```text
    /// 5.1.4.  The Digest Field
    ///   The digest is calculated by concatenating the canonical form of the
    ///   fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    ///   and then applying the digest algorithm.
    ///
    ///     digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    ///
    ///      "|" denotes concatenation
    ///
    ///     DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    /// ```
    ///
    /// [RFC 4034, Section 5.1.4]: https://tools.ietf.org/html/rfc4034#section-5.1.4
    fn digest<N: ToName>(
        &self,
        name: &N,
        algorithm: DigestAlg,
    ) -> Result<Digest, AlgorithmError>;
}

impl<Octets> DnskeyExt for Dnskey<Octets>
where
    Octets: AsRef<[u8]>,
{
    /// Calculates a digest from DNSKEY.
    ///
    /// See [RFC 4034, Section 5.1.4]:
    ///
    /// ```text
    /// 5.1.4.  The Digest Field
    ///   The digest is calculated by concatenating the canonical form of the
    ///   fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    ///   and then applying the digest algorithm.
    ///
    ///     digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
    ///
    ///      "|" denotes concatenation
    ///
    ///     DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
    /// ```
    ///
    /// [RFC 4034, Section 5.1.4]: https://tools.ietf.org/html/rfc4034#section-5.1.4
    fn digest<N: ToName>(
        &self,
        name: &N,
        algorithm: DigestAlg,
    ) -> Result<Digest, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| {
            name.compose_canonical(&mut buf)?;
            self.compose_canonical_rdata(&mut buf)
        });

        let mut ctx = match algorithm {
            DigestAlg::SHA1 => DigestContext::new(DigestType::Sha1),
            DigestAlg::SHA256 => DigestContext::new(DigestType::Sha256),
            DigestAlg::SHA384 => DigestContext::new(DigestType::Sha384),
            _ => {
                return Err(AlgorithmError::Unsupported);
            }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }
}

/// Return whether a DigestAlg is supported or not.
// This needs to match the digests supported in digest.
pub fn supported_digest(d: &DigestAlg) -> bool {
    *d == DigestAlg::SHA1
        || *d == DigestAlg::SHA256
        || *d == DigestAlg::SHA384
}

//============ Error Types ===================================================

//------------ AlgorithmError ------------------------------------------------

/// An algorithm error during verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmError {
    /// Unsupported algorithm.
    Unsupported,

    /// Bad signature.
    BadSig,

    /// Invalid data.
    InvalidData,
}

//--- Display, Error

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            AlgorithmError::Unsupported => "unsupported algorithm",
            AlgorithmError::BadSig => "bad signature",
            AlgorithmError::InvalidData => "invalid data",
        })
    }
}

impl error::Error for AlgorithmError {}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::iana::SecAlg;
    use crate::utils::base64;

    type Dnskey = crate::rdata::Dnskey<Vec<u8>>;
    type Ds = crate::rdata::Ds<Vec<u8>>;
    type Name = crate::base::name::Name<Vec<u8>>;

    // Returns current root KSK/ZSK for testing (2048b)
    fn root_pubkey() -> (Dnskey, Dnskey) {
        let ksk = base64::decode::<Vec<u8>>(
            "\
            AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/\
            4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMt\
            NROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwV\
            N8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK\
            6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+c\
            n8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
        )
        .unwrap();
        let zsk = base64::decode::<Vec<u8>>(
            "\
            AwEAAeVDC34GZILwsQJy97K2Fst4P3XYZrXLyrkausYzSqEjSUulgh+iLgH\
            g0y7FIF890+sIjXsk7KLJUmCOWfYWPorNKEOKLk5Zx/4M6D3IHZE3O3m/Ea\
            hrc28qQzmTLxiMZAW65MvR2UO3LxVtYOPBEBiDgAQD47x2JLsJYtavCzNL5\
            WiUk59OgvHmDqmcC7VXYBhK8V8Tic089XJgExGeplKWUt9yyc31ra1swJX5\
            1XsOaQz17+vyLVH8AZP26KvKFiZeoRbaq6vl+hc8HQnI2ug5rA2zoz3MsSQ\
            BvP1f/HvqsWxLqwXXKyDD1QM639U+XzVB8CYigyscRP22QCnwKIU=",
        )
        .unwrap();
        (
            Dnskey::new(257, 3, SecAlg::RSASHA256, ksk).unwrap(),
            Dnskey::new(256, 3, SecAlg::RSASHA256, zsk).unwrap(),
        )
    }

    #[test]
    fn dnskey_digest() {
        let (dnskey, _) = root_pubkey();
        let owner = Name::root();
        let expected = Ds::new(
            20326,
            SecAlg::RSASHA256,
            DigestAlg::SHA256,
            base64::decode::<Vec<u8>>(
                "4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            dnskey.digest(&owner, DigestAlg::SHA256).unwrap().as_ref(),
            expected.digest()
        );
    }

    #[test]
    fn dnskey_digest_unsupported() {
        let (dnskey, _) = root_pubkey();
        let owner = Name::root();
        assert!(dnskey.digest(&owner, DigestAlg::GOST).is_err());
    }
}
