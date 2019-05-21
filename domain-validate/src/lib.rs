use derive_more::Display;
use domain_core::{Compose, ToDname};
use domain_core::iana::DigestAlg;
use domain_core::rdata::Dnskey;
use ring::digest;
use std::error;

//------------ AlgorithmError ------------------------------------------------

/// An algorithm error during verification.
#[derive(Clone, Debug, Display)]
pub enum AlgorithmError {
    #[display(fmt="unsupported algorithm")]
    Unsupported,
}

impl error::Error for AlgorithmError { }

/// Extensions for DNSKEY record type.
pub trait DnskeyExt: Compose {
    /// Calculates a digest from DNSKEY.
    /// See [RFC 4034, Section 5.1.4](https://tools.ietf.org/html/rfc4034#section-5.1.4)
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
    fn digest<N: ToDname>(&self, dname: &N, algorithm: DigestAlg) -> Result<digest::Digest, AlgorithmError>;
}

impl DnskeyExt for Dnskey {
    /// Calculates a digest from DNSKEY.
    /// See [RFC 4034, Section 5.1.4](https://tools.ietf.org/html/rfc4034#section-5.1.4)
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
    fn digest<N: ToDname>(&self, dname: &N, algorithm: DigestAlg) -> Result<digest::Digest, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        dname.compose(&mut buf);
        self.compose(&mut buf);

        let mut ctx = match algorithm {
            DigestAlg::Sha1 => digest::Context::new(&digest::SHA1),
            DigestAlg::Sha256 => digest::Context::new(&digest::SHA256),
            DigestAlg::Gost => { return Err(AlgorithmError::Unsupported); }
            DigestAlg::Sha384 => digest::Context::new(&digest::SHA384),
            _ => { return Err(AlgorithmError::Unsupported); }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;
    use domain_core::{Dname, iana::SecAlg, utils::base64, rdata::Ds};

    // Returns current root KSK for testing.
    fn root_pubkey() -> Dnskey {
        let pubkey = base64::decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").unwrap().into();
        Dnskey::new(257, 3, SecAlg::RsaSha256, pubkey)
    }

    #[test]
    fn dnskey_digest() {
        let dnskey = root_pubkey();
        let owner = Dname::root();
        let expected = Ds::new(20326, SecAlg::RsaSha256, DigestAlg::Sha256, base64::decode("4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=").unwrap().into());
        assert_eq!(dnskey.digest(&owner, DigestAlg::Sha256).unwrap().as_ref(), expected.digest().as_ref());
    }

    #[test]
    fn dnskey_digest_unsupported() {
        let dnskey = root_pubkey();
        let owner = Dname::root();
        assert_eq!(dnskey.digest(&owner, DigestAlg::Gost).is_err(), true);
    }
}