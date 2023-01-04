//! DNSSEC validation.
//!
//! **This module is experimental and likely to change significantly.**
#![cfg(feature = "validate")]
#![cfg_attr(docsrs, doc(cfg(feature = "validate")))]

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, SecAlg};
use crate::base::name::ToDname;
use crate::base::wire:: Composer;
use crate::base::rdata::RecordData;
use crate::base::record::Record;
use crate::rdata::{Dnskey, Rrsig};
use octseq::builder::{OctetsBuilder, ShortBuf};
use ring::{digest, signature};
use std::vec::Vec;
use std::{error, fmt};

//------------ Dnskey --------------------------------------------------------

/// Extensions for DNSKEY record type.
pub trait DnskeyExt: Compose {
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
    fn digest<N: ToDname>(
        &self,
        dname: &N,
        algorithm: DigestAlg,
    ) -> Result<digest::Digest, AlgorithmError>;
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
    fn digest<N: ToDname>(
        &self,
        dname: &N,
        algorithm: DigestAlg,
    ) -> Result<digest::Digest, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        dname.compose_canonical(&mut buf);
        self.compose_canonical(&mut buf);

        let mut ctx = match algorithm {
            DigestAlg::Sha1 => {
                digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
            }
            DigestAlg::Sha256 => digest::Context::new(&digest::SHA256),
            DigestAlg::Sha384 => digest::Context::new(&digest::SHA384),
            _ => {
                return Err(AlgorithmError::Unsupported);
            }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }
}

//------------ Rrsig ---------------------------------------------------------

/// Extensions for DNSKEY record type.
pub trait RrsigExt: Compose {
    /// Compose the signed data according to [RC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
    ///
    /// ```text
    ///    Once the RRSIG RR has met the validity requirements described in
    ///    Section 5.3.1, the validator has to reconstruct the original signed
    ///    data.  The original signed data includes RRSIG RDATA (excluding the
    ///    Signature field) and the canonical form of the RRset.  Aside from
    ///    being ordered, the canonical form of the RRset might also differ from
    ///    the received RRset due to DNS name compression, decremented TTLs, or
    ///    wildcard expansion.
    /// ```
    fn signed_data<
        N: ToDname,
        D: RecordData,
        B: OctetsBuilder + AsMut<[u8]>,
    >(
        &self,
        buf: &mut B,
        records: &mut [Record<N, D>],
    ) -> Result<(), ShortBuf>
    where
        D: CanonicalOrd + Compose + Sized;

    /// Attempt to use the cryptographic signature to authenticate the signed data, and thus authenticate the RRSET.
    /// The signed data is expected to be calculated as per [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
    ///
    /// [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2):
    /// ```text
    /// 5.3.3.  Checking the Signature
    ///
    ///    Once the resolver has validated the RRSIG RR as described in Section
    ///    5.3.1 and reconstructed the original signed data as described in
    ///    Section 5.3.2, the validator can attempt to use the cryptographic
    ///    signature to authenticate the signed data, and thus (finally!)
    ///    authenticate the RRset.
    ///
    ///    The Algorithm field in the RRSIG RR identifies the cryptographic
    ///    algorithm used to generate the signature.  The signature itself is
    ///    contained in the Signature field of the RRSIG RDATA, and the public
    ///    key used to verify the signature is contained in the Public Key field
    ///    of the matching DNSKEY RR(s) (found in Section 5.3.1).  [RFC4034]
    ///    provides a list of algorithm types and provides pointers to the
    ///    documents that define each algorithm's use.
    /// ```
    fn verify_signed_data(
        &self,
        dnskey: &Dnskey<impl AsRef<[u8]>>,
        signed_data: &impl AsRef<[u8]>,
    ) -> Result<(), AlgorithmError>;
}

impl<Octets: AsRef<[u8]>, Name: Compose> RrsigExt for Rrsig<Octets, Name> {
    fn signed_data<
        N: ToDname,
        D: RecordData,
        B: Composer,
    >(
        &self,
        buf: &mut B,
        records: &mut [Record<N, D>],
    ) -> Result<(), B::AppendError>
    where
        D: CanonicalOrd + Compose + Sized,
    {
        // signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //    "|" denotes concatenation
        // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //    with the Signature field excluded and the Signer's Name
        //    in canonical form.
        self.type_covered().try_compose(buf)?;
        self.algorithm().try_compose(buf)?;
        self.labels().try_compose(buf)?;
        self.original_ttl().try_compose(buf)?;
        self.expiration().try_compose(buf)?;
        self.inception().try_compose(buf)?;
        self.key_tag().try_compose(buf)?;
        self.signer_name().try_compose_canonical(buf)?;

        // The set of all RR(i) is sorted into canonical order.
        // See https://tools.ietf.org/html/rfc4034#section-6.3
        records.sort_by(|a, b| a.data().canonical_cmp(b.data()));

        // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
        for rr in records {
            // Handle expanded wildcards as per [RFC4035, Section 5.3.2]
            // (https://tools.ietf.org/html/rfc4035#section-5.3.2).
            let rrsig_labels = usize::from(self.labels());
            let fqdn = rr.owner();
            // Subtract the root label from count as the algorithm doesn't
            // accomodate that.
            let fqdn_labels = fqdn.iter_labels().count() - 1;
            if rrsig_labels < fqdn_labels {
                // name = "*." | the rightmost rrsig_label labels of the fqdn
                buf.append_slice(b"\x01*")?;
                match fqdn
                    .to_cow()
                    .iter_suffixes()
                    .nth(fqdn_labels - rrsig_labels)
                {
                    Some(name) => name.try_compose_canonical(buf)?,
                    None => fqdn.atry_compose_canonical(buf)?,
                }?;
            } else {
                fqdn.compose_canonical(buf)?;
            }

            rr.rtype().try_compose(buf)?;
            rr.class().try_compose(buf)?;
            self.original_ttl().try_compose(buf)?;
            buf.u16_len_prefixed(|buf| rr.data().compose_canonical(buf))?;
        }
        Ok(())
    }

    fn verify_signed_data(
        &self,
        dnskey: &Dnskey<impl AsRef<[u8]>>,
        signed_data: &impl AsRef<[u8]>,
    ) -> Result<(), AlgorithmError> {
        let signature = self.signature().as_ref();
        let signed_data = signed_data.as_ref();

        // Caller needs to ensure that the signature matches the key, but enforce the algorithm match
        if self.algorithm() != dnskey.algorithm() {
            return Err(AlgorithmError::InvalidData);
        }

        // Note: Canonicalize the algorithm, otherwise matching named variants against Int(_) is not going to work
        let sec_alg = SecAlg::from_int(self.algorithm().to_int());
        match sec_alg {
            SecAlg::RsaSha1
            | SecAlg::RsaSha1Nsec3Sha1
            | SecAlg::RsaSha256
            | SecAlg::RsaSha512 => {
                let (algorithm, min_bytes) = match sec_alg {
                    SecAlg::RsaSha1 | SecAlg::RsaSha1Nsec3Sha1 => (
                        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecAlg::RsaSha256 => (
                        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecAlg::RsaSha512 => (
                        &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    _ => unreachable!(),
                };

                // The key isn't available in either PEM or DER, so use the
                // direct RSA verifier.
                let (e, n) = rsa_exponent_modulus(dnskey, min_bytes)?;
                let public_key =
                    signature::RsaPublicKeyComponents { n: &n, e: &e };
                public_key
                    .verify(algorithm, signed_data, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::EcdsaP256Sha256 | SecAlg::EcdsaP384Sha384 => {
                let algorithm = match sec_alg {
                    SecAlg::EcdsaP256Sha256 => {
                        &signature::ECDSA_P256_SHA256_FIXED
                    }
                    SecAlg::EcdsaP384Sha384 => {
                        &signature::ECDSA_P384_SHA384_FIXED
                    }
                    _ => unreachable!(),
                };

                // Add 0x4 identifier to the ECDSA pubkey as expected by ring.
                let public_key = dnskey.public_key().as_ref();
                let mut key = Vec::with_capacity(public_key.len() + 1);
                key.push(0x4);
                key.extend_from_slice(public_key);

                signature::UnparsedPublicKey::new(algorithm, &key)
                    .verify(signed_data, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::Ed25519 => {
                let key = dnskey.public_key();
                signature::UnparsedPublicKey::new(&signature::ED25519, &key)
                    .verify(signed_data, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            _ => Err(AlgorithmError::Unsupported),
        }
    }
}

/// Return the RSA exponent and modulus components from DNSKEY record data.
fn rsa_exponent_modulus(
    dnskey: &Dnskey<impl AsRef<[u8]>>,
    min_len: usize,
) -> Result<(&[u8], &[u8]), AlgorithmError> {
    let public_key = dnskey.public_key().as_ref();
    if public_key.len() <= 3 {
        return Err(AlgorithmError::InvalidData);
    }

    let (pos, exp_len) = match public_key[0] {
        0 => (
            3,
            (usize::from(public_key[1]) << 8) | usize::from(public_key[2]),
        ),
        len => (1, usize::from(len)),
    };

    // Check if there's enough space for exponent and modulus.
    if public_key[pos..].len() < pos + exp_len {
        return Err(AlgorithmError::InvalidData);
    };

    // Check for minimum supported key size
    if public_key[pos..].len() < min_len {
        return Err(AlgorithmError::Unsupported);
    }

    Ok(public_key[pos..].split_at(exp_len))
}

//============ Error Types ===================================================

//------------ AlgorithmError ------------------------------------------------

/// An algorithm error during verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmError {
    Unsupported,
    BadSig,
    InvalidData,
}

//--- Display and Error

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AlgorithmError::Unsupported => {
                f.write_str("unsupported algorithm")
            }
            AlgorithmError::BadSig => f.write_str("bad signature"),
            AlgorithmError::InvalidData => f.write_str("invalid data"),
        }
    }
}

impl error::Error for AlgorithmError {}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::iana::{Class, Rtype, SecAlg};
    use crate::base::serial::Serial;
    use crate::rdata::{Mx, ZoneRecordData};
    use crate::utils::base64;
    use bytes::Bytes;
    use std::str::FromStr;
    use std::vec::Vec;

    type Dname = crate::base::name::Dname<Vec<u8>>;
    type Ds = crate::rdata::Ds<Vec<u8>>;
    type Dnskey = crate::rdata::Dnskey<Vec<u8>>;
    type Rrsig = crate::rdata::Rrsig<Vec<u8>, Dname>;

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
            Dnskey::new(257, 3, SecAlg::RsaSha256, ksk),
            Dnskey::new(256, 3, SecAlg::RsaSha256, zsk),
        )
    }

    // Returns the current net KSK/ZSK for testing (1024b)
    fn net_pubkey() -> (Dnskey, Dnskey) {
        let ksk = base64::decode::<Vec<u8>>(
            "AQOYBnzqWXIEj6mlgXg4LWC0HP2n8eK8XqgHlmJ/69iuIHsa1TrHDG6TcOra/pyeGKwH0nKZhTmXSuUFGh9BCNiwVDuyyb6OBGy2Nte9Kr8NwWg4q+zhSoOf4D+gC9dEzg0yFdwT0DKEvmNPt0K4jbQDS4Yimb+uPKuF6yieWWrPYYCrv8C9KC8JMze2uT6NuWBfsl2fDUoV4l65qMww06D7n+p7RbdwWkAZ0fA63mXVXBZF6kpDtsYD7SUB9jhhfLQE/r85bvg3FaSs5Wi2BaqN06SzGWI1DHu7axthIOeHwg00zxlhTpoYCH0ldoQz+S65zWYi/fRJiyLSBb6JZOvn",
        )
        .unwrap();
        let zsk = base64::decode::<Vec<u8>>(
            "AQPW36Zs2vsDFGgdXBlg8RXSr1pSJ12NK+u9YcWfOr85we2z5A04SKQlIfyTK37dItGFcldtF7oYwPg11T3R33viKV6PyASvnuRl8QKiLk5FfGUDt1sQJv3S/9wT22Le1vnoE/6XFRyeb8kmJgz0oQB1VAO9b0l6Vm8KAVeOGJ+Qsjaq0O0aVzwPvmPtYm/i3qoAhkaMBUpg6RrF5NKhRyG3",
        )
        .unwrap();
        (
            Dnskey::new(257, 3, SecAlg::RsaSha256, ksk),
            Dnskey::new(256, 3, SecAlg::RsaSha256, zsk),
        )
    }

    #[test]
    fn dnskey_digest() {
        let (dnskey, _) = root_pubkey();
        let owner = Dname::root();
        let expected = Ds::new(
            20326,
            SecAlg::RsaSha256,
            DigestAlg::Sha256,
            base64::decode::<Vec<u8>>(
                "4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=",
            )
            .unwrap(),
        );
        assert_eq!(
            dnskey.digest(&owner, DigestAlg::Sha256).unwrap().as_ref(),
            expected.digest()
        );
    }

    #[test]
    fn dnskey_digest_unsupported() {
        let (dnskey, _) = root_pubkey();
        let owner = Dname::root();
        assert!(dnskey.digest(&owner, DigestAlg::Gost).is_err());
    }

    fn rrsig_verify_dnskey(ksk: Dnskey, zsk: Dnskey, rrsig: Rrsig) {
        let mut records: Vec<_> = [&ksk, &zsk]
            .iter()
            .cloned()
            .map(|x| {
                Record::new(
                    rrsig.signer_name().clone(),
                    Class::In,
                    0,
                    x.clone(),
                )
            })
            .collect();
        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, records.as_mut_slice()).unwrap();
            Bytes::from(buf)
        };

        // Test that the KSK is sorted after ZSK key
        assert_eq!(ksk.key_tag(), rrsig.key_tag());
        assert_eq!(ksk.key_tag(), records[1].data().key_tag());

        // Test verifier
        assert!(rrsig.verify_signed_data(&ksk, &signed_data).is_ok());
        assert!(rrsig.verify_signed_data(&zsk, &signed_data).is_err());
    }

    #[test]
    fn rrsig_verify_rsa_sha256() {
        // Test 2048b long key
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(
            Rtype::Dnskey,
            SecAlg::RsaSha256,
            0,
            172800,
            1560211200.into(),
            1558396800.into(),
            20326,
            Dname::root(),
            base64::decode::<Vec<u8>>(
                "otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZOdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gqxthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooEb7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4/yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQdg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==",
            )
            .unwrap()
        );
        rrsig_verify_dnskey(ksk, zsk, rrsig);

        // Test 1024b long key
        let (ksk, zsk) = net_pubkey();
        let rrsig = Rrsig::new(
            Rtype::Dnskey,
            SecAlg::RsaSha256,
            1,
            86400,
            Serial::rrsig_from_str("20210921162830").unwrap(),
            Serial::rrsig_from_str("20210906162330").unwrap(),
            35886,
            "net.".parse::<Dname>().unwrap(),
            base64::decode::<Vec<u8>>(
                "j1s1IPMoZd0mbmelNVvcbYNe2tFCdLsLpNCnQ8xW6d91ujwPZ2yDlc3lU3hb+Jq3sPoj+5lVgB7fZzXQUQTPFWLF7zvW49da8pWuqzxFtg6EjXRBIWH5rpEhOcr+y3QolJcPOTx+/utCqt2tBKUUy3LfM6WgvopdSGaryWdwFJPW7qKHjyyLYxIGx5AEuLfzsA5XZf8CmpUheSRH99GRZoIB+sQzHuelWGMQ5A42DPvOVZFmTpIwiT2QaIpid4nJ7jNfahfwFrCoS+hvqjK9vktc5/6E/Mt7DwCQDaPt5cqDfYltUitQy+YA5YP5sOhINChYadZe+2N80OA+RKz0mA==",
            )
            .unwrap()
        );
        rrsig_verify_dnskey(ksk, zsk, rrsig.clone());

        // Test that 512b short RSA DNSKEY is not supported (too short)
        let data = base64::decode::<Vec<u8>>(
            "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
        )
        .unwrap();

        let short_key = Dnskey::new(256, 3, SecAlg::RsaSha256, data);
        let err = rrsig
            .verify_signed_data(&short_key, &vec![0; 100])
            .unwrap_err();
        assert_eq!(err, AlgorithmError::Unsupported);
    }

    #[test]
    fn rrsig_verify_ecdsap256_sha256() {
        let (ksk, zsk) = (
            Dnskey::new(
                257,
                3,
                SecAlg::EcdsaP256Sha256,
                base64::decode::<Vec<u8>>(
                    "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAe\
                    F+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
                )
                .unwrap(),
            ),
            Dnskey::new(
                256,
                3,
                SecAlg::EcdsaP256Sha256,
                base64::decode::<Vec<u8>>(
                    "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IR\
                    d8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
                )
                .unwrap(),
            ),
        );

        let owner = Dname::from_str("cloudflare.com.").unwrap();
        let rrsig = Rrsig::new(
            Rtype::Dnskey,
            SecAlg::EcdsaP256Sha256,
            2,
            3600,
            1560314494.into(),
            1555130494.into(),
            2371,
            owner,
            base64::decode::<Vec<u8>>(
                "8jnAGhG7O52wmL065je10XQztRX1vK8P8KBSyo71Z6h5wAT9+GFxKBaE\
                zcJBLvRmofYFDAhju21p1uTfLaYHrg==",
            )
            .unwrap(),
        );
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ed25519() {
        let (ksk, zsk) = (
            Dnskey::new(
                257,
                3,
                SecAlg::Ed25519,
                base64::decode::<Vec<u8>>(
                    "m1NELLVVQKl4fHVn/KKdeNO0PrYKGT3IGbYseT8XcKo=",
                )
                .unwrap(),
            ),
            Dnskey::new(
                256,
                3,
                SecAlg::Ed25519,
                base64::decode::<Vec<u8>>(
                    "2tstZAjgmlDTePn0NVXrAHBJmg84LoaFVxzLl1anjGI=",
                )
                .unwrap(),
            ),
        );

        let owner =
            Dname::from_octets(Vec::from(b"\x07ED25519\x02nl\x00".as_ref()))
                .unwrap();
        let rrsig = Rrsig::new(
            Rtype::Dnskey,
            SecAlg::Ed25519,
            2,
            3600,
            1559174400.into(),
            1557360000.into(),
            45515,
            owner,
            base64::decode::<Vec<u8>>(
                "hvPSS3E9Mx7lMARqtv6IGiw0NE0uz0mZewndJCHTkhwSYqlasUq7KfO5\
                QdtgPXja7YkTaqzrYUbYk01J8ICsAA==",
            )
            .unwrap(),
        );
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_generic_type() {
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(
            Rtype::Dnskey,
            SecAlg::RsaSha256,
            0,
            172800,
            1560211200.into(),
            1558396800.into(),
            20326,
            Dname::root(),
            base64::decode::<Vec<u8>>(
                "otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZ\
                OdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gq\
                xthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooE\
                b7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4\
                /yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQ\
                dg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==",
            )
            .unwrap(),
        );

        let mut records: Vec<Record<Dname, ZoneRecordData<Vec<u8>, Dname>>> =
            [&ksk, &zsk]
                .iter()
                .cloned()
                .map(|x| {
                    let data = ZoneRecordData::from(x.clone());
                    Record::new(
                        rrsig.signer_name().clone(),
                        Class::In,
                        0,
                        data,
                    )
                })
                .collect();

        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, records.as_mut_slice()).unwrap();
            Bytes::from(buf)
        };

        assert!(rrsig.verify_signed_data(&ksk, &signed_data).is_ok());
    }

    #[test]
    fn rrsig_verify_wildcard() {
        let key = Dnskey::new(
            256,
            3,
            SecAlg::RsaSha1,
            base64::decode::<Vec<u8>>(
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxX\
                HZS4i8dANH4DX3tbHol61ek8EFMcsGXxKciJFHyhl94C+NwILQd\
                zsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZIySFNsgEY\
                vh0z2542lzMKR4Dh8uZffQ==",
            )
            .unwrap(),
        );
        let rrsig = Rrsig::new(
            Rtype::Mx,
            SecAlg::RsaSha1,
            2,
            3600,
            Serial::rrsig_from_str("20040509183619").unwrap(),
            Serial::rrsig_from_str("20040409183619").unwrap(),
            38519,
            Dname::from_str("example.").unwrap(),
            base64::decode::<Vec<u8>>(
                "OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2f9AMN1CytCd10cYI\
                 SAxfAdvXSZ7xujKAtPbctvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhq\
                 e2XTjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw4kX18MMR34i8lC\
                 36SR5xBni8vHI=",
            )
            .unwrap(),
        );
        let record = Record::new(
            Dname::from_str("a.z.w.example.").unwrap(),
            Class::In,
            3600,
            Mx::new(1, Dname::from_str("ai.example.").unwrap()),
        );
        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, &mut [record]).unwrap();
            Bytes::from(buf)
        };

        // Test that the key matches RRSIG
        assert_eq!(key.key_tag(), rrsig.key_tag());

        // Test verifier
        assert_eq!(rrsig.verify_signed_data(&key, &signed_data), Ok(()));
    }
}
