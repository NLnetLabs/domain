//! Base functions for DNSSEC validation.

use crate::base::iana::{DigestAlgorithm, SecurityAlgorithm};
use crate::base::rdata::ComposeRecordData;
use crate::base::wire::{Compose, Composer};
use crate::base::{CanonicalOrd, Name, Record, RecordData, ToName};
use crate::crypto::common::{
    AlgorithmError, Digest, DigestBuilder, DigestType, PublicKey,
};
use crate::dep::octseq::builder::with_infallible;
use crate::rdata::{Dnskey, Rrsig};

use bytes::Bytes;

use std::vec::Vec;

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
        algorithm: DigestAlgorithm,
    ) -> Result<Digest, AlgorithmError>;

    /// Return the key size in bits or an error if the algorithm is not
    /// supported.
    fn key_size(&self) -> Result<usize, AlgorithmError>;
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
        algorithm: DigestAlgorithm,
    ) -> Result<Digest, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        with_infallible(|| {
            name.compose_canonical(&mut buf)?;
            self.compose_canonical_rdata(&mut buf)
        });

        let mut ctx = match algorithm {
            DigestAlgorithm::SHA1 => DigestBuilder::new(DigestType::Sha1),
            DigestAlgorithm::SHA256 => DigestBuilder::new(DigestType::Sha256),
            DigestAlgorithm::SHA384 => DigestBuilder::new(DigestType::Sha384),
            _ => {
                return Err(AlgorithmError::Unsupported);
            }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }

    /// The size of this key, in bits.
    ///
    /// For RSA keys, this measures the size of the public modulus.  For all
    /// other algorithms, it is the size of the fixed-width public key.
    fn key_size(&self) -> Result<usize, AlgorithmError> {
        match self.algorithm() {
            SecurityAlgorithm::RSASHA1
            | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
            | SecurityAlgorithm::RSASHA256
            | SecurityAlgorithm::RSASHA512 => {
                let data = self.public_key().as_ref();
                // The exponent length is encoded as 1 or 3 bytes.
                let (exp_len, off) = if data[0] != 0 {
                    (data[0] as usize, 1)
                } else {
                    // NOTE: Even though this is the extended encoding of the length,
                    // a user could choose to put a length less than 256 over here.
                    let exp_len =
                        u16::from_be_bytes(data[1..3].try_into().unwrap());
                    (exp_len as usize, 3)
                };
                let n = &data[off + exp_len..];
                Ok(n.len() * 8 - n[0].leading_zeros() as usize)
            }
            SecurityAlgorithm::ECDSAP256SHA256
            | SecurityAlgorithm::ECDSAP384SHA384 => {
                // ECDSA public keys have two points.
                Ok(self.public_key().as_ref().len() / 2 * 8)
            }
            SecurityAlgorithm::ED25519 | SecurityAlgorithm::ED448 => {
                // EdDSA public key sizes are measured in encoded form.
                Ok(self.public_key().as_ref().len() * 8)
            }
            _ => Err(AlgorithmError::Unsupported),
        }
    }
}

/// Return whether a DigestAlgorithm is supported or not.
// This needs to match the digests supported in digest.
pub fn supported_digest(d: &DigestAlgorithm) -> bool {
    *d == DigestAlgorithm::SHA1
        || *d == DigestAlgorithm::SHA256
        || *d == DigestAlgorithm::SHA384
}

//------------ Rrsig ---------------------------------------------------------

/// Extensions for DNSKEY record type.
pub trait RrsigExt {
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
    fn signed_data<N: ToName, D, B: Composer>(
        &self,
        buf: &mut B,
        records: &mut [impl AsRef<Record<N, D>>],
    ) -> Result<(), B::AppendError>
    where
        D: RecordData + CanonicalOrd + ComposeRecordData + Sized;

    /// Return if records are expanded for a wildcard according to the
    /// information in this signature.
    fn wildcard_closest_encloser<N, D>(
        &self,
        rr: &Record<N, D>,
    ) -> Option<Name<Bytes>>
    where
        N: ToName;

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

impl<Octets: AsRef<[u8]>, TN: ToName> RrsigExt for Rrsig<Octets, TN> {
    fn signed_data<N: ToName, D, B: Composer>(
        &self,
        buf: &mut B,
        records: &mut [impl AsRef<Record<N, D>>],
    ) -> Result<(), B::AppendError>
    where
        D: RecordData + CanonicalOrd + ComposeRecordData + Sized,
    {
        // signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //    "|" denotes concatenation
        // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //    with the Signature field excluded and the Signer's Name
        //    in canonical form.
        self.type_covered().compose(buf)?;
        self.algorithm().compose(buf)?;
        self.labels().compose(buf)?;
        self.original_ttl().compose(buf)?;
        self.expiration().compose(buf)?;
        self.inception().compose(buf)?;
        self.key_tag().compose(buf)?;
        self.signer_name().compose_canonical(buf)?;

        // The set of all RR(i) is sorted into canonical order.
        // See https://tools.ietf.org/html/rfc4034#section-6.3
        records.sort_by(|a, b| {
            a.as_ref().data().canonical_cmp(b.as_ref().data())
        });

        // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
        for rr in records.iter().map(|r| r.as_ref()) {
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
                    Some(name) => name.compose_canonical(buf)?,
                    None => fqdn.compose_canonical(buf)?,
                };
            } else {
                fqdn.compose_canonical(buf)?;
            }

            rr.rtype().compose(buf)?;
            rr.class().compose(buf)?;
            self.original_ttl().compose(buf)?;
            rr.data().compose_canonical_len_rdata(buf)?;
        }
        Ok(())
    }

    fn wildcard_closest_encloser<N, D>(
        &self,
        rr: &Record<N, D>,
    ) -> Option<Name<Bytes>>
    where
        N: ToName,
    {
        // Handle expanded wildcards as per [RFC4035, Section 5.3.2]
        // (https://tools.ietf.org/html/rfc4035#section-5.3.2).
        let rrsig_labels = usize::from(self.labels());
        let fqdn = rr.owner();
        // Subtract the root label from count as the algorithm doesn't
        // accomodate that.
        let fqdn_labels = fqdn.iter_labels().count() - 1;
        if rrsig_labels < fqdn_labels {
            // name = "*." | the rightmost rrsig_label labels of the fqdn
            Some(
                match fqdn
                    .to_cow()
                    .iter_suffixes()
                    .nth(fqdn_labels - rrsig_labels)
                {
                    Some(name) => Name::from_octets(Bytes::copy_from_slice(
                        name.as_octets(),
                    ))
                    .unwrap(),
                    None => fqdn.to_bytes(),
                },
            )
        } else {
            None
        }
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

        let public_key = PublicKey::from_dnskey(dnskey)?;
        public_key.verify(signed_data, signature)
    }
}

/// Report whether an algorithm is supported or not.
// This needs to match the algorithms supported in signed_data.
pub fn supported_algorithm(a: &SecurityAlgorithm) -> bool {
    *a == SecurityAlgorithm::RSASHA1
        || *a == SecurityAlgorithm::RSASHA1_NSEC3_SHA1
        || *a == SecurityAlgorithm::RSASHA256
        || *a == SecurityAlgorithm::RSASHA512
        || *a == SecurityAlgorithm::ECDSAP256SHA256
}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::iana::{Class, Rtype, SecurityAlgorithm};
    use crate::base::scan::{IterScanner, Scanner};
    use crate::base::Ttl;
    use crate::dnssec::common::parse_from_bind;
    use crate::rdata::dnssec::Timestamp;
    use crate::rdata::{Mx, ZoneRecordData};
    use crate::utils::base64;

    use std::str::FromStr;

    type Dnskey = crate::rdata::Dnskey<Vec<u8>>;
    type Ds = crate::rdata::Ds<Vec<u8>>;
    type Name = crate::base::name::Name<Vec<u8>>;
    type Rrsig = crate::rdata::Rrsig<Vec<u8>, Name>;

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
            Dnskey::new(257, 3, SecurityAlgorithm::RSASHA256, ksk).unwrap(),
            Dnskey::new(256, 3, SecurityAlgorithm::RSASHA256, zsk).unwrap(),
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
            Dnskey::new(257, 3, SecurityAlgorithm::RSASHA256, ksk).unwrap(),
            Dnskey::new(256, 3, SecurityAlgorithm::RSASHA256, zsk).unwrap(),
        )
    }

    #[test]
    fn dnskey_digest() {
        let (dnskey, _) = root_pubkey();
        let owner = Name::root();
        let expected = Ds::new(
            20326,
            SecurityAlgorithm::RSASHA256,
            DigestAlgorithm::SHA256,
            base64::decode::<Vec<u8>>(
                "4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            dnskey
                .digest(&owner, DigestAlgorithm::SHA256)
                .unwrap()
                .as_ref(),
            expected.digest()
        );
    }

    #[test]
    fn rrsig_verify_rsa_sha256() {
        // Test 2048b long key
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::RSASHA256,
            0,
            Ttl::from_secs(172800),
            1560211200.into(),
            1558396800.into(),
            20326,
            Name::root(),
            base64::decode::<Vec<u8>>(
                "otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZOdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gqxthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooEb7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4/yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQdg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==",
            )
            .unwrap()
        ).unwrap();
        rrsig_verify_dnskey(ksk, zsk, rrsig);

        // Test 1024b long key
        let (ksk, zsk) = net_pubkey();
        let rrsig = Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::RSASHA256,
            1,
            Ttl::from_secs(86400),
            Timestamp::from_str("20210921162830").unwrap(),
            Timestamp::from_str("20210906162330").unwrap(),
            35886,
            "net.".parse::<Name>().unwrap(),
            base64::decode::<Vec<u8>>(
                "j1s1IPMoZd0mbmelNVvcbYNe2tFCdLsLpNCnQ8xW6d91ujwPZ2yDlc3lU3hb+Jq3sPoj+5lVgB7fZzXQUQTPFWLF7zvW49da8pWuqzxFtg6EjXRBIWH5rpEhOcr+y3QolJcPOTx+/utCqt2tBKUUy3LfM6WgvopdSGaryWdwFJPW7qKHjyyLYxIGx5AEuLfzsA5XZf8CmpUheSRH99GRZoIB+sQzHuelWGMQ5A42DPvOVZFmTpIwiT2QaIpid4nJ7jNfahfwFrCoS+hvqjK9vktc5/6E/Mt7DwCQDaPt5cqDfYltUitQy+YA5YP5sOhINChYadZe+2N80OA+RKz0mA==",
            )
            .unwrap()
        ).unwrap();
        rrsig_verify_dnskey(ksk, zsk, rrsig.clone());

        // Test that 512b short RSA DNSKEY is not supported (too short)
        let data = base64::decode::<Vec<u8>>(
            "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
        )
        .unwrap();

        let short_key =
            Dnskey::new(256, 3, SecurityAlgorithm::RSASHA256, data).unwrap();
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
                SecurityAlgorithm::ECDSAP256SHA256,
                base64::decode::<Vec<u8>>(
                    "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAe\
                    F+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
                )
                .unwrap(),
            )
            .unwrap(),
            Dnskey::new(
                256,
                3,
                SecurityAlgorithm::ECDSAP256SHA256,
                base64::decode::<Vec<u8>>(
                    "oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IR\
                    d8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        let owner = Name::from_str("cloudflare.com.").unwrap();
        let rrsig = Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::ECDSAP256SHA256,
            2,
            Ttl::from_secs(3600),
            1560314494.into(),
            1555130494.into(),
            2371,
            owner,
            base64::decode::<Vec<u8>>(
                "8jnAGhG7O52wmL065je10XQztRX1vK8P8KBSyo71Z6h5wAT9+GFxKBaE\
                zcJBLvRmofYFDAhju21p1uTfLaYHrg==",
            )
            .unwrap(),
        )
        .unwrap();
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ed25519() {
        let (ksk, zsk) = (
            Dnskey::new(
                257,
                3,
                SecurityAlgorithm::ED25519,
                base64::decode::<Vec<u8>>(
                    "m1NELLVVQKl4fHVn/KKdeNO0PrYKGT3IGbYseT8XcKo=",
                )
                .unwrap(),
            )
            .unwrap(),
            Dnskey::new(
                256,
                3,
                SecurityAlgorithm::ED25519,
                base64::decode::<Vec<u8>>(
                    "2tstZAjgmlDTePn0NVXrAHBJmg84LoaFVxzLl1anjGI=",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        let owner =
            Name::from_octets(Vec::from(b"\x07ED25519\x02nl\x00".as_ref()))
                .unwrap();
        let rrsig = Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::ED25519,
            2,
            Ttl::from_secs(3600),
            1559174400.into(),
            1557360000.into(),
            45515,
            owner,
            base64::decode::<Vec<u8>>(
                "hvPSS3E9Mx7lMARqtv6IGiw0NE0uz0mZewndJCHTkhwSYqlasUq7KfO5\
                QdtgPXja7YkTaqzrYUbYk01J8ICsAA==",
            )
            .unwrap(),
        )
        .unwrap();
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_generic_type() {
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(
            Rtype::DNSKEY,
            SecurityAlgorithm::RSASHA256,
            0,
            Ttl::from_secs(172800),
            1560211200.into(),
            1558396800.into(),
            20326,
            Name::root(),
            base64::decode::<Vec<u8>>(
                "otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZ\
                OdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gq\
                xthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooE\
                b7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4\
                /yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQ\
                dg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==",
            )
            .unwrap(),
        )
        .unwrap();

        let mut records: Vec<Record<Name, ZoneRecordData<Vec<u8>, Name>>> =
            [&ksk, &zsk]
                .iter()
                .cloned()
                .map(|x| {
                    let data = ZoneRecordData::from(x.clone());
                    Record::new(
                        rrsig.signer_name().clone(),
                        Class::IN,
                        Ttl::from_secs(0),
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
            SecurityAlgorithm::RSASHA1,
            base64::decode::<Vec<u8>>(
                "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxX\
                HZS4i8dANH4DX3tbHol61ek8EFMcsGXxKciJFHyhl94C+NwILQd\
                zsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZIySFNsgEY\
                vh0z2542lzMKR4Dh8uZffQ==",
            )
            .unwrap(),
        )
        .unwrap();
        let rrsig = Rrsig::new(
            Rtype::MX,
            SecurityAlgorithm::RSASHA1,
            2,
            Ttl::from_secs(3600),
            Timestamp::from_str("20040509183619").unwrap(),
            Timestamp::from_str("20040409183619").unwrap(),
            38519,
            Name::from_str("example.").unwrap(),
            base64::decode::<Vec<u8>>(
                "OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2f9AMN1CytCd10cYI\
                 SAxfAdvXSZ7xujKAtPbctvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhq\
                 e2XTjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw4kX18MMR34i8lC\
                 36SR5xBni8vHI=",
            )
            .unwrap(),
        )
        .unwrap();
        let record = Record::new(
            Name::from_str("a.z.w.example.").unwrap(),
            Class::IN,
            Ttl::from_secs(3600),
            Mx::new(1, Name::from_str("ai.example.").unwrap()),
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

    fn rrsig_verify_dnskey(ksk: Dnskey, zsk: Dnskey, rrsig: Rrsig) {
        let mut records: Vec<_> = [&ksk, &zsk]
            .iter()
            .cloned()
            .map(|x| {
                Record::new(
                    rrsig.signer_name().clone(),
                    Class::IN,
                    Ttl::from_secs(0),
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
    fn dnskey_digest_unsupported() {
        let (dnskey, _) = root_pubkey();
        let owner = Name::root();
        assert!(dnskey.digest(&owner, DigestAlgorithm::GOST).is_err());
    }

    const KEYS: &[(SecurityAlgorithm, u16, usize)] = &[
        (SecurityAlgorithm::RSASHA1, 439, 2048),
        (SecurityAlgorithm::RSASHA1_NSEC3_SHA1, 22204, 2048),
        (SecurityAlgorithm::RSASHA256, 60616, 2048),
        (SecurityAlgorithm::ECDSAP256SHA256, 42253, 256),
        (SecurityAlgorithm::ECDSAP384SHA384, 33566, 384),
        (SecurityAlgorithm::ED25519, 56037, 256),
        (SecurityAlgorithm::ED448, 7379, 456),
    ];

    #[test]
    fn key_size() {
        for &(algorithm, key_tag, key_size) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = parse_from_bind::<Vec<u8>>(&data).unwrap();
            assert_eq!(key.data().key_size(), Ok(key_size));
        }
    }

    #[test]
    fn digest() {
        for &(algorithm, key_tag, _) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = parse_from_bind::<Vec<u8>>(&data).unwrap();

            // Scan the DS record from the file.
            let path = format!("test-data/dnssec-keys/K{}.ds", name);
            let data = std::fs::read_to_string(path).unwrap();
            let mut scanner = IterScanner::new(data.split_ascii_whitespace());
            let _ = scanner.scan_name().unwrap();
            let _ = Class::scan(&mut scanner).unwrap();
            assert_eq!(Rtype::scan(&mut scanner).unwrap(), Rtype::DS);
            let ds = Ds::scan(&mut scanner).unwrap();

            let key_ds = Ds::new(
                key.data().key_tag(),
                key.data().algorithm(),
                ds.digest_type(),
                key.data()
                    .digest(key.owner(), ds.digest_type())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            )
            .unwrap();

            assert_eq!(key_ds, ds);
        }
    }
}
