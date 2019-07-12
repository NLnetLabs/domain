use bytes::{BufMut, Bytes};
use derive_more::Display;
use domain_core::iana::{DigestAlg, SecAlg};
use domain_core::rdata::{Dnskey, Rrsig, RecordData};
use domain_core::{CanonicalOrd, Compose, Compress, Record, ToDname};
use ring::{digest, signature};
use std::error;

//------------ AlgorithmError ------------------------------------------------

/// An algorithm error during verification.
#[derive(Clone, Debug, Display)]
pub enum AlgorithmError {
    #[display(fmt = "unsupported algorithm")]
    Unsupported,
    #[display(fmt = "bad signature")]
    BadSig,
}

impl error::Error for AlgorithmError {}

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
    fn digest<N: ToDname>(
        &self,
        dname: &N,
        algorithm: DigestAlg,
    ) -> Result<digest::Digest, AlgorithmError>;

    // Extract public key exponent and modulus.
    // See [RFC3110, Section 2](https://tools.ietf.org/html/rfc3110#section-2)
    fn rsa_exponent_modulus(&self) -> Result<(&[u8], &[u8]), AlgorithmError>;
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
    fn digest<N: ToDname>(
        &self,
        dname: &N,
        algorithm: DigestAlg,
    ) -> Result<digest::Digest, AlgorithmError> {
        let mut buf: Vec<u8> = Vec::new();
        dname.compose(&mut buf);
        self.compose(&mut buf);

        let mut ctx = match algorithm {
            DigestAlg::Sha1 => digest::Context::new(&digest::SHA1),
            DigestAlg::Sha256 => digest::Context::new(&digest::SHA256),
            DigestAlg::Gost => {
                return Err(AlgorithmError::Unsupported);
            }
            DigestAlg::Sha384 => digest::Context::new(&digest::SHA384),
            _ => {
                return Err(AlgorithmError::Unsupported);
            }
        };

        ctx.update(&buf);
        Ok(ctx.finish())
    }

    fn rsa_exponent_modulus(&self) -> Result<(&[u8], &[u8]), AlgorithmError> {
        assert!(self.algorithm() == SecAlg::RsaSha1 || self.algorithm() == SecAlg::RsaSha256);

        let public_key = self.public_key();
        if public_key.len() <= 3 {
            // TODO: return a better error
            return Err(AlgorithmError::Unsupported);
        }

        let (pos, exp_len) = match public_key[0] {
            0 => (
                3,
                (usize::from(public_key[1]) << 8) | usize::from(public_key[2]),
            ),
            len => (1, usize::from(len)),
        };

        // Check if there's enough space for exponent and modulus.
        if public_key.len() < pos + exp_len {
            return Err(AlgorithmError::Unsupported);
        };

        Ok(public_key[pos..].split_at(exp_len))
    }
}

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
    fn signed_data<N: ToDname, D: RecordData, B: BufMut>(
        &self,
        buf: &mut B,
        records: &mut [Record<N, D>],
    ) where
        D: CanonicalOrd + Compose + Compress + Sized;

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
        dnskey: &Dnskey,
        signed_data: &Bytes,
    ) -> Result<(), AlgorithmError>;
}

impl RrsigExt for Rrsig {
    fn signed_data<N: ToDname, D: RecordData + CanonicalOrd, B: BufMut>(
        &self,
        buf: &mut B,
        records: &mut [Record<N, D>],
    ) where
        D: CanonicalOrd + Compose + Compress + Sized,
    {
        // signed_data = RRSIG_RDATA | RR(1) | RR(2)...  where
        //    "|" denotes concatenation
        // RRSIG_RDATA is the wire format of the RRSIG RDATA fields
        //    with the Signature field excluded and the Signer's Name
        //    in canonical form.
        self.type_covered().compose(buf);
        self.algorithm().compose(buf);
        self.labels().compose(buf);
        self.original_ttl().compose(buf);
        self.expiration().compose(buf);
        self.inception().compose(buf);
        self.key_tag().compose(buf);
        self.signer_name().compose_canonical(buf);

        // The set of all RR(i) is sorted into canonical order.
        // See https://tools.ietf.org/html/rfc4034#section-6.3
        records.sort_by(|a, b| a.data().canonical_cmp(b.data()));

        // RR(i) = name | type | class | OrigTTL | RDATA length | RDATA
        for rr in records {
            // Handle expanded wildcards as per [RFC4035, Section 5.3.2](https://tools.ietf.org/html/rfc4035#section-5.3.2).
            let rrsig_labels = usize::from(self.labels());
            let fqdn = rr.owner();
            // Subtract the root label from count as the algorithm doesn't accomodate that.
            let mut fqdn_labels = fqdn.iter_labels().count() - 1;
            if rrsig_labels < fqdn_labels {
                // name = "*." | the rightmost rrsig_label labels of the fqdn
                b"\x01*".compose(buf);
                let mut fqdn = fqdn.to_name();
                while fqdn_labels < rrsig_labels {
                    fqdn.parent();
                    fqdn_labels -= 1;
                }
                fqdn.compose_canonical(buf);
            } else {
                fqdn.compose_canonical(buf);
            }

            rr.rtype().compose(buf);
            rr.class().compose(buf);
            self.original_ttl().compose(buf);
            let rdlen = rr.data().compose_len() as u16;
            rdlen.compose(buf);
            rr.data().compose_canonical(buf);
        }
    }

    fn verify_signed_data(
        &self,
        dnskey: &Dnskey,
        signed_data: &Bytes,
    ) -> Result<(), AlgorithmError> {
        use untrusted::Input;

        let message = untrusted::Input::from(signed_data);
        let signature = Input::from(self.signature());

        match self.algorithm() {
            SecAlg::RsaSha1 | SecAlg::RsaSha256 | SecAlg::RsaSha512 => {
                let algorithm = match self.algorithm() {
                    SecAlg::RsaSha1 => &signature::RSA_PKCS1_2048_8192_SHA1,
                    SecAlg::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
                    SecAlg::RsaSha512 => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => unreachable!(),
                };
                // The key isn't available in either PEM or DER, so use the direct RSA verifier.
                let (e, m) = dnskey.rsa_exponent_modulus()?;
                signature::primitive::verify_rsa(
                    algorithm,
                    (Input::from(m), Input::from(e)),
                    message,
                    signature,
                )
                .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::EcdsaP256Sha256 | SecAlg::EcdsaP384Sha384 => {
                let algorithm = match self.algorithm() {
                    SecAlg::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
                    SecAlg::EcdsaP384Sha384 => &signature::ECDSA_P384_SHA384_FIXED,
                    _ => unreachable!(),
                };

                // Add 0x4 identifier to the ECDSA pubkey as expected by ring.
                let public_key = dnskey.public_key();
                let mut key = Vec::with_capacity(public_key.len() + 1);
                key.push(0x4);
                key.extend_from_slice(&public_key);

                signature::verify(algorithm, Input::from(&key), message, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            SecAlg::Ed25519 => {
                let key = dnskey.public_key();
                signature::verify(&signature::ED25519, Input::from(&key), message, signature)
                    .map_err(|_| AlgorithmError::BadSig)
            }
            _ => return Err(AlgorithmError::Unsupported),
        }
    }
}

//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;
    use domain_core::iana::{Class, Rtype, SecAlg};
    use domain_core::{rdata::{MasterRecordData, Ds}, utils::base64, Dname};

    // Returns current root KSK/ZSK for testing.
    fn root_pubkey() -> (Dnskey, Dnskey) {
        let ksk = base64::decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").unwrap().into();
        let zsk = base64::decode("AwEAAeVDC34GZILwsQJy97K2Fst4P3XYZrXLyrkausYzSqEjSUulgh+iLgHg0y7FIF890+sIjXsk7KLJUmCOWfYWPorNKEOKLk5Zx/4M6D3IHZE3O3m/Eahrc28qQzmTLxiMZAW65MvR2UO3LxVtYOPBEBiDgAQD47x2JLsJYtavCzNL5WiUk59OgvHmDqmcC7VXYBhK8V8Tic089XJgExGeplKWUt9yyc31ra1swJX51XsOaQz17+vyLVH8AZP26KvKFiZeoRbaq6vl+hc8HQnI2ug5rA2zoz3MsSQBvP1f/HvqsWxLqwXXKyDD1QM639U+XzVB8CYigyscRP22QCnwKIU=").unwrap().into();
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
            base64::decode("4G1EuAuPHTmpXAsNfGXQhFjogECbvGg0VxBCN8f47I0=")
                .unwrap()
                .into(),
        );
        assert_eq!(
            dnskey.digest(&owner, DigestAlg::Sha256).unwrap().as_ref(),
            expected.digest().as_ref()
        );
    }

    #[test]
    fn dnskey_digest_unsupported() {
        let (dnskey, _) = root_pubkey();
        let owner = Dname::root();
        assert_eq!(dnskey.digest(&owner, DigestAlg::Gost).is_err(), true);
    }

    fn rrsig_verify_dnskey(ksk: Dnskey, zsk: Dnskey, rrsig: Rrsig) {
        let mut records: Vec<_> = [&ksk, &zsk]
            .iter()
            .cloned()
            .map(|x| Record::new(rrsig.signer_name().clone(), Class::In, 0, x.clone()))
            .collect();
        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, records.as_mut_slice());
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
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::RsaSha256, 0, 172800, 1560211200.into(), 1558396800.into(), 20326, Dname::root(), base64::decode("otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZOdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gqxthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooEb7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4/yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQdg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ecdsap256_sha256() {
        let (ksk, zsk) = (
            Dnskey::new(257, 3, SecAlg::EcdsaP256Sha256, base64::decode("mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==").unwrap().into()),
            Dnskey::new(256, 3, SecAlg::EcdsaP256Sha256, base64::decode("oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==").unwrap().into()),
        );

        let owner = Dname::from_slice(b"\x0acloudflare\x03com\x00").unwrap();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::EcdsaP256Sha256, 2, 3600, 1560314494.into(), 1555130494.into(), 2371, owner.clone(), base64::decode("8jnAGhG7O52wmL065je10XQztRX1vK8P8KBSyo71Z6h5wAT9+GFxKBaEzcJBLvRmofYFDAhju21p1uTfLaYHrg==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_ed25519() {
        let (ksk, zsk) = (
            Dnskey::new(
                257,
                3,
                SecAlg::Ed25519,
                base64::decode("m1NELLVVQKl4fHVn/KKdeNO0PrYKGT3IGbYseT8XcKo=")
                    .unwrap()
                    .into(),
            ),
            Dnskey::new(
                256,
                3,
                SecAlg::Ed25519,
                base64::decode("2tstZAjgmlDTePn0NVXrAHBJmg84LoaFVxzLl1anjGI=")
                    .unwrap()
                    .into(),
            ),
        );

        let owner = Dname::from_slice(b"\x07ED25519\x02nl\x00").unwrap();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::Ed25519, 2, 3600, 1559174400.into(), 1557360000.into(), 45515, owner.clone(), base64::decode("hvPSS3E9Mx7lMARqtv6IGiw0NE0uz0mZewndJCHTkhwSYqlasUq7KfO5QdtgPXja7YkTaqzrYUbYk01J8ICsAA==").unwrap().into());
        rrsig_verify_dnskey(ksk, zsk, rrsig);
    }

    #[test]
    fn rrsig_verify_generic_type() {
        let (ksk, zsk) = root_pubkey();
        let rrsig = Rrsig::new(Rtype::Dnskey, SecAlg::RsaSha256, 0, 172800, 1560211200.into(), 1558396800.into(), 20326, Dname::root(), base64::decode("otBkINZAQu7AvPKjr/xWIEE7+SoZtKgF8bzVynX6bfJMJuPay8jPvNmwXkZOdSoYlvFp0bk9JWJKCh8y5uoNfMFkN6OSrDkr3t0E+c8c0Mnmwkk5CETH3Gqxthi0yyRX5T4VlHU06/Ks4zI+XAgl3FBpOc554ivdzez8YCjAIGx7XgzzooEb7heMSlLc7S7/HNjw51TPRs4RxrAVcezieKCzPPpeWBhjE6R3oiSwrl0SBD4/yplrDlr7UHs/Atcm3MSgemdyr2sOoOUkVQCVpcj3SQQezoD2tCM7861CXEQdg5fjeHDtz285xHt5HJpA5cOcctRo4ihybfow/+V7AQ==").unwrap().into());

        let mut records: Vec<Record<Dname, MasterRecordData<Dname>>> = [&ksk, &zsk]
            .iter()
            .cloned()
            .map(|x| {
                let data = MasterRecordData::from(x.clone());
                Record::new(rrsig.signer_name().clone(), Class::In, 0, data)
            })
            .collect();

        let signed_data = {
            let mut buf = Vec::new();
            rrsig.signed_data(&mut buf, records.as_mut_slice());
            Bytes::from(buf)
        };

        assert!(rrsig.verify_signed_data(&ksk, &signed_data).is_ok());
    }
}
