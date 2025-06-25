#![cfg(feature = "kmip")]
#![cfg_attr(docsrs, doc(cfg(feature = "kmip")))]

//============ Error Types ===================================================

//----------- GenerateError --------------------------------------------------

use core::fmt;

use std::{string::String, vec::Vec};

use bcder::decode::SliceSource;
use kmip::types::{
    common::{KeyMaterial, TransparentRSAPublicKey},
    response::ManagedObject,
};
use log::error;

pub use kmip::client::ConnectionSettings;

use crate::{
    base::iana::SecurityAlgorithm,
    crypto::{common::rsa_encode, kmip_pool::KmipConnPool},
    rdata::Dnskey,
};

/// An error in generating a key pair with OpenSSL.
#[derive(Clone, Debug)]
pub enum GenerateError {
    /// The requested algorithm is not supported.
    UnsupportedAlgorithm(SecurityAlgorithm),

    // The requested key size for the given algorithm is not supported.
    UnsupportedKeySize {
        algorithm: SecurityAlgorithm,
        min: u32,
        max: u32,
        requested: u32,
    },

    /// A problem occurred while communicating with the KMIP server.
    Kmip(String),
}

//--- Formatting

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "algorithm {algorithm} not supported")
            }
            Self::UnsupportedKeySize {
                algorithm,
                min,
                max,
                requested,
            } => {
                write!(f, "key size {requested} for algorithm {algorithm} must be in the range {min}..={max}")
            }
            Self::Kmip(err) => {
                write!(f, "a problem occurred while communicating with the KMIP server: {err}")
            }
        }
    }
}

//--- Error

impl std::error::Error for GenerateError {}

pub struct PublicKey {
    algorithm: SecurityAlgorithm,

    public_key_id: String,

    conn_pool: KmipConnPool,
}

impl PublicKey {
    pub fn new(
        public_key_id: String,
        algorithm: SecurityAlgorithm,
        conn_pool: KmipConnPool,
    ) -> Self {
        Self {
            public_key_id,
            algorithm,
            conn_pool,
        }
    }

    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    pub fn dnskey(
        &self,
        flags: u16,
    ) -> Result<Dnskey<Vec<u8>>, kmip::client::Error> {
        // https://datatracker.ietf.org/doc/html/rfc5702#section-2
        // Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource
        // Records for DNSSEC
        // 2.  DNSKEY Resource Records
        //   "The format of the DNSKEY RR can be found in [RFC4034].
        //   [RFC3110] describes the use of RSA/SHA-1 for DNSSEC
        //   signatures."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.4
        // Resource Records for the DNS Security Extensions
        // 2.  The DNSKEY Resource Record
        // 2.1.4.  The Public Key Field
        //   "The Public Key Field holds the public key material.  The
        //    format depends on the algorithm of the key being stored and
        //    is described in separate documents."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc3110#section-2
        // RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
        // 2. RSA Public KEY Resource Records
        //   "... The structure of the algorithm specific portion of the
        //    RDATA part of such RRs is as shown below.
        //
        //    Field             Size
        //    -----             ----
        //    exponent length   1 or 3 octets (see text)
        //    exponent          as specified by length field
        //    modulus           remaining space
        //
        // For interoperability, the exponent and modulus are each limited
        // to 4096 bits in length.  The public key exponent is a variable
        // length unsigned integer.  Its length in octets is represented
        // as one octet if it is in the range of 1 to 255 and by a zero
        // octet followed by a two octet unsigned length if it is longer
        // than 255 bytes.  The public key modulus field is a
        // multiprecision unsigned integer.  The length of the modulus can
        // be determined from the RDLENGTH and the preceding RDATA fields
        // including the exponent.  Leading zero octets are prohibited in
        // the exponent and modulus.

        let client = self.conn_pool.get().inspect_err(|err| error!("{err}")).map_err(|err| {
            kmip::client::Error::ServerError(format!(
                "Error while attempting to acquire KMIP connection from pool: {err}"
            ))
        })?;

        // Note: OpenDNSSEC queries the public key ID, _unless_ it was
        // configured not to store the public key in the HSM (by setting
        // CKA_TOKEN false) in which case there is no public key and so it
        // uses the private key object handle instead.
        let res = client
            .get_key(&self.public_key_id)
            .inspect_err(|err| error!("{err}"))?;

        let ManagedObject::PublicKey(public_key) = res.cryptographic_object
        else {
            return Err(kmip::client::Error::DeserializeError(format!("Fetched KMIP object was expected to be a PublicKey but was instead: {}", res.cryptographic_object)));
        };

        // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027125
        //   "“Raw” key format is intended to be applied to symmetric keys
        //    and not asymmetric keys"
        //
        // As we deal in assymetric keys (RSA, ECDSA), not symmetric keys,
        // we should not encounter public_key.key_block.key_format_type ==
        // KeyFormatType::Raw. However, Fortanix DSM returns
        // KeyFormatType::Raw when fetching key data for an ECDSA public key.

        // TODO: SAFETY
        // TODO: We don't know that these lengths are correct, consult cryptographic_length() too?
        let algorithm =
            match public_key.key_block.cryptographic_algorithm.unwrap() {
                kmip::types::common::CryptographicAlgorithm::RSA => {
                    SecurityAlgorithm::RSASHA256
                }
                kmip::types::common::CryptographicAlgorithm::ECDSA => {
                    SecurityAlgorithm::ECDSAP256SHA256
                }
                alg => return Err(kmip::client::Error::DeserializeError(format!("Fetched KMIP object has unsupported cryptographic algorithm type: {alg}"))),
            };

        let octets = match public_key.key_block.key_value.key_material {
            KeyMaterial::Bytes(bytes) => {
                // This is what we get with PyKMIP using RSASHA256 and
                // Fortanix using ECDSAP256SHA256. With Fortanix it
                // appears to be a DER encoded SubjectPublicKeyInfo
                // data structure of the form:
                // SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
                //  algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
                //    algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
                //    parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
                //  subjectPublicKey BIT_STRING @23+66: (520 bit)
                let source = SliceSource::new(&bytes);
                let public_key =
                    rpki::crypto::PublicKey::decode(source).unwrap();
                let bits = public_key.bits().to_vec();

                // For RSA, the bits are also DER encoded of the form:
                //   RSAPrivateKey SEQUENCE (2 elem)
                //     version Version INTEGER (1024 bit) 140670898145304244147145320460151523064481569650486421654946000437850…
                //     modulus INTEGER 65537
                //
                // or is it really:
                //   RSAPrivateKey SEQUENCE (2 elem)
                //     modulus INTEGER
                //     publicExponent INTEGER

                // if public_key.algorithm() == PublicKeyFormat::Rsa {
                //     let source = SliceSource::new(&bits);
                //     let mut modulus = vec![];
                //     let mut public_exponent = vec![];
                //     bcder::Mode::Der.decode(source, |cons| {
                //         cons.take_sequence(|cons| {
                //             modulus = bcder::string::BitString::take_from(cons)?.octet_slice().unwrap().to_vec();
                //             public_exponent = BitString::take_from(cons)?.octet_slice().unwrap().to_vec();
                //             Ok(())
                //         })
                //     }).unwrap();
                //     rsa_encode(&public_exponent, &modulus)
                // } else {
                bits
                // }
            }

            KeyMaterial::TransparentRSAPublicKey(
                TransparentRSAPublicKey {
                    modulus,
                    public_exponent,
                },
            ) => rsa_encode(&public_exponent, &modulus),

            mat => return Err(kmip::client::Error::DeserializeError(format!("Fetched KMIP object has unsupported key material type: {mat}"))),
        };

        Ok(Dnskey::new(flags, 3, algorithm, octets).unwrap())
    }
}

#[cfg(feature = "unstable-crypto-sign")]
pub mod sign {
    use std::boxed::Box;
    use std::string::{String, ToString};
    use std::time::SystemTime;
    use std::vec::Vec;

    use kmip::types::common::{
        CryptographicAlgorithm, CryptographicParameters,
        CryptographicUsageMask, Data, DigitalSignatureAlgorithm,
        HashingAlgorithm, UniqueIdentifier,
    };
    use kmip::types::request::{
        self, CommonTemplateAttribute, PrivateKeyTemplateAttribute,
        PublicKeyTemplateAttribute, RequestPayload,
    };
    use kmip::types::response::ResponsePayload;
    use log::{debug, error};

    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::common::{DigestBuilder, DigestType};
    use crate::crypto::kmip::{GenerateError, PublicKey};
    use crate::crypto::kmip_pool::KmipConnPool;
    use crate::crypto::sign::{
        GenerateParams, SignError, SignRaw, Signature,
    };
    use crate::rdata::Dnskey;

    #[derive(Clone, Debug)]
    pub struct KeyPair {
        /// The algorithm used by the key.
        algorithm: SecurityAlgorithm,

        private_key_id: String,

        public_key_id: String,

        conn_pool: KmipConnPool,

        flags: u16,
    }

    impl KeyPair {
        pub fn new(
            algorithm: SecurityAlgorithm,
            flags: u16,
            private_key_id: &str,
            public_key_id: &str,
            conn_pool: KmipConnPool,
        ) -> Self {
            Self {
                algorithm,
                private_key_id: private_key_id.to_string(),
                public_key_id: public_key_id.to_string(),
                conn_pool,
                flags,
            }
        }

        pub fn private_key_id(&self) -> &str {
            &self.private_key_id
        }

        pub fn public_key_id(&self) -> &str {
            &self.public_key_id
        }

        pub fn public_key(&self) -> PublicKey {
            PublicKey::new(
                self.public_key_id.clone(),
                self.algorithm,
                self.conn_pool.clone(),
            )
        }
    }

    impl SignRaw for KeyPair {
        fn algorithm(&self) -> SecurityAlgorithm {
            self.algorithm
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            // TODO: SAFETY
            PublicKey::new(
                self.public_key_id.clone(),
                self.algorithm,
                self.conn_pool.clone(),
            )
            .dnskey(self.flags)
            .unwrap()
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            // https://www.rfc-editor.org/rfc/rfc5702.html#section-3
            // 3.  RRSIG Resource Records
            //   "The value of the signature field in the RRSIG RR follows the
            //    RSASSA- PKCS1-v1_5 signature scheme and is calculated as
            //    follows."
            //    ...
            //    hash = SHA-XXX(data)
            //
            //    Here XXX is either 256 or 512, depending on the algorithm used, as
            //    specified in FIPS PUB 180-3; "data" is the wire format data of the
            //    resource record set that is signed, as specified in [RFC4034].
            //
            //    signature = ( 00 | 01 | FF* | 00 | prefix | hash ) ** e (mod n)"
            //    ...
            //
            // 3.1.  RSA/SHA-256 RRSIG Resource Records
            //   "RSA/SHA-256 signatures are stored in the DNS using RRSIG resource
            //    records (RRs) with algorithm number 8.
            //
            //    The prefix is the ASN.1 DER SHA-256 algorithm designator prefix, as
            //    specified in PKCS #1 v2.1 [RFC3447]:
            //
            //    hex 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20"
            //
            // We assume that the HSM signing operation implements this signing
            // operation according to these rules.

            let (crypto_alg, hashing_alg, digest_type) = match self.algorithm
            {
                SecurityAlgorithm::RSASHA256 => (
                    CryptographicAlgorithm::RSA,
                    HashingAlgorithm::SHA256,
                    DigestType::Sha256,
                ),
                SecurityAlgorithm::ECDSAP256SHA256 => (
                    CryptographicAlgorithm::ECDSA,
                    HashingAlgorithm::SHA256,
                    DigestType::Sha256,
                ),
                _ => return Err(SignError),
            };

            // TODO: For HSMs that don't support hashing do we have to do
            // hashing ourselves here after signing? Note: PyKMIP doesn't
            // support CryptographicParameters (and thus also not
            // HashingFunction) nor does it support the Hash operation.
            // Maybe via crypto::common::DigestBuilder?
            //
            // TODO: Where do we find out what the HSM supports? Trying an
            // operation then falling back each time it fails is inefficient.
            // We can presumably instead discover this on first use of the
            // HSM, ala how Krill does HSM probing. We would need to know the
            // result of such probing, which features are supported, here. We
            // only have access to the KMIP connection pool here, so I guess
            // that has to be able to tell us what we want to know.
            //
            // Note: OpenDNSSEC does its own hashing. Trying to do SHA256
            // hashing ourselves and then not passing a hashing algorithm to
            // the Sign operation below results (with Fortanix at least) in
            // error "Must specify HashingAlgorithm". OpenDNSSEC code comments
            // say this is done because "some HSMs don't really handle
            // CKM_SHA1_RSA_PKCS well".
            let mut ctx = DigestBuilder::new(digest_type);
            ctx.update(data);
            let digest = ctx.finish();
            let mut data = digest.as_ref();

            // OpenDNSSEC says that for RSA the prefix must be added to the
            // buffer manually first as "CKM_RSA_PKCS does the padding, but
            // cannot know the identifier prefix, so we need to add that
            // ourselves."
            let mut new_data;
            if matches!(self.algorithm, SecurityAlgorithm::RSASHA256) {
                new_data = vec![
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
                    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                    0x20,
                ];
                new_data.extend_from_slice(data);
                data = &new_data;
            }

            let request = RequestPayload::Sign(
                Some(UniqueIdentifier(self.private_key_id.clone())),
                Some(
                    CryptographicParameters::default()
                        // .with_padding_method(PaddingMethod::)
                        .with_hashing_algorithm(hashing_alg)
                        .with_cryptographic_algorithm(crypto_alg),
                ),
                Data(data.as_ref().to_vec()),
            );

            // Execute the request and capture the response
            let client = self
                .conn_pool
                .get()
                .inspect_err(|err| {
                    error!(
                        "Error while obtaining KMIP pool connection: {err}"
                    )
                })
                .map_err(|_| SignError)?;

            let res = client
                .do_request(request)
                .inspect_err(|err| {
                    error!("Error while sending KMIP request: {err}")
                })
                .map_err(|_| SignError)?;

            let ResponsePayload::Sign(signed) = res else {
                unreachable!();
            };

            match self.algorithm {
                SecurityAlgorithm::RSASHA256 => {
                    // Ok(Signature::RsaSha256(Box::<[u8; 64]>::new(
                    //     signed
                    //         .signature_data
                    //         .into_boxed_slice()
                    //         .inspect_err(|err| eprintln!("Signing7: Error"))
                    //         .map_err(|_| SignError)?,
                    // )))
                    Ok(Signature::RsaSha256(
                        signed.signature_data.into_boxed_slice(),
                    ))
                }
                SecurityAlgorithm::ECDSAP256SHA256 => {
                    let signature = openssl::ecdsa::EcdsaSig::from_der(
                        &signed.signature_data,
                    )
                    .unwrap();
                    let mut r = signature.r().to_vec_padded(32).unwrap();
                    let mut s = signature.s().to_vec_padded(32).unwrap();
                    r.append(&mut s);

                    Ok(Signature::EcdsaP256Sha256(Box::<[u8; 64]>::new(
                        r.try_into().map_err(|_| SignError)?,
                    )))
                }
                SecurityAlgorithm::ECDSAP384SHA384 => {
                    Ok(Signature::EcdsaP384Sha384(Box::<[u8; 96]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .map_err(|_| SignError)?,
                    )))
                }
                SecurityAlgorithm::ED25519 => {
                    Ok(Signature::Ed25519(Box::<[u8; 64]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .map_err(|_| SignError)?,
                    )))
                }
                SecurityAlgorithm::ED448 => {
                    Ok(Signature::Ed448(Box::<[u8; 114]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .map_err(|_| SignError)?,
                    )))
                }
                _ => Err(SignError)?,
            }
        }
    }

    //----------- generate() -------------------------------------------------

    /// Generate a new secret key for the given algorithm.
    pub fn generate(
        name: String,
        params: GenerateParams, // TODO: Is this enough? Or do we need to take SecurityAlgorithm as input instead of GenerateParams to ensure we don't lose distinctions like 5 vs 7 which are both RSASHA1?
        flags: u16,
        conn_pool: KmipConnPool,
    ) -> Result<KeyPair, GenerateError> {
        let algorithm = params.algorithm();

        let client = conn_pool.get().map_err(|_| SignError).unwrap();

        // TODO: Determine this on first use of the HSM?
        // PyKMIP doesn't support ActivationDate.
        // Fortanix DSM does support it and creates the key in an activated state but still returns a (harmless?) error:
        //   Server error: Operation CreateKeyPair failed: Input field `state` is not coherent with provided activation/deactivation dates
        let activate_on_create = false;

        let use_cryptographic_params = false;

        let mut common_attrs = vec![];
        let priv_key_attrs = vec![
            // Krill supplies a name at creation time. Do we need to?
            // Note: Fortanix DSM requires a name for at least the private key.
            request::Attribute::Name(format!("{name}_priv")),
            request::Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Sign,
            ),
        ];
        let pub_key_attrs = vec![
            // Krill supplies a name at creation time. Do we need to?
            // Note: Fortanix DSM requires a name for at least the private key.
            request::Attribute::Name(format!("{name}_pub")),
            // Krill does verification, do we need to? ODS doesn't.
            // Note: PyKMIP requires a Cryptographic Usage Mask for the public
            // key.
            request::Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Verify,
            ),
        ];

        // PyKMIP doesn't support CryptographicParameters so we cannot supply
        // HashingAlgorithm. It also doesn't support the Hash operation. How
        // do we specify SHA256 hashing? Do we have to do it ourselves
        // post-signing? Can we just specify the hashing to do when invoking
        // the Sign operation?
        // Fortanix DSM also doesn't support Cryptographic Parameters:
        //   Server error: Operation CreateKeyPair failed: Don't have handling for attribute Cryptographic Parameters

        // PyKMIP doesn't support Attribute::ActivationDate. For HSMs that
        // don't support it we have to do a separate Activate operation after
        // creating the key pair.
        // Fortanix DSM does support ActivationDate.

        match params {
            GenerateParams::RsaSha256 { bits } => {
                // RFC 8624 3.1 DNSSEC Signing: MUST
                // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776503
                //   "For RSA, Cryptographic Length corresponds to the bit length of the Modulus"

                // https://www.rfc-editor.org/rfc/rfc5702.html#section-2.1
                // 2.1.  RSA/SHA-256 DNSKEY Resource Records
                //   "For interoperability, as in [RFC3110], the key size of
                //    RSA/SHA-256 keys MUST NOT be less than 512 bits and MUST
                //    NOT be more than 4096 bits."
                if !(512..=4096).contains(&bits) {
                    return Err(GenerateError::UnsupportedKeySize {
                        algorithm: SecurityAlgorithm::RSASHA256,
                        min: 512,
                        max: 4096,
                        requested: bits,
                    });
                }

                if use_cryptographic_params {
                    common_attrs.push(
                        request::Attribute::CryptographicParameters(
                            CryptographicParameters::default()
                            .with_digital_signature_algorithm(DigitalSignatureAlgorithm::SHA256WithRSAEncryption_PKCS1_v1_5)
                        )
                    )
                } else {
                    common_attrs.push(
                        request::Attribute::CryptographicAlgorithm(
                            CryptographicAlgorithm::RSA,
                        ),
                    );
                    common_attrs.push(
                        request::Attribute::CryptographicLength(
                            bits.try_into().unwrap(),
                        ),
                    );
                }
            }
            GenerateParams::RsaSha512 { .. } => {
                return Err(GenerateError::UnsupportedAlgorithm(
                    SecurityAlgorithm::RSASHA512,
                ));
            }
            GenerateParams::EcdsaP256Sha256 => {
                // PyKMIP doesn't support ECDSA:
                //   "Operation CreateKeyPair failed: The cryptographic
                //   algorithm (CryptographicAlgorithm.ECDSA) is not a
                //   supported asymmetric key algorithm."

                if use_cryptographic_params {
                    common_attrs.push(
                        request::Attribute::CryptographicParameters(
                            CryptographicParameters::default()
                                .with_digital_signature_algorithm(
                                DigitalSignatureAlgorithm::ECDSAWithSHA256,
                            ),
                        ),
                    )
                } else {
                    // RFC 8624 3.1 DNSSEC Signing: MUST
                    // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776503
                    //   "For ECDSA, ECDH, and ECMQV algorithms, Cryptographic
                    //    Length corresponds to the bit length of parameter
                    //    Q."
                    common_attrs.push(
                        request::Attribute::CryptographicAlgorithm(
                            CryptographicAlgorithm::ECDSA,
                        ),
                    );
                    // ODS doesn't tell PKCS#11 a Q length. I have no idea
                    // what value we should put here, but as Q length is
                    // optional let's try not passing it.
                    // Note: PyKMIP requires a length: use 256 from P-256?
                    // Note: Fortanix also requires a length and gives error
                    // "missing required field `elliptic_curve` in request
                    // body" if cryptographic length is not specified, and a
                    // value of 256 works fine while a value of 255 causes
                    // error "Unsupported length for ECC key". When using 256
                    // the Fortanix UI shows the key as type EC with curve
                    // NistP256 so that seems good.
                    common_attrs
                        .push(request::Attribute::CryptographicLength(256));
                }
            }
            GenerateParams::EcdsaP384Sha384 => {
                // RFC 8624 3.1 DNSSEC Signing: MAY
                todo!()
            }
            GenerateParams::Ed25519 => {
                // RFC 8624 3.1 DNSSEC Signing: RECOMMENDED
                todo!()
            }
            GenerateParams::Ed448 => {
                // RFC 8624 3.1 DNSSEC Signing: MAY
                todo!()
            }
        };

        if activate_on_create {
            // https://docs.oasis-open.org/kmip/testcases/v1.1/kmip-testcases-v1.1.html
            // shows an example including an Activation Date value of 2 noted
            // as meaning Thu Jan 01 01:00:02 CET 1970. i.e. the activation
            // date should be a UNIX epoch timestamp.
            let time_now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            common_attrs.push(request::Attribute::ActivationDate(time_now));
        }

        let request = RequestPayload::CreateKeyPair(
            Some(CommonTemplateAttribute::new(common_attrs)),
            Some(PrivateKeyTemplateAttribute::new(priv_key_attrs)),
            Some(PublicKeyTemplateAttribute::new(pub_key_attrs)),
        );

        // Execute the request and capture the response
        let response = client.do_request(request).map_err(|err| {
            error!("KMIP request failed: {err}");
            debug!(
                "KMIP last request: {}",
                client.last_req_diag_str().unwrap_or_default()
            );
            debug!(
                "KMIP last response: {}",
                client.last_res_diag_str().unwrap_or_default()
            );
            GenerateError::Kmip(err.to_string())
        })?;

        // Process the successful response
        let ResponsePayload::CreateKeyPair(payload) = response else {
            error!("KMIP request failed: Wrong response type received!");
            return Err(GenerateError::Kmip("Unable to parse KMIP response: payload should be CreateKeyPair".to_string()));
        };

        Ok(KeyPair {
            algorithm,
            private_key_id: payload.private_key_unique_identifier.to_string(),
            public_key_id: payload.public_key_unique_identifier.to_string(),
            conn_pool,
            flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::string::ToString;
    use std::time::SystemTime;
    use std::vec::Vec;

    use kmip::client::ConnectionSettings;

    use crate::crypto::kmip::sign::generate;
    use crate::crypto::kmip_pool::ConnectionManager;
    use crate::crypto::sign::SignRaw;
    use crate::logging::init_logging;

    #[test]
    #[ignore = "Requires running PyKMIP"]
    fn pykmip_connect() {
        init_logging();
        let mut cert_bytes = Vec::new();
        let file = File::open(
            "/home/ximon/docker_data/pykmip/pykmip-data/selfsigned.crt",
        )
        .unwrap();
        let mut reader = BufReader::new(file);
        reader.read_to_end(&mut cert_bytes).unwrap();

        let mut key_bytes = Vec::new();
        let file = File::open(
            "/home/ximon/docker_data/pykmip/pykmip-data/selfsigned.key",
        )
        .unwrap();
        let mut reader = BufReader::new(file);
        reader.read_to_end(&mut key_bytes).unwrap();

        let mut conn_settings = ConnectionSettings::default();
        conn_settings.host = "localhost".to_string();
        conn_settings.port = 5696;
        conn_settings.insecure = true;
        conn_settings.client_cert =
            Some(kmip::client::ClientCertificate::SeparatePem {
                cert_bytes,
                key_bytes: Some(key_bytes),
            });

        eprintln!("Creating pool...");
        let pool = ConnectionManager::create_connection_pool(
            conn_settings.into(),
            16384,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();

        eprintln!("Connecting...");
        let client = pool.get().unwrap();

        eprintln!("Connected");
        let res = client.query();
        dbg!(&res);
        res.unwrap();

        let generated_key_name = format!(
            "{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let res = generate(
            generated_key_name,
            //crate::crypto::sign::GenerateParams::RsaSha256 { bits: 2048 },
            crate::crypto::sign::GenerateParams::EcdsaP256Sha256,
            256,
            pool,
        );
        dbg!(&res);
        let _key = res.unwrap();

        // let dnskey = key.dnskey();
        // eprintln!("DNSKEY: {}", dnskey);
    }

    #[test]
    #[ignore = "Requires Fortanix credentials"]
    fn fortanix_dsm_test() {
        // Note: keyls fails against Fortanix DSM for some reason with error:
        // Error: Server error: Operation Locate failed: expected
        // AttributeValue, got ObjectType, Diagnostics:
        // req: 78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce8:79[08[0At57e4:]]]],
        // resp: 7B[7A[69[6Ai6Bi]92d0Di]0F[5Ce8:7Fe1:7Ee100:7Dt]]

        init_logging();

        let mut conn_settings = ConnectionSettings::default();
        // conn_settings.host = "eu.smartkey.io".to_string();
        // conn_settings.port = 5696;
        // conn_settings.username = Some(env!("FORTANIX_USER").to_string());
        // conn_settings.password = Some(env!("FORTANIX_PASS").to_string());

        conn_settings.host = "127.0.0.1".to_string(); //"eu.smartkey.io".to_string();
        conn_settings.port = 5696;
        conn_settings.insecure = true; // When connecting to kmip2pkcs11
        conn_settings.connect_timeout = Some(Duration::from_secs(3));
        conn_settings.read_timeout = Some(Duration::from_secs(30));
        conn_settings.write_timeout = Some(Duration::from_secs(3));

        eprintln!("Creating pool...");
        let pool = ConnectionManager::create_connection_pool(
            conn_settings.into(),
            16384,
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
        .unwrap();

        eprintln!("Connecting...");
        let client = pool.get().unwrap();

        eprintln!("Connected");
        // let res = client.query();
        // dbg!(&res);
        // res.unwrap();

        let generated_key_name = format!(
            "{}",
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let res = generate(
            generated_key_name,
            crate::crypto::sign::GenerateParams::RsaSha256 { bits: 1024 },
            // crate::crypto::sign::GenerateParams::EcdsaP256Sha256,
            256,
            pool,
        );
        let key = res.unwrap();
        eprintln!("Generated public key with id: {}", key.public_key_id());
        eprintln!("Generated private key with id: {}", key.private_key_id());

        // sleep(Duration::from_secs(5));

        let dnskey = key.dnskey();
        eprintln!("DNSKEY: {}", dnskey);

        // // Fortanix: Activating the public key also activates the private key.
        // // Attempting to then activate the private key fails as it is already
        // // active. Yet signing fails with "Object is not yet active"...
        client.activate_key(key.public_key_id()).unwrap();
        // // client.activate_key(key.private_key_id()).unwrap();

        // // This works round the not yet active yet error.
        // sleep(Duration::from_secs(5));

        // let request = RequestPayload::Sign(
        //     Some(UniqueIdentifier(key.private_key_id().to_string())),
        //     // While the KMIP 1.2 spec says crypto parameters are optional and
        //     // if not specified those of the key will be used, Fortanix
        //     // complains about "No cryptographic parameters specified" if this
        //     // is None, and "Must specicify HashingAlgorithm" if that is not
        //     // specified.
        //     Some(
        //         CryptographicParameters::default()
        //             // .with_padding_method(PaddingMethod::)
        //             .with_hashing_algorithm(HashingAlgorithm::SHA256)
        //             .with_cryptographic_algorithm(
        //                 CryptographicAlgorithm::RSA,
        //                 //CryptographicAlgorithm::ECDSA,
        //             ),
        //     ),
        //     Data("Message for ECDSA signing".as_bytes().to_vec()),
        // );

        // // Execute the request and capture the response
        // let res = client.do_request(request).unwrap();

        // dbg!(&res);

        // let ResponsePayload::Sign(signed) = res else {
        //     unreachable!();
        // };

        // // let signature =
        // //     openssl::ecdsa::EcdsaSig::from_der(&signed.signature_data)
        // //         .unwrap();

        // // dbg!(signature.r().to_vec_padded(32));
        // // dbg!(signature.s().to_vec_padded(32));

        // // dbg!(response);
    }
}
