#![cfg(feature = "kmip")]
#![cfg_attr(docsrs, doc(cfg(feature = "kmip")))]

//============ Error Types ===================================================

//----------- GenerateError --------------------------------------------------

use core::fmt;

/// An error in generating a key pair with OpenSSL.
#[derive(Clone, Debug)]
pub enum GenerateError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Formatting

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for GenerateError {}

#[cfg(feature = "unstable-crypto-sign")]
pub mod sign {
    use std::boxed::Box;
    use std::string::{String, ToString};
    use std::time::SystemTime;
    use std::vec::Vec;

    use kmip::types::common::{
        CryptographicAlgorithm, CryptographicParameters,
        CryptographicUsageMask, DigitalSignatureAlgorithm, HashingAlgorithm,
        KeyMaterial, ObjectType,
    };
    use kmip::types::request::{
        self, CommonTemplateAttribute, PrivateKeyTemplateAttribute,
        PublicKeyTemplateAttribute, RequestPayload,
    };
    use kmip::types::response::{ManagedObject, ResponsePayload};
    use log::error;

    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::kmip_pool::KmipConnPool;
    use crate::crypto::sign::{
        GenerateError, GenerateParams, SignError, SignRaw, Signature,
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

    impl SignRaw for KeyPair {
        fn algorithm(&self) -> SecurityAlgorithm {
            self.algorithm
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            let client = self.conn_pool.get().unwrap();

            let res = client.get_key(&self.public_key_id).unwrap();

            assert_eq!(res.object_type, ObjectType::PublicKey);

            let ManagedObject::PublicKey(public_key) =
                res.cryptographic_object
            else {
                todo!();
            };

            let octets = match public_key.key_block.key_value.key_material {
                KeyMaterial::Bytes(bytes) => {
                    // Hmmm, this is what we get with PyKMIP, rather than
                    // TransparentRSAPublicKey. The Dnskey we create using
                    // these octets doesn't seem to render the RDATA correctly
                    // so do we need to do something with these bytes?
                    bytes
                }
                KeyMaterial::TransparentRSAPublicKey(key) => {
                    rpki::crypto::keys::PublicKey::rsa_from_components(
                        &key.modulus,
                        &key.public_exponent,
                    )
                    .unwrap()
                    .bits()
                    .to_vec()
                }
                _ => todo!(),
            };

            Dnskey::new(self.flags, 3, self.algorithm, octets).unwrap()
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            let client = self.conn_pool.get().map_err(|_| SignError)?;

            let signed = client.sign(&self.private_key_id, data).unwrap();

            // TODO: For HSMs that don't support hashing do we have to do
            // hashing ourselves here after signing? Note: PyKMIP doesn't
            // support CryptographicParameters (and thus also not
            // HashingFunction) nor does it support the Hash operation.
            // Maybe via crypto::common::DigestBuilder?

            // TODO: Where do we find out what the HSM supports? Trying an
            // operation then falling back each time it fails is inefficient.
            // We can presumably instead discover this on first use of the
            // HSM, ala how Krill does HSM probing. We would need to know the
            // result of such probing, which features are supported, here. We
            // only have access to the KMIP connection pool here, so I guess
            // that has to be able to tell us what we want to know.
            match self.algorithm {
                SecurityAlgorithm::RSASHA256 => {
                    Ok(Signature::RsaSha256(Box::<[u8; 64]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .map_err(|_| SignError)?,
                    )))
                }
                SecurityAlgorithm::ECDSAP256SHA256 => {
                    Ok(Signature::EcdsaP256Sha256(Box::<[u8; 64]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .map_err(|_| SignError)?,
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
        params: GenerateParams,
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

                // RFC 5702 2.1
                if bits < 512 || bits > 4096 {
                    return Err(GenerateError::UnsupportedAlgorithm);
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
            Some(CommonTemplateAttribute::unnamed(common_attrs)),
            Some(PrivateKeyTemplateAttribute::unnamed(priv_key_attrs)),
            Some(PublicKeyTemplateAttribute::unnamed(pub_key_attrs)),
        );

        // Execute the request and capture the response
        let response = client.do_request(request).map_err(|err| {
            error!("KMIP request failed: {err}");
            error!(
                "KMIP last request: {}",
                client.last_req_diag_str().unwrap_or_default()
            );
            error!(
                "KMIP last response: {}",
                client.last_res_diag_str().unwrap_or_default()
            );
            GenerateError::Implementation
        })?;

        // Process the successful response
        let ResponsePayload::CreateKeyPair(payload) = response else {
            error!("KMIP request failed: Wrong response type received!");
            return Err(GenerateError::Implementation);
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
    use std::vec::Vec;

    use kmip::client::ConnectionSettings;

    use crate::crypto::kmip::sign::generate;
    use crate::crypto::kmip_pool::ConnectionManager;
    use crate::crypto::sign::SignRaw;
    use crate::logging::init_logging;
    use std::time::SystemTime;

    #[test]
    fn connect() {
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
        let key = res.unwrap();

        // let dnskey = key.dnskey();
        // eprintln!("DNSKEY: {}", dnskey);
    }

    #[test]
    fn fortanix_dsm_test() {
        // Note: keyls fails against Fortanix DSM for some reason with error:
        // Error: Server error: Operation Locate failed: expected
        // AttributeValue, got ObjectType, Diagnostics:
        // req: 78[77[69[6Ai6Bi]0C[23[24e1:25[99tA1t]]]0Di]0F[5Ce8:79[08[0At57e4:]]]],
        // resp: 7B[7A[69[6Ai6Bi]92d0Di]0F[5Ce8:7Fe1:7Ee100:7Dt]]

        init_logging();

        let mut conn_settings = ConnectionSettings::default();
        conn_settings.host = "eu.smartkey.io".to_string();
        conn_settings.port = 5696;
        conn_settings.username =
            Some("2c79ae57-18a9-431a-baa1-0ef98cf88f45".to_string());
        conn_settings.password = Some("kbJcsgfVaiVOnldmyIXitwWnuIeEVHw9Jm0EoY3NA_qj-glVucT1sbRcSWGf3st7B8xWN-aKC4rmJ0gNmfQCgg".to_string());

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
        let key = res.unwrap();

        let dnskey = key.dnskey();
        eprintln!("DNSKEY: {}", dnskey);
    }
}
