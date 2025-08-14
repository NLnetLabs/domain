#![cfg(all(feature = "kmip", any(feature = "ring", feature = "openssl")))]
#![cfg_attr(docsrs, doc(cfg(feature = "kmip")))]

use core::{fmt, str::FromStr};

use std::{
    string::{String, ToString},
    vec::Vec,
};

use bcder::{decode::SliceSource, BitString, ConstOid, Oid};
use kmip::{
    client::pool::SyncConnPool,
    types::{
        common::{KeyFormatType, KeyMaterial, TransparentRSAPublicKey},
        response::ManagedObject,
    },
};
use tracing::{debug, error};
use url::Url;

use crate::{
    base::iana::SecurityAlgorithm,
    crypto::{common::rsa_encode, sign::SignError},
    rdata::Dnskey,
    utils::base16,
};

pub use kmip::client::{ClientCertificate, ConnectionSettings};

//============ Error Types ===================================================

//----------- GenerateError --------------------------------------------------

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

/// [RFC 4055](https://tools.ietf.org/html/rfc4055) `rsaEncryption`
///
/// Identifies an RSA public key with no limitation to either RSASSA-PSS or
/// RSAES-OEAP.
pub const RSA_ENCRYPTION_OID: ConstOid =
    Oid(&[42, 134, 72, 134, 247, 13, 1, 1, 1]);

/// [RFC 5480](https://tools.ietf.org/html/rfc5480) `ecPublicKey`.
///
/// Identifies public keys for elliptic curve cryptography.
pub const EC_PUBLIC_KEY_OID: ConstOid = Oid(&[42, 134, 72, 206, 61, 2, 1]);

/// [RFC 5480](https://tools.ietf.org/html/rfc5480) `secp256r1`.
///
/// Identifies the P-256 curve for elliptic curve cryptography.
pub const SECP256R1_OID: ConstOid = Oid(&[42, 134, 72, 206, 61, 3, 1, 7]);

/// A URL that represents a key stored in a KMIP compatible HSM.
///
/// The URL structure is:
///
///   kmip://<server_id>/keys/<key_id>?algorithm=<algorithm>&flags=<flags>
///
/// The algorithm and flags must be stored in the URL because they are DNSSEC
/// specific and not properties of the key itself and thus not known to or
/// stored by the HSM.
///
/// While algorithm may seem to be something known to and stored by the HSM,
/// DNSSEC complicates that by aliasing multiple algorithm numbers to the
/// same cryptographic algorithm, and we need to know when using the key which
/// _DNSSEC_ algorithm number to use.
///
/// The server_id could be the actual address of the target, but does not have
/// to be. There are multiple for this:
///
///   - In a highly available clustered deployment across multiple subnets
///     it could be that the clustered HSM is available to the clustered
///     application via different names/IP addresses in different subnets of
///     the deployment. Using an abstract server_id which is mapped via local
///     configuration in the subnet to the correct hostname/FQDN/IP address
///     for that subnet allows the correct target address to be determined at
///     the point of access.
///   - Using the actual hostname/FQDN/IP address may make it confusing for
///     an operator trying to understand where the key is actually stored.
///     This can happen for example if the product name for the HSM is say
///     Fortanix DSM, while the domain name used to access the HSM might be
///     eu.smartkey.io, which having no mention of the name Fortanix in the
///     FQDN is not immediately obvious that it has any relationship with
///     Fortanix.
///   - If the same HSM is used for different use cases via use of HSM
///     partitions, referring to the HSM by its address may not make it clear
///     which partition is being used, so using a more meaningful name like
///     'testing' or such could make it clearer where the key is actually
///     being stored.
///   - Storing the username and password in the key URL will cause many
///     copies of those credentials to be stored, one per key, which is harder
///     to secure than if they are only in a single location and looked up on
///     actual access.
///   - Storing the username and password in the key URL would cause the URL
///     to become unusable if the credentials were rotated even though the
///     location at which the key is stored has not changed.
///   - Even if the FQDN, port number, username and password are all correct,
///     there may need to be more settings specified in order to connect to
///     the HSM some of which would not fit easily into a URL such as TLS
///     client certficate details and whether or not to require the server
///     TLS certificate to be valid (which can be inconvenient in test setups
///     using self-signed certificates).
///
/// Thus an abstract server_id is stored in the key URL and it is the
/// responsibility of the user of the key URL to map the server id to the full
/// set of settings required to successfully connect to the HSM to make use of
/// the key.
pub struct KeyUrl {
    url: Url,
    server_id: String,
    key_id: String,
    algorithm: SecurityAlgorithm,
    flags: u16,
}

impl KeyUrl {
    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn into_url(self) -> Url {
        self.url
    }
}

impl TryFrom<Url> for KeyUrl {
    type Error = SignError;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        let server_id = url
            .host_str()
            .ok_or(format!("Key URL lacks hostname component: {url}"))?
            .to_string();

        let url_path = url.path().to_string();
        let key_id = url_path
            .strip_prefix("/keys/")
            .ok_or(format!("Key URL lacks /keys/ path component: {url}"))?;

        let key_id = key_id.to_string();
        let mut flags = None;
        let mut algorithm = None;
        for (k, v) in url.query_pairs() {
            match &*k {
                "flags" => {
                    flags = Some(v.parse::<u16>().map_err(|err| {
                        format!("Key URL flags value is invalid: {err}")
                    })?)
                }
                "algorithm" => {
                    algorithm = Some(
                        SecurityAlgorithm::from_str(&v).map_err(|err| {
                            format!(
                                "Key URL algorithm value is invalid: {err}"
                            )
                        })?,
                    )
                }
                unknown => Err(format!(
                    "Key URL contains unknown query parameter: {unknown}"
                ))?,
            }
        }
        let algorithm = algorithm.ok_or(format!(
            "Key URL lacks algorithm query parameter: {url}"
        ))?;
        let flags = flags
            .ok_or(format!("Key URL lacks flags query parameter: {url}"))?;

        Ok(Self {
            url,
            server_id,
            key_id,
            algorithm,
            flags,
        })
    }
}

pub struct PublicKey {
    algorithm: SecurityAlgorithm,

    public_key: Vec<u8>,
}

impl PublicKey {
    pub fn from_metadata(
        public_key_id: &str,
        algorithm: SecurityAlgorithm,
        conn_pool: SyncConnPool,
    ) -> Result<Self, kmip::client::Error> {
        let public_key = Self::fetch_public_key(public_key_id, &conn_pool)?;

        Ok(Self {
            algorithm,
            public_key,
        })
    }

    pub fn from_url(
        public_key_url: KeyUrl,
        conn_pool: SyncConnPool,
    ) -> Result<Self, kmip::client::Error> {
        Self::from_metadata(
            public_key_url.key_id(),
            public_key_url.algorithm(),
            conn_pool,
        )
    }

    pub fn algorithm(&self) -> SecurityAlgorithm {
        self.algorithm
    }

    pub fn dnskey(&self, flags: u16) -> Dnskey<Vec<u8>> {
        Dnskey::new(flags, 3, self.algorithm, self.public_key.clone())
            .unwrap()
    }
}

impl PublicKey {
    fn fetch_public_key(
        public_key_id: &str,
        conn_pool: &SyncConnPool,
    ) -> Result<Vec<u8>, kmip::client::Error> {
        // https://datatracker.ietf.org/doc/html/rfc5702#section-2
        // Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource
        // Records for DNSSEC
        //
        // 2.  DNSKEY Resource Records
        //   "The format of the DNSKEY RR can be found in [RFC4034]. [RFC3110]
        //   describes the use of RSA/SHA-1 for DNSSEC signatures."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.4
        // Resource Records for the DNS Security Extensions
        // 2.  The DNSKEY Resource Record
        // 2.1.4.  The Public Key Field
        //   "The Public Key Field holds the public key material.  The
        //    format depends on the algorithm of the key being stored and is
        //    described in separate documents."
        //                          |
        //                          |
        //                          v
        // https://datatracker.ietf.org/doc/html/rfc3110#section-2
        // RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
        // 2. RSA Public KEY Resource Records
        //   "... The structure of the algorithm specific portion of the RDATA
        //    part of such RRs is as shown below.
        //
        //    Field             Size
        //    -----             ----
        //    exponent length   1 or 3 octets (see text)
        //    exponent          as specified by length field
        //    modulus           remaining space
        //
        // For interoperability, the exponent and modulus are each limited to
        // 4096 bits in length.  The public key exponent is a variable length
        // unsigned integer.  Its length in octets is represented as one octet
        // if it is in the range of 1 to 255 and by a zero octet followed by
        // a two octet unsigned length if it is longer than 255 bytes.  The
        // public key modulus field is a multiprecision unsigned integer.  The
        // length of the modulus can be determined from the RDLENGTH and the
        // preceding RDATA fields including the exponent.  Leading zero octets
        // are prohibited in the exponent and modulus.

        let client = conn_pool.get().inspect_err(|err| error!("{err}")).map_err(|err| {
            kmip::client::Error::ServerError(format!(
                "Error while attempting to acquire KMIP connection from pool: {err}"
            ))
        })?;

        // Note: OpenDNSSEC queries the public key ID, _unless_ it was
        // configured not the public key in the HSM (by setting CKA_TOKEN
        // false) in which case there is no public key and so it uses the
        // private key object handle instead.
        let res = client
            .get_key(public_key_id)
            .inspect_err(|err| error!("{err}"))?;
        let ManagedObject::PublicKey(public_key) = res.cryptographic_object
        else {
            return Err(kmip::client::Error::DeserializeError(format!("Fetched KMIP object was expected to be a PublicKey but was instead: {}", res.cryptographic_object)));
        };

        // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027125
        //   "“Raw” key format is intended to be applied to symmetric keys
        //    and not asymmetric keys"
        //
        // As we deal in asymmetric keys (RSA, ECDSA), not symmetric keys,
        // we should not encounter public_key.key_block.key_format_type
        // == KeyFormatType::Raw. However, Fortanix DSM returns
        // KeyFormatType::Raw when fetching key data for an ECDSA public key.

        // TODO: SAFETY
        // TODO: We don't know that these lengths are correct, consult
        // cryptographic_length() too?
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
                debug!("Cryptographic Algorithm: {:?}", public_key.key_block.cryptographic_algorithm);
                debug!("Key Format Type: {:?}", public_key.key_block.key_format_type);
                debug!("Key bytes as hex: {}", base16::encode_display(&bytes));

                // Handle key format type PKCS1
                match (algorithm, public_key.key_block.key_format_type) {
                    (SecurityAlgorithm::RSASHA256, KeyFormatType::PKCS1) => {
                        // PyKMIP outputs PKCS#1 ASN.1 DER encoded RSA public
                        // key data like so:
                        //   RSAPublicKey::=SEQUENCE{
                        //     modulus INTEGER, -- n
                        //     publicExponent INTEGER -- e }
                        let source = SliceSource::new(&bytes);
                        let mut modulus = None;
                        let mut public_exponent = None;
                        bcder::Mode::Der
                            .decode(source, |cons| {
                                cons.take_sequence(|cons| {
                                    modulus = Some(bcder::Unsigned::take_from(cons)?);
                                    public_exponent = Some(bcder::Unsigned::take_from(cons)?);
                                    Ok(())
                                })
                            }).map_err(|err| kmip::client::Error::DeserializeError(format!("Unable to parse PKCS#1 RSASHA256 SubjectPublicKeyInfo: {err}")))?;

                        let Some(modulus) = modulus else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse PKCS#1 RSASHA256 SubjectPublicKeyInfo: missing modulus".into()));
                        };

                        let Some(public_exponent) = public_exponent else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse PKCS#1 RSASHA256 SubjectPublicKeyInfo: missing public exponent".into()));
                        };

                        let n = modulus.as_slice();
                        let e = public_exponent.as_slice();
                        crate::crypto::common::rsa_encode(e, n)
                    },

                    (SecurityAlgorithm::RSASHA256, KeyFormatType::Raw) => {
                        // For an RSA key Fortanix DSM supplies: (from https://asn1js.eu/)
                        //   SubjectPublicKeyInfo SEQUENCE (2 elem)
                        //     algorithm AlgorithmIdentifier SEQUENCE (2 elem)
                        //       algorithm OBJECT IDENTIFIER 1.2.840.113549.1.1.1 rsaEncryption (PKCS #1)
                        //       parameter ANY NULL
                        //     subjectPublicKey BIT STRING (2160 bit) 001100001000001000000001000010100000001010000010000000010000000100000…
                        //       SEQUENCE (2 elem)
                        //         INTEGER (2048 bit) 229677698057230630160769379936346719377896297586216888467726484346678…
                        //         INTEGER 65537
                        let source = SliceSource::new(&bytes);
                        let mut modulus = None;
                        let mut public_exponent = None;
                        bcder::Mode::Der
                            .decode(source, |cons| {
                                cons.take_sequence(|cons| {
                                    cons.take_sequence(|cons| {
                                        let algorithm = Oid::take_from(cons)?;
                                        if algorithm != RSA_ENCRYPTION_OID {
                                            return Err(cons.content_err("Only SubjectPublicKeyInfo with algorithm rsaEncryption is supported"));
                                        }
                                        // Ignore the parameters.
                                        Ok(())
                                    })?;
                                    cons.take_sequence(|cons| {
                                        modulus = Some(bcder::Unsigned::take_from(cons)?);
                                        public_exponent = Some(bcder::Unsigned::take_from(cons)?);
                                        Ok(())
                                    })
                                })
                            }).map_err(|err| kmip::client::Error::DeserializeError(format!("Unable to parse raw RSASHA256 SubjectPublicKeyInfo: {err}")))?;

                        let Some(modulus) = modulus else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse raw RSASHA256 SubjectPublicKeyInfo: missing modulus".into()));
                        };

                        let Some(public_exponent) = public_exponent else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse raw RSASHA256 SubjectPublicKeyInfo: missing public exponent".into()));
                        };

                        let n = modulus.as_slice();
                        let e = public_exponent.as_slice();
                        crate::crypto::common::rsa_encode(e, n)
                    }

                    (SecurityAlgorithm::ECDSAP256SHA256, KeyFormatType::Raw) => {
                        // For an ECDSA key Fortanix DSM supplies: (from https://asn1js.eu/)
                        //   SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
                        //     algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
                        //       algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
                        //       parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
                        //     subjectPublicKey BIT_STRING @23+66: (520 bit)
                        //
                        // From: https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
                        //   The parameter for id-ecPublicKey is as follows and MUST always be
                        //   present:
                        //
                        //     ECParameters ::= CHOICE {
                        //       namedCurve         OBJECT IDENTIFIER
                        //       -- implicitCurve   NULL
                        //       -- specifiedCurve  SpecifiedECDomain
                        //     }
                        //       -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
                        //       -- Details for SpecifiedECDomain can be found in [X9.62].
                        //       -- Any future additions to this CHOICE should be coordinated
                        //       -- with ANSI X9.
                        let source = SliceSource::new(&bytes);
                        let mut bits = None;
                        bcder::Mode::Der
                            .decode(source, |cons| {
                                cons.take_sequence(|cons| {
                                    cons.take_sequence(|cons| {
                                        let algorithm = Oid::take_from(cons)?;
                                        if algorithm != EC_PUBLIC_KEY_OID {
                                            Err(cons.content_err("Only SubjectPublicKeyInfo with algorithm id-ecPublicKey is supported"))
                                        } else {
                                            let named_curve = Oid::take_from(cons)?;
                                            if named_curve != SECP256R1_OID {
                                               return Err(cons.content_err("Only SubjectPublicKeyInfo with namedCurve secp256r1 is supported"));
                                            }
                                            Ok(())
                                        }
                                    })?;
                                    bits = Some(BitString::take_from(cons)?);
                                    Ok(())
                                })
                            }).map_err(|err| kmip::client::Error::DeserializeError(format!("Unable to parse ECDSAP256SHA256 SubjectPublicKeyInfo: {err}")))?;

                        let Some(bits) = bits else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse ECDSAP256SHA256 SubjectPublicKeyInfo bit string: missing octets".into()));
                        };

                        // https://www.rfc-editor.org/rfc/rfc5480#section-2.2
                        //   "The subjectPublicKey from SubjectPublicKeyInfo
                        //    is the ECC public key. ECC public keys have the
                        //    following syntax:
                        //
                        //        ECPoint ::= OCTET STRING
                        //    ...
                        //    The first octet of the OCTET STRING indicates
                        //    whether the key is compressed or uncompressed.
                        //    The uncompressed form is indicated by 0x04 and
                        //    the compressed form is indicated by either 0x02
                        //    or 0x03 (see 2.3.3 in [SEC1]).  The public key
                        //    MUST be rejected if any other value is included
                        //    in the first octet."
                        let Some(octets) = bits.octet_slice() else {
                            return Err(kmip::client::Error::DeserializeError("Unable to parse ECDSAP256SHA256 SubjectPublicKeyInfo bit string: missing octets".into()));
                        };

                        // Expect octet string to be [<compression flag byte>,
                        // <32-byte X value>, <32-byte Y value>].
                        if octets.len() != 65 {
                            return Err(kmip::client::Error::DeserializeError(format!("Unable to parse ECDSAP256SHA256 SubjectPublicKeyInfo bit string: expected [<compression flag byte>, <32-byte X value>, <32-byte Y value>]: {} ({} bytes)", base16::encode_display(octets), octets.len())));
                        }

                        // Note: OpenDNSSEC doesn't support the compressed
                        // form either.
                        let compression_flag = octets[0];
                        if compression_flag != 0x04 {
                            return Err(kmip::client::Error::DeserializeError(format!("Unable to parse ECDSAP256SHA256 SubjectPublicKeyInfo bit string: unknown compression flag {compression_flag:?}")))?;
                        }

                        // Expect octet string to be X | Y (| denotes
                        // concatenation) where X and Y are each 32 bytes
                        // (because P-256 uses 256 bit values and 256 bits are
                        // 32 bytes). Skip the compression flag.
                        octets[1..].to_vec()
                    }

                    _ => todo!(),
                }
            }

            KeyMaterial::TransparentRSAPublicKey(
                // Nameshed-HSM-Relay
                TransparentRSAPublicKey {
                    modulus,
                    public_exponent,
                },
            ) => rsa_encode(&public_exponent, &modulus),

            mat => return Err(kmip::client::Error::DeserializeError(format!("Fetched KMIP object has unsupported key material type: {mat}"))),
        };

        Ok(octets)
    }
}

#[cfg(feature = "unstable-crypto-sign")]
/// Submodule for private keys and signing.
pub mod sign {
    use std::boxed::Box;
    use std::string::{String, ToString};
    use std::time::SystemTime;
    use std::vec::Vec;

    use kmip::client::pool::SyncConnPool;
    use kmip::types::common::{
        CryptographicAlgorithm, CryptographicParameters,
        CryptographicUsageMask, Data, DigitalSignatureAlgorithm,
        HashingAlgorithm, PaddingMethod, UniqueBatchItemID, UniqueIdentifier,
    };
    use kmip::types::request::{
        self, BatchItem, CommonTemplateAttribute,
        PrivateKeyTemplateAttribute, PublicKeyTemplateAttribute,
        RequestPayload,
    };
    use kmip::types::response::{
        CreateKeyPairResponsePayload, ResponsePayload,
    };
    use log::trace;
    use openssl::ecdsa::EcdsaSig;
    use tracing::{debug, error};
    use url::Url;
    use uuid::Uuid;

    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::common::DigestType;
    use crate::crypto::kmip::{GenerateError, KeyUrl, PublicKey};
    use crate::crypto::sign::{
        GenerateParams, SignError, SignRaw, Signature,
    };
    use crate::rdata::Dnskey;
    use crate::utils::base16;

    impl From<kmip::client::Error> for SignError {
        fn from(err: kmip::client::Error) -> Self {
            err.to_string().into()
        }
    }

    /// A reference to a key pair stored in an [OASIS KMIP] compliant HSM
    /// server.
    ///
    /// [OASIS KMIP]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
    #[derive(Clone, Debug)]
    pub struct KeyPair {
        /// The algorithm used by the key.
        algorithm: SecurityAlgorithm,

        /// The KMIP ID of the private key.
        private_key_id: String,

        /// The KMIP ID of the public key.
        public_key_id: String,

        /// The connection pool for connecting to the KMIP server.
        // TODO: Should this be T that impl's a Connection trait, why should
        // it know that it's a pool rather than a single connection?
        conn_pool: SyncConnPool,

        /// Cached DNSKEY RR for the public key.
        dnskey: Dnskey<Vec<u8>>,

        /// Flags from [`Dnskey`].
        flags: u16,
    }

    //--- Constructors

    impl KeyPair {
        /// Construct a reference to a KMIP HSM held key pair using key
        /// metadata.
        pub fn from_metadata(
            algorithm: SecurityAlgorithm,
            flags: u16,
            private_key_id: &str,
            public_key_id: &str,
            conn_pool: SyncConnPool,
        ) -> Result<Self, GenerateError> {
            let dnskey = PublicKey::from_metadata(
                public_key_id,
                algorithm,
                conn_pool.clone(),
            )
            .map_err(|err| GenerateError::Kmip(err.to_string()))?
            .dnskey(flags);

            Ok(Self {
                algorithm,
                private_key_id: private_key_id.to_string(),
                public_key_id: public_key_id.to_string(),
                conn_pool,
                flags,
                dnskey,
            })
        }

        /// Construct a reference to a KMIP HSM held key pair using key URLs.
        pub fn from_urls(
            priv_key_url: KeyUrl,
            pub_key_url: KeyUrl,
            conn_pool: SyncConnPool,
        ) -> Result<Self, GenerateError> {
            if priv_key_url.algorithm() != pub_key_url.algorithm() {
                return Err(GenerateError::Kmip(format!("Private and public key URLs have different algorithms: {} vs {}", priv_key_url.algorithm(), pub_key_url.algorithm()).into()));
            } else if priv_key_url.flags() != pub_key_url.flags() {
                return Err(GenerateError::Kmip(format!("Private and public key URLs have different flags: {} vs {}", priv_key_url.flags(), pub_key_url.flags()).into()));
            } else if priv_key_url.server_id() != pub_key_url.server_id() {
                return Err(GenerateError::Kmip(format!("Private and public key URLs have different server IDs: {} vs {}", priv_key_url.server_id(), pub_key_url.server_id()).into()));
            } else if priv_key_url.server_id() != conn_pool.server_id() {
                return Err(GenerateError::Kmip(format!("Key URLs have different server ID to the KMIP connection pool: {} vs {}", priv_key_url.server_id(), conn_pool.server_id()).into()));
            } else {
                Self::from_metadata(
                    priv_key_url.algorithm(),
                    priv_key_url.flags(),
                    priv_key_url.key_id(),
                    pub_key_url.key_id(),
                    conn_pool,
                )
            }
        }
    }

    //--- Accessors

    impl KeyPair {
        /// Get the KMIP HSM ID for the private half of this key pair.
        pub fn private_key_id(&self) -> &str {
            &self.private_key_id
        }

        /// Get the KMIP HSM ID for the public half of this key pair.
        pub fn public_key_id(&self) -> &str {
            &self.public_key_id
        }

        /// Get a KMIP URL for the private half of this key pair.
        pub fn private_key_url(&self) -> Result<Url, SignError> {
            self.mk_key_url(&self.private_key_id)
        }

        /// Get a KMIP URL for the public half of this key pair.
        pub fn public_key_url(&self) -> Result<Url, SignError> {
            self.mk_key_url(&self.public_key_id)
        }

        /// Get a reference to the KMIP HSM connection pool for this key pair.
        pub fn conn_pool(&self) -> &SyncConnPool {
            &self.conn_pool
        }
    }

    //--- Operations

    impl KeyPair {
        /// Enqueue a KMIP signing operation using this key pair on the given
        /// data.
        ///
        /// Like [`SignRaw::sign_raw()`] but deferred until
        /// [`KeyPair::sign_raw_submit_queue()`] is called.
        pub fn sign_raw_enqueue(
            &self,
            queue: &mut SignQueue,
            data: &[u8],
        ) -> Result<Option<Signature>, SignError> {
            let request = self.sign_pre(data)?;
            let operation = request.operation();
            let batch_item_id =
                UniqueBatchItemID(Uuid::new_v4().into_bytes().to_vec());
            let batch_item =
                BatchItem(operation, Some(batch_item_id), request);
            queue.0.push(batch_item);
            Ok(None)
        }

        /// Submit the given signing queue as a batch to the KMIP HSM.
        //
        // TODO: Should the queue store the KMIP connection pool reference and
        // should submit() be a method on the queue?
        // TODO: What happens if the same queue is used with
        // sign_raw_enqueue() but with keys that are held by different KMIP
        // HSMs and thus have different KMIP connection pools?
        pub fn sign_raw_submit_queue(
            &self,
            queue: &mut SignQueue,
        ) -> Result<Vec<Signature>, SignError> {
            // Execute the request and capture the response.
            let client = self.conn_pool.get().map_err(|err| {
                format!("Error while obtaining KMIP pool connection: {err}")
            })?;

            // Drain the queue.
            let q_size = queue.0.capacity();
            let mut empty = Vec::with_capacity(q_size);
            std::mem::swap(&mut queue.0, &mut empty);
            let queue = empty;

            // This will block which could be problematic if executed from an
            // async task handler thread as it will block execution of other
            // tasks while waiting for the remote KMIP server to respond.
            let res = client.do_requests(queue).map_err(|err| {
                format!("Error while sending KMIP request: {err}")
            })?;

            let mut sigs = Vec::with_capacity(q_size);
            for res in res {
                let res = res?;
                let sig = self.sign_post(res.payload.unwrap())?;
                sigs.push(sig);
            }

            Ok(sigs)
        }
    }

    //--- Internal details

    impl KeyPair {
        /// Make a KMIP URL for this key using the given KMIP ID.
        fn mk_key_url(&self, key_id: &str) -> Result<Url, SignError> {
            // We have to store the algorithm in the URL because the DNSSEC
            // algorithm (e.g. 5 and 7) don't necessarily correspond to the
            // cryptographic algorithm of the key known to the HSM. And we
            // have to store the flags in the URL because these are not known
            // to the HSM, they say someting about the use to which the key
            // will be put of which the HSM is unaware.
            let url = format!(
                "kmip://{}/keys/{}?algorithm={}&flags={}",
                self.conn_pool.server_id(),
                key_id,
                self.algorithm,
                self.flags
            );

            let url = Url::parse(&url).map_err::<SignError, _>(|err| {
                format!("unable to parse {url} as URL: {err}").into()
            })?;

            Ok(url)
        }

        /// Prepare a KMIP signing operation request to sign the given data
        /// using this key pair.
        fn sign_pre(&self, data: &[u8]) -> Result<RequestPayload, SignError> {
            let (crypto_alg, hashing_alg, _digest_type) = match self.algorithm
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
                alg => {
                    return Err(format!(
                        "Algorithm not supported for KMIP signing: {alg}"
                    )
                    .into())
                }
            };
            let mut cryptographic_parameters =
                CryptographicParameters::default()
                    .with_hashing_algorithm(hashing_alg)
                    .with_cryptographic_algorithm(crypto_alg);
            if self.algorithm == SecurityAlgorithm::RSASHA256 {
                cryptographic_parameters = cryptographic_parameters
                    .with_padding_method(PaddingMethod::PKCS1_v1_5);
            }
            let request = RequestPayload::Sign(
                Some(UniqueIdentifier(self.private_key_id.clone())),
                Some(cryptographic_parameters),
                Data(data.as_ref().to_vec()),
            );
            Ok(request)
        }

        /// Process a KMIP HSM signing operation response for this key pair.
        fn sign_post(
            &self,
            res: ResponsePayload,
        ) -> Result<Signature, SignError> {
            tracing::trace!("Checking sign payload");
            let ResponsePayload::Sign(signed) = res else {
                unreachable!();
            };

            trace!(
                "Algorithm: {}, Signature Data: {}",
                self.algorithm,
                base16::encode_display(&signed.signature_data)
            );
            match (self.algorithm, signed.signature_data.len()) {
                (SecurityAlgorithm::RSASHA256, _) => Ok(Signature::RsaSha256(
                    signed.signature_data.into_boxed_slice(),
                )),

                (SecurityAlgorithm::ECDSAP256SHA256, _) => {
                    // ECDSA signature received from Fortanix DSM, decoded
                    // using this command:
                    //
                    //   $ echo '<hex encoded signature data>' | xxd -r -p | dumpasn1 -
                    //     0  69: SEQUENCE {
                    //     2  33:   INTEGER
                    //          :     00 C6 A7 D1 2E A1 0C B4 96 BD D9 A5 48 2C 9B F4
                    //          :     0C EC 9F FC EF 1A 0D 59 BB B9 24 F3 FE DA DC F8
                    //          :     9E
                    //    37  32:   INTEGER
                    //          :     4B A7 22 69 F2 F8 65 88 63 D0 25 D3 A9 D5 92 4F
                    //          :     A2 21 BD 59 CD 27 60 6D 16 C3 79 EF B4 0A CA 33
                    //          :   }
                    //
                    // Where the two integer values are known as 'r' and 's'.
                    let signature = EcdsaSig::from_der(&signed.signature_data).unwrap();
                    let mut r = signature.r().to_vec_padded(32).unwrap();
                    let mut s = signature.s().to_vec_padded(32).unwrap();
                    r.append(&mut s);
                    Ok(Signature::EcdsaP256Sha256(Box::<[u8; 64]>::new(
                        r.try_into().unwrap()
                    )))
                }

                (SecurityAlgorithm::ECDSAP384SHA384, 96) => {
                    Ok(Signature::EcdsaP384Sha384(Box::<[u8; 96]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .unwrap()
                    )))
                }
                (SecurityAlgorithm::ED25519, 64) => {
                    Ok(Signature::Ed25519(Box::<[u8; 64]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .unwrap()
                    )))
                }

                (SecurityAlgorithm::ED448, 114) => {
                    Ok(Signature::Ed448(Box::<[u8; 114]>::new(
                        signed
                            .signature_data
                            .try_into()
                            .unwrap()
                    )))
                }

                (alg, sig_len) => {
                    Err(format!("KMIP signature algorithm not supported or signature length incorrect: {sig_len} byte {alg} signature (0x{})",
                        base16::encode_display(&signed.signature_data
                    )))?
                }
            }
        }
    }

    /// A queue of KMIP signing operations pending batch submission.
    pub struct SignQueue(Vec<BatchItem>);

    impl SignQueue {
        pub fn new() -> Self {
            Self(vec![])
        }
    }

    impl SignRaw for KeyPair {
        fn algorithm(&self) -> SecurityAlgorithm {
            self.algorithm
        }

        fn flags(&self) -> u16 {
            self.flags
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            self.dnskey.clone()
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            let request = self.sign_pre(data)?;

            // Execute the request and capture the response.
            let client = self.conn_pool.get().map_err(|err| {
                format!("Error while obtaining KMIP pool connection: {err}")
            })?;

            // This will block which could be problematic if executed from an
            // async task handler thread as it will block execution of other
            // tasks while waiting for the remote KMIP server to respond.
            let res = client.do_request(request).map_err(|err| {
                format!("Error while sending KMIP request: {err}")
            })?;

            self.sign_post(res)
        }
    }

    //----------- generate() -------------------------------------------------

    /// Generate a new key pair for a given algorithm using a specified HSM.
    pub fn generate(
        name: String,
        // TODO: Is this enough? Or do we need to take SecurityAlgorithm
        // as input instead of GenerateParams to ensure we don't lose
        // distinctions like 5 vs 7 which are both RSASHA1?
        params: GenerateParams,
        flags: u16,
        conn_pool: SyncConnPool,
    ) -> Result<KeyPair, GenerateError> {
        let algorithm = params.algorithm();

        let client = conn_pool
            .get()
            .map_err(|err| GenerateError::Kmip(format!("Key generation failed: Cannot connect to KMIP server {}: {err}", conn_pool.server_id())))?;

        // TODO: Determine this on first use of the HSM?
        // PyKMIP doesn't support ActivationDate.
        // Fortanix DSM does support it and creates the key in an activated
        // state but still returns a (harmless?) error:
        //   Server error: Operation CreateKeyPair failed: Input field `state`
        //   is not coherent with provided activation/deactivation dates
        let activate_on_create = false;

        let use_cryptographic_params = false;

        let mut common_attrs = vec![];
        let priv_key_attrs = vec![
            // Krill supplies a name at creation time. Do we need to?
            // Note: Fortanix DSM requires a name for at least the private
            // key.
            request::Attribute::Name(format!("{name}_priv")),
            request::Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Sign,
            ),
        ];
        let pub_key_attrs = vec![
            // Krill supplies a name at creation time. Do we need to?
            // Note: Fortanix DSM requires a name for at least the private
            // key.
            request::Attribute::Name(format!("{name}_pub")),
            // Krill does verification, do we need to? ODS doesn't.
            // Note: PyKMIP requires a Cryptographic Usage Mask for the public
            // key.
            request::Attribute::CryptographicUsageMask(
                CryptographicUsageMask::Verify,
            ),
        ];

        // PyKMIP doesn't support CryptographicParameters so we cannot supply
        // HashingAlgorithm. It also doesn't support the Hash operation.
        // How do we specify SHA256 hashing? Do we have to do it ourselves
        // post-signing? Can we just specify the hashing to do when invoking
        // the Sign operation?
        // Fortanix DSM also doesn't support Cryptographic Parameters:
        //   Server error: Operation CreateKeyPair failed: Don't have handling
        //   for attribute Cryptographic Parameters

        // PyKMIP doesn't support Attribute::ActivationDate. For HSMs that
        // don't support it we have to do a separate Activate operation after
        // creating the key pair.
        // Fortanix DSM does support ActivationDate.

        match params {
            GenerateParams::RsaSha256 { bits } => {
                // RFC 8624 3.1 DNSSEC Signing: MUST
                // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc395776503
                //   "For RSA, Cryptographic Length corresponds to the bit
                //    length of the Modulus"

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
                    // body" if cryptographic length is not specified, and
                    // a value of 256 works fine while a value of 255 causes
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
        tracing::trace!("Key generation operation complete");

        // Drop the KMIP client so that it will be returned to the pool and
        // thus be available below when KeyPair::new() is invoked and tries to
        // fetch the details needed to determine the DNSKEY RR.
        drop(client);

        // Process the successful response
        let ResponsePayload::CreateKeyPair(payload) = response else {
            error!("KMIP request failed: Wrong response type received!");
            return Err(GenerateError::Kmip("Unable to parse KMIP response: payload should be CreateKeyPair".to_string()));
        };

        let CreateKeyPairResponsePayload {
            private_key_unique_identifier,
            public_key_unique_identifier,
        } = payload;

        tracing::trace!("Creating KeyPair with DNSKEY");

        let key_pair = KeyPair::from_metadata(
            algorithm,
            flags,
            private_key_unique_identifier.as_str(),
            public_key_unique_identifier.as_str(),
            conn_pool.clone(),
        )
        .map_err(|err| GenerateError::Kmip(err.to_string()))?;

        // Activate the key if not already, otherwise it cannot be used for
        // signing.
        if !activate_on_create {
            let client = conn_pool
                .get()
                .map_err(|err| GenerateError::Kmip(format!("Key generation failed: Cannot connect to KMIP server {}: {err}", conn_pool.server_id())))?;
            let request =
                RequestPayload::Activate(Some(private_key_unique_identifier));

            // Execute the request and capture the response
            tracing::trace!("Activating KMIP key...");
            let response = client.do_request(request).map_err(|err| {
                eprintln!("KMIP activate private key request failed: {err}");
                eprintln!(
                    "KMIP last request: {}",
                    client.last_req_diag_str().unwrap_or_default()
                );
                eprintln!(
                    "KMIP last response: {}",
                    client.last_res_diag_str().unwrap_or_default()
                );
                GenerateError::Kmip(err.to_string())
            })?;
            tracing::trace!("Activate operation complete");

            // Process the successful response
            let ResponsePayload::Activate(_) = response else {
                error!("KMIP request failed: Wrong response type received!");
                return Err(GenerateError::Kmip("Unable to parse KMIP response: payload should be Activate".to_string()));
            };
        }

        Ok(key_pair)
    }

    //----------- TODO: destroy() --------------------------------------------

    // TODO
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::string::ToString;
    use std::time::SystemTime;
    use std::vec::Vec;

    use kmip::client::pool::ConnectionManager;
    use kmip::client::ConnectionSettings;

    use crate::crypto::kmip::sign::generate;
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
            "Test server".to_string(),
            conn_settings.into(),
            16384,
            Some(Duration::from_secs(60)),
            Some(Duration::from_secs(60)),
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
            crate::crypto::sign::GenerateParams::RsaSha256 { bits: 2048 },
            // crate::crypto::sign::GenerateParams::EcdsaP256Sha256,
            256,
            pool,
        );
        dbg!(&res);
        let key = res.unwrap();

        eprintln!("DNSKEY: {}", key.dnskey());
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
            "Test server".to_string(),
            conn_settings.into(),
            16384,
            Some(Duration::from_secs(60)),
            Some(Duration::from_secs(60)),
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

        eprintln!("DNSKEY: {}", key.dnskey());

        client.activate_key(key.public_key_id()).unwrap();

        // Fortanix: Activating the public key also activates the private key.
        // Attempting to then activate the private key fails as it is already
        // active. Yet signing fails with "Object is not yet active"...
        // client.activate_key(key.private_key_id()).unwrap();

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
