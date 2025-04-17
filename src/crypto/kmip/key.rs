use std::string::String;

use crate::base::iana::SecurityAlgorithm;

use super::pool::KmipConnPool;

struct KeyPair {
    /// The algorithm used by the key.
    algorithm: SecurityAlgorithm,

    private_key_id: String,

    conn_pool: KmipConnPool,
}

#[cfg(feature = "unstable-crypto-sign")]
pub mod sign {
    use std::boxed::Box;
    use std::vec::Vec;

    use crate::crypto::sign::{SignError, SignRaw, Signature};
    use crate::rdata::Dnskey;
    use crate::base::iana::SecurityAlgorithm;

    impl SignRaw for super::KeyPair {
        fn algorithm(&self) -> SecurityAlgorithm {
            self.algorithm
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            todo!()
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            let client = self.conn_pool.get().map_err(|_| SignError)?;

            let signed = client.sign(&self.private_key_id, data).unwrap();

            let signature: [u8; 64] =
                signed.signature_data.try_into().unwrap();

            let sig = Signature::EcdsaP256Sha256(Box::new(signature));

            Ok(sig)
        }
    }
}
