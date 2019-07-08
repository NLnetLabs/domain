//! Signer.

use bytes::Bytes;
use domain_core::iana::SecAlg;
use domain_core::rdata::Dnskey;


pub trait Key {
    type Error;
    type Signer: Signer<Error=Self::Error>;

    fn dnskey(&self) -> Result<Dnskey, Self::Error>;
    fn signer(&self) -> Result<Self::Signer, Self::Error>;

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.algorithm())
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.key_tag())
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error> {
        let mut signer = self.signer()?;
        signer.update(data)?;
        signer.finalize()
    }
}

pub trait Signer {
    type Error;

    fn update(&mut self, data: &[u8]) -> Result<(), Self::Error>;
    fn finalize(self) -> Result<Bytes, Self::Error>;
}

