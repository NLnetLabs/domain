use crate::base::iana::SecAlg;
use crate::base::name::ToName;
use crate::rdata::{Dnskey, Ds};

pub trait SigningKey {
    type Octets: AsRef<[u8]>;
    type Signature: AsRef<[u8]>;
    type Error;

    fn dnskey(&self, flags: u16)
        -> Result<Dnskey<Self::Octets>, Self::Error>;

    fn ds<N: ToName>(
        &self,
        owner: N,
        flags: u16,
    ) -> Result<Ds<Self::Octets>, Self::Error>;

    fn algorithm(&self) -> Result<SecAlg, Self::Error>;

    fn key_tag(&self, flags: u16) -> Result<u16, Self::Error> {
        self.dnskey(flags).map(|dnskey| dnskey.key_tag())
    }

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::Error>;
}

impl<'a, K: SigningKey> SigningKey for &'a K {
    type Octets = K::Octets;
    type Signature = K::Signature;
    type Error = K::Error;

    fn dnskey(
        &self,
        flags: u16,
    ) -> Result<Dnskey<Self::Octets>, Self::Error> {
        (*self).dnskey(flags)
    }

    fn ds<N: ToName>(
        &self,
        owner: N,
        flags: u16,
    ) -> Result<Ds<Self::Octets>, Self::Error> {
        (*self).ds(owner, flags)
    }

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        (*self).algorithm()
    }

    fn key_tag(&self, flags: u16) -> Result<u16, Self::Error> {
        (*self).key_tag(flags)
    }

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        (*self).sign(data)
    }
}
