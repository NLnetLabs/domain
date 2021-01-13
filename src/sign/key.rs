use crate::base::iana::SecAlg;
use crate::base::name::ToDname;
use crate::rdata::{Dnskey, Ds};

pub trait SigningKey {
    type Octets: AsRef<[u8]>;
    type Signature: AsRef<[u8]>;
    type Error;

    fn dnskey(&self) -> Result<Dnskey<Self::Octets>, Self::Error>;
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds<Self::Octets>, Self::Error>;

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.algorithm())
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.key_tag())
    }

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::Error>;
}

impl<'a, K: SigningKey> SigningKey for &'a K {
    type Octets = K::Octets;
    type Signature = K::Signature;
    type Error = K::Error;

    fn dnskey(&self) -> Result<Dnskey<Self::Octets>, Self::Error> {
        (*self).dnskey()
    }
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds<Self::Octets>, Self::Error> {
        (*self).ds(owner)
    }

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        (*self).algorithm()
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        (*self).key_tag()
    }

    fn sign(&self, data: &[u8]) -> Result<Self::Signature, Self::Error> {
        (*self).sign(data)
    }
}
