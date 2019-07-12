use bytes::Bytes;
use domain_core::ToDname;
use domain_core::iana::SecAlg;
use domain_core::rdata::{Ds, Dnskey};


pub trait SigningKey {
    type Error;

    fn dnskey(&self) -> Result<Dnskey, Self::Error>;
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error>;

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.algorithm())
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        self.dnskey().map(|dnskey| dnskey.key_tag())
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error>;
}


impl<'a, K: SigningKey> SigningKey for &'a K {
    type Error = K::Error;

    fn dnskey(&self) -> Result<Dnskey, Self::Error> {
        (*self).dnskey()
    }
    fn ds<N: ToDname>(&self, owner: N) -> Result<Ds, Self::Error> {
        (*self).ds(owner)
    }

    fn algorithm(&self) -> Result<SecAlg, Self::Error> {
        (*self).algorithm()
    }

    fn key_tag(&self) -> Result<u16, Self::Error> {
        (*self).key_tag()
    }

    fn sign(&self, data: &[u8]) -> Result<Bytes, Self::Error> {
        (*self).sign(data)
    }
}

