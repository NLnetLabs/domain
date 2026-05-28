use core::convert::From;
/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
use std::fmt::Debug;

struct Foo {}

trait DNSParameter<T> {
    type INT: Sized + Debug;

    //--- getters
    fn get_integer(&self) -> Self::INT;
    fn get_mnemonic(&self) -> &'static str;

    //--- from;
    fn from_integer(value: Self::INT) -> Self;
    fn from_mnemonic(value: &str) -> Self;
}

impl<P> From<u8> for P
where
    P: DNSParameter<Foo, INT = u8>,
{
    fn from(value: u8) -> Self {
        P::from_integer(value)
    }
}
