//! Service Binding (SVCB) Parameter Registry

use core::fmt;

int_enum! {
    =>
    SvcParamKey, u16;

    (Mandatory => 0, b"Mandatory keys in this RR")
    (Alpn => 1, b"Additional supported protocols")
    (NoDefaultAlpn => 2, b"Additional supported protocols")
    (Port => 3, b"Port for alternative endpoint")
    (Ipv4Hint => 4, b"IPv4 address hints")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    (Ech => 5, b"Encrypted ClientHello info")
    (Ipv6Hint => 6, b"IPv6 address hints")
    // https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/
    (DohPath => 7, b"DNS over HTTPS path template")
}

pub const SVC_PARAM_KEY_PRIVATE_RANGE_BEGIN: u16 = 65280;
pub const SVC_PARAM_KEY_PRIVATE_RANGE_END: u16 = 65534;
pub const SVC_PARAM_KEY_INVALID: u16 = 65535;

impl fmt::Display for SvcParamKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::Mandatory => "mandatory",
            Self::Alpn => "alpn",
            Self::NoDefaultAlpn => "nodefaultalpn",
            Self::Port => "port",
            Self::Ipv4Hint => "ipv4hint",
            Self::Ech => "ech",
            Self::Ipv6Hint => "ipv6hint",
            Self::DohPath => "dohpath",
            Self::Int(n) => return write!(f, "key{}", n),
        };

        f.write_str(s)
    }
}
