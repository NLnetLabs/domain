//! Service Binding (SVCB) Parameter Registry

int_enum! {
    =>
    SvcParamKey, u16;

    (MANDATORY => 0, b"Mandatory keys in this RR")
    (ALPN => 1, b"Additional supported protocols")
    (NO_DEFAULT_ALPN => 2, b"Additional supported protocols")
    (PORT => 3, b"Port for alternative endpoint")
    (IPV4HINT => 4, b"IPv4 address hints")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    (ECH => 5, b"Encrypted ClientHello info")
    (IPV6HINT => 6, b"IPv6 address hints")
    // https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/
    (DOHPATH => 7, b"DNS over HTTPS path template")
}

int_enum_str_with_prefix!(SvcParamKey, "key", b"key", u16, "unknown key");

impl SvcParamKey {
    pub const PRIVATE_RANGE_BEGIN: u16 = 65280;
    pub const PRIVATE_RANGE_END: u16 = 65534;
    pub const INVALID: Self = Self(65535);
}
