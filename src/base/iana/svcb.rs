//! Service Binding (SVCB) Parameter Registry

int_enum! {
    =>
    SvcParamKey, u16;

    (MANDATORY => 0, b"mandatory")
    (ALPN => 1, b"alpn")
    (NO_DEFAULT_ALPN => 2, b"no-default-alpn")
    (PORT => 3, b"port")
    (IPV4HINT => 4, b"ipv4hint")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    (ECH => 5, b"ech")
    (IPV6HINT => 6, b"ipv6hint")
    // https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/
    (DOHPATH => 7, b"dohpath")
}

int_enum_str_with_prefix!(SvcParamKey, "key", b"key", u16, "unknown key");

impl SvcParamKey {
    pub const PRIVATE_RANGE_BEGIN: u16 = 65280;
    pub const PRIVATE_RANGE_END: u16 = 65534;
    pub const INVALID: Self = Self(65535);
}
