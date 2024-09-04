//! Service Binding (SVCB) Parameter Registry

int_enum! {
    =>
    SvcParamKey, u16;

    (MANDATORY => 0, "mandatory")
    (ALPN => 1, "alpn")
    (NO_DEFAULT_ALPN => 2, "no-default-alpn")
    (PORT => 3, "port")
    (IPV4HINT => 4, "ipv4hint")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    (ECH => 5, "ech")
    (IPV6HINT => 6, "ipv6hint")
    // https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/
    (DOHPATH => 7, "dohpath")
}

int_enum_str_with_prefix!(SvcParamKey, "key", b"key", u16, "unknown key");
int_enum_show_with_prefix!(SvcParamKey, "key");

impl SvcParamKey {
    pub const PRIVATE_RANGE_BEGIN: u16 = 65280;
    pub const PRIVATE_RANGE_END: u16 = 65534;
    pub const INVALID: Self = Self(65535);
}
