//! Service Binding (SVCB) Parameter Registry

use crate::base::iana::macros::FromStrError;
use crate::base::iana::macros::IanaEnum;

iana_enum! {
    =>
    SvcParamKey, u16;
    display_mnemonic_fallback_prefix_integer,
    parse_from_mnemonic_or_prefix_integer,
    serialize_to_mnemonic_fallback_prefix_integer,
    deserialize_from_mnemonic_or_prefix_integer,
    "key";

    (MANDATORY => 0, "mandatory")
    (ALPN => 1, "alpn")
    (NO_DEFAULT_ALPN => 2, "no-default-alpn")
    (PORT => 3, "port")
    (IPV4HINT => 4, "ipv4hint")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-esni/
    (ECH => 5, "ech")
    (IPV6HINT => 6, "ipv6hint")
    // https://datatracker.ietf.org/doc/rfc9461/
    (DOHPATH => 7, "dohpath")
    (OHTTP => 8, "ohttp")
    // https://datatracker.ietf.org/doc/draft-ietf-tls-key-share-prediction/
    (TLS_SUPPORTED_GROUPS => 9, "tls-supported-groups")
    // TODO: docpath https://datatracker.ietf.org/doc/draft-ietf-core-dns-over-coap/
}

int_enum_zonefile_fmt_with_prefix!(SvcParamKey, "key");

impl SvcParamKey {
    pub const PRIVATE_RANGE_BEGIN: u16 = 65280;
    pub const PRIVATE_RANGE_END: u16 = 65534;
    pub const INVALID: Self = Self(65535);
}
