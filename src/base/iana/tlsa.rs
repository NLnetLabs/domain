//! TLSA IANA parameters.

//------------ TlsaCertificateUsage ------------------------------------------

use crate::base::iana::macros::FromStrError;
use crate::base::iana::macros::IanaEnum;

iana_enum! {
    /// TLSA Certificate Usage type.
    ///
    /// This type specifies the provided association that will be used to match the certificate
    /// presented in the TLS handshake
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-04.
    ///
    /// [TLSA]: ../../../rdata/tlsa/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml#certificate-usages
    =>
    TlsaCertificateUsage, u8;
    display_integer,
    parse_from_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";

    /// CA constraint
    (PKIX_TA => 0, "PKIX-TA")

    /// Service certificate constraint
    (PKIX_EE => 1, "PKIX-EE")

    /// Trust anchor assertion
    (DANE_TA => 2, "DANE-TA")

    /// Domain-issued certificate
    (DANE_EE => 3, "DANE-EE")

    /// Reserved for Private Use
    (PRIVCERT => 255, "PrivCert")
}

int_enum_zonefile_fmt_decimal!(
    TlsaCertificateUsage,
    "certificate usage type"
);

//------------ TlsaSelector --------------------------------------------------

iana_enum! {
    /// TLSA Selector type.
    ///
    /// This type specifies which part of the TLS certificate presented by the server will be
    /// matched against the association data
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-04.
    ///
    /// [TLSA]: ../../../rdata/tlsa/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml#selectors
    =>
    TlsaSelector, u8;
    display_integer,
    parse_from_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";

    /// Full certificate
    (CERT => 0, "Cert")

    /// SubjectPublicKeyInfo
    (SPKI => 1, "SPKI")

    /// Reserved for Private Use
    (PRIVSEL => 255, "PrivSel")
}

int_enum_zonefile_fmt_decimal!(TlsaSelector, "selector");

//------------ TlsaMatchingType ----------------------------------------------

iana_enum! {
    /// TLSA Matching Type type.
    ///
    /// This type specifies how the certificate association is presented.
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-04.
    ///
    /// [TLSA]: ../../../rdata/tlsa/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml#matching-types
    =>
    TlsaMatchingType, u8;
    display_integer,
    parse_from_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";

    /// No hash used
    (FULL => 0, "Full")

    /// 256 bit hash by SHA2
    (SHA2_256 => 1, "SHA2-256")

    /// 512 bit hash by SHA2
    (SHA2_512 => 2, "SHA2-512")

    /// Reserved for Private Use
    (PRIVMATCH => 255, "PrivMatch")
}

int_enum_zonefile_fmt_decimal!(TlsaMatchingType, "matching type");
