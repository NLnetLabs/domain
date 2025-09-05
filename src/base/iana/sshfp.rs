//! SSHFP IANA parameters.
//!
//! [RFC 4255]: https://tools.ietf.org/html/rfc4255
//! [RFC 6594]: https://tools.ietf.org/html/rfc6594
//! [RFC 7479]: https://tools.ietf.org/html/rfc7479
//! [RFC 8709]: https://tools.ietf.org/html/rfc8709

//------------ SshfpType -----------------------------------------------------

// FIXME: These types don't actually have a mnemonic, only a description.
int_enum! {
    /// SSHFP fingerprint type.
    ///
    /// This type selects the digest algorithm used for the fingerprint in the
    /// [SSHFP] record.
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-04.
    ///
    /// [SSHFP]: ../../../rdata/sshfp/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml#dns-sshfp-rr-parameters-2
    =>
    SshfpType, u8;

    (RESERVED => 0, "Reserved")

    /// Specified that the SHA-1 algorithm is used. [RFC4255]
    (SHA1 => 1, "SHA-1")

    /// Specified that the SHA-256 algorithm is used. [RFC6594]
    (SHA256 => 2, "SHA-256")

}

int_enum_str_decimal!(SshfpType, u8);
int_enum_zonefile_fmt_decimal!(SshfpType, "fingerprint type");

//------------ SshfpAlgorithm ------------------------------------------------

int_enum! {
    /// SSHFP public key algorithms.
    ///
    /// This type selects the algorithm of the public key associated with the [SSHFP].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-04.
    ///
    /// [SSHFP]: ../../../rdata/sshfp/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml#dns-sshfp-rr-parameters-1
    =>
    SshfpAlgorithm, u8;

    /// Specified that the Reserved algorithm is used. [RFC4255]
    (RESERVED => 0, "Reserved")

    /// Specified that the RSA algorithm is used. [RFC4255]
    (RSA => 1, "RSA")

    /// Specified that the DSA algorithm is used. [RFC4255]
    (DSA => 2, "DSA")

    /// Specified that the ECDSA algorithm is used. [RFC6594]
    (ECDSA => 3, "ECDSA")

    /// Specified that the Ed25519 algorithm is used. [RFC7479]
    (ED25519 => 4, "Ed25519")

    /// Specified that the Ed448 algorithm is used. [RFC8709]
    (ED448 => 6, "Ed448")
}

int_enum_str_decimal!(SshfpAlgorithm, u8);
int_enum_zonefile_fmt_decimal!(SshfpAlgorithm, "public key algorithm");
