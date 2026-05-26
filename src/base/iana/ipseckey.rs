//! IPSECKEY IANA parameters.
//!
//! The values of these types don't officially have an IANA assigned name and
//! mnemonic. For ease of use, we define them here anyway.

//------------ IpseckeyAlgorithm ---------------------------------------------

int_enum! {
    /// IPSECKEY Algorithms.
    ///
    /// This type identifies the public key's cryptographic algorithm of the
    /// [IPSECKEY].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-09.
    ///
    /// [IPSECKEY]: ../../../rdata/ipseckey/index.html
    /// [IANA registration]:  https://www.iana.org/assignments/ipseckey-rr-parameters/ipseckey-rr-parameters.xhtml#ipseckey-rr-parameters-1
    =>
    IpseckeyAlgorithm, u8;

    /// Specified that no Public key is present.
    (NONE => 0, "NONE")

    /// Specified that a DSA Public Key is used.
    (DSA => 1, "DSA")

    /// Specified that an RSA Public Key is used.
    (RSA => 2, "RSA")

    /// Specified that an ECDSA Public Key is used.
    (ECDSA => 3, "ECDSA")

    /// Specified that an EdDSA Public Key is used.
    (EDDSA => 4, "EdDSA")
}

// int_enum_fromstr_decimal!(IpseckeyAlgorithm, u8);
// int_enum_display_decimal!(IpseckeyAlgorithm, u8);
// int_enum_zonefile_fmt_decimal!(IpseckeyAlgorithm, "ipseckey algorithm");

scan_impl!(IpseckeyAlgorithm);

int_enum_zonefile_fmt_decimal!(IpseckeyAlgorithm, "algorithm");

// Display
int_enum_impl_display_integer!(
    IpseckeyAlgorithm
);

// FromStrError
instantiate_fromstrerror_with_error_description!(
    "unknown ipseckey algorithm"
);

// serde::Serialize / serde::Deserialize
int_enum_impl_serde_to_and_from_integer!(IpseckeyAlgorithm, u8);

// core::str::FromStr / from_bytes()
int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer!(IpseckeyAlgorithm);

//------------ IpseckeyGateway -----------------------------------------------

int_enum! {
    /// IPSECKEY Gateway Types.
    ///
    /// This type indicates the format of the information that is stored in
    /// the gateway field of the [IPSECKEY].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2025-09-09.
    ///
    /// [IPSECKEY]: ../../../rdata/ipseckey/index.html
    /// [IANA registration]: https://www.iana.org/assignments/ipseckey-rr-parameters/ipseckey-rr-parameters.xhtml#ipseckey-rr-parameters-2
    =>
    IpseckeyGatewayType, u8;

    /// Specified that No gateway is present.
    (NONE => 0, "NONE")

    /// Specified that A 4-byte IPv4 address is present.
    (IPV4 => 1, "IPV4")

    /// Specified that A 16-byte IPv6 address is present.
    (IPV6 => 2, "IPV6")

    /// Specified that A wire-encoded domain name is present.
    (NAME => 3, "NAME")
}

// int_enum_fromstr_decimal!(IpseckeyGatewayType, u8);
// int_enum_display_decimal!(IpseckeyGatewayType, u8);
// int_enum_zonefile_fmt_decimal!(IpseckeyGatewayType, "ipseckey gateway type");

scan_impl!(IpseckeyGatewayType);

int_enum_zonefile_fmt_decimal!(IpseckeyGatewayType, "algorithm");

// Display
int_enum_impl_display_integer!(
    IpseckeyGatewayType
);

// FromStrError
// instantiate_fromstrerror_with_error_description!(
//     "unknown ipseckey algorithm"
// );

// serde::Serialize / serde::Deserialize
int_enum_impl_serde_to_and_from_integer!(IpseckeyGatewayType, u8);

// core::str::FromStr / from_bytes()
int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer!(IpseckeyGatewayType);
