//! DNSSEC Algorithm Numbers

//------------ SecAlg -------------------------------------------------------

int_enum! {
    /// Security Algorithm Numbers.
    ///
    /// These numbers are used in various security related record types.
    ///
    /// For the currently registered values see the [IANA registration].
    ///
    /// [IANA registration]: http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1].
    =>
    SecAlg, u8;

    /// Delete DS
    ///
    /// This algorithm is used in RFC 8087 to signal to the parent that a
    /// certain DS record should be deleted. It is _not_ an actual algorithm
    /// and can neither be used in zone nor transaction signing.
    (DELETE => 0, b"DELETE")

    /// RSA/MD5
    ///
    /// This algorithm was described in RFC 2537 and since has been
    /// deprecated due to weaknesses of the MD5 hash algorithm by RFC 3110
    /// which suggests to use RSA/SHA1 instead.
    ///
    /// This algorithm may not be used for zone signing but may be used
    /// for transaction security.
    (RSAMD5 => 1, b"RSAMD5")

    /// Diffie-Hellman
    ///
    /// This algorithm is described in RFC 2539 for storing Diffie-Hellman
    /// (DH) keys in DNS resource records. It can not be used for zone
    /// signing but only for transaction security.
    (DH => 2, b"DH")

    /// DSA/SHA1
    ///
    /// This algorithm is described in RFC 2536. It may be used both for
    /// zone signing and transaction security.
    (DSA => 3, b"DSA")

    /// RSA/SHA-1
    ///
    /// This algorithm is described in RFC 3110. It may be used both for
    /// zone signing and transaction security. It is mandatory for DNSSEC
    /// implementations.
    (RSASHA1 => 5, b"RSASHA1")

    /// DSA-NSEC3-SHA1
    ///
    /// This value is an alias for `Dsa` for use within NSEC3 records.
    (DSA_NSEC3_SHA1 => 6, b"DSA-NSEC3-SHA1")

    /// RSASHA1-NSEC3-SHA1
    ///
    /// This value is an alias for `RsaSha1` for use within NSEC3 records.
    (RSASHA1_NSEC3_SHA1 => 7, b"RSASHA1-NSEC3-SHA1")

    /// RSA/SHA-256
    ///
    /// This algorithm is described in RFC 5702. It may be used for zone
    /// signing only.
    (RSASHA256 => 8, b"RSASHA256")

    /// RSA/SHA-512
    ///
    /// This algorithm is described in RFC 5702. It may be used for zone
    /// signing only.
    (RSASHA512 => 10, b"RSASHA512")

    /// GOST R 34.10-2001
    ///
    /// This algorithm is described in RFC 5933. It may be used for zone
    /// signing only.
    (ECC_GOST => 12, b"ECC-GOST")

    /// ECDSA Curve P-256 with SHA-256
    ///
    /// This algorithm is described in RFC 6605. It may be used for zone
    /// signing only.
    (ECDSAP256SHA256 => 13, b"ECDSAP256SHA256")

    /// ECDSA Curve P-384 with SHA-384
    ///
    /// This algorithm is described in RFC 6605. It may be used for zone
    /// signing only.
    (ECDSAP384SHA384 => 14, b"ECDSAP384SHA384")

    /// ED25519
    ///
    /// This algorithm is described in RFC 8080.
    (ED25519 => 15, b"ED25519")

    /// ED448
    ///
    /// This algorithm is described in RFC 8080.
    (ED448 => 16, b"ED448")

    /// Reserved for Indirect Keys
    ///
    /// This value is reserved by RFC 4034.
    (INDIRECT => 252, b"INDIRECT")

    /// A private algorithm identified by a domain name.
    ///
    /// This value is defined in RFC 4034.
    (PRIVATEDNS => 253, b"PRIVATEDNS")

    /// A private algorithm identified by a ISO OID.
    ///
    /// This value is defined in RFC 4034.
    (PRIVATEOID => 254, b"PRIVATEOID")
}

int_enum_str_with_decimal!(SecAlg, u8, "unknown algorithm");
