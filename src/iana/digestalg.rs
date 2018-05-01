//! Delegation Signer Digest Algorithm Numbers


//------------ DigestAlg -----------------------------------------------------

int_enum!{
    /// Delegation Signer Digest Algorithm Numbers
    ///
    /// These numbers are used in the DS resource record to specify how the
    /// key digest in the record has been generated.
    ///
    /// For the currently registered values see the [IANA registration].
    ///
    /// [IANA registration]: https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1
    =>
    DigestAlg, u8;

    (Sha1 => 1, b"SHA-1")
    (Sha256 => 2, b"SHA-256")
    (Gost => 3, b"GOST R 34.11-94")
    (Sha384 => 4, b"SHA-384")
}

int_enum_str_decimal!(DigestAlg, u8);

