//! NSEC3 Hash Algorithms


//------------ Nsec3HashAlg --------------------------------------------------

int_enum!{
    /// NSEC3 Hash Algorithm Numbers
    ///
    /// For the currently registered values see the [IANA registration].
    ///
    /// [IANA registration]: https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml#dnssec-nsec3-parameters-3
    =>
    Nsec3HashAlg, u8;

    (Sha1 => 1, b"SHA-1")
}

int_enum_str_decimal!(Nsec3HashAlg, u8);

