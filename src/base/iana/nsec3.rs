//! NSEC3 hash algorithms.

//------------ Nsec3HashAlgorithm --------------------------------------------

int_enum! {
    /// NSEC3 hash algorithm numbers.
    ///
    /// This type selects the algorithm used to hash domain names for use with
    /// the [NSEC3].
    ///
    /// For the currently registered values see the [IANA registration]. This
    /// type is complete as of 2008-03-05.
    ///
    /// [NSEC3]: ../../../rdata/rfc5155/index.html
    /// [IANA registration]: https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml#dnssec-nsec3-parameters-3
    =>
    Nsec3HashAlgorithm, u8;

    /// Specifies that the SHA-1 hash function is used.
    (SHA1 => 1, "SHA-1")
}

// int_enum_fromstr_decimal!(Nsec3HashAlgorithm, u8);
// int_enum_display_decimal!(Nsec3HashAlgorithm, u8);
// int_enum_zonefile_fmt_decimal!(Nsec3HashAlgorithm, "hash algorithm");

scan_impl!(Nsec3HashAlgorithm);

int_enum_zonefile_fmt_decimal!(Nsec3HashAlgorithm, "algorithm");

// Display
int_enum_impl_display_integer!(
    Nsec3HashAlgorithm
);

// FromStrError
instantiate_fromstrerror_with_error_description!(
    "unknown Nsec3HashAlgorithm"
);

// serde::Serialize / serde::Deserialize
int_enum_impl_serde_to_and_from_integer!(Nsec3HashAlgorithm, u8);

// core::str::FromStr / from_bytes()
int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer!(Nsec3HashAlgorithm);
