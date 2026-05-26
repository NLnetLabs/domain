//! Delegation signer digest algorithm numbers.

//------------ DigestAlgorithm -----------------------------------------------

int_enum! {
    /// Delegation signer digest algorithm numbers.
    ///
    /// These numbers are used in the DS resource record to specify how the
    /// key digest in the record has been generated.
    ///
    /// For the currently registered values see the [IANA registration].
    /// This type is complete as of the registry update of 2012-04-13.
    ///
    /// [IANA registration]: https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1
    =>
    DigestAlgorithm, u8;

    /// Specifies that the SHA-1 hash function is used.
    ///
    /// Implementation of this function is currently mandatory.
    (SHA1 => 1, "SHA-1")

    /// Specifies that the SHA-256 hash function is used.
    ///
    /// Implementation of this function is currently mandatory.
    (SHA256 => 2, "SHA-256")

    /// Specifies that the GOST R 34.11-94 hash function is used.
    ///
    /// Use of this hash function is described in [RFC 5933]. Implementing
    /// the function is optional.
    ///
    /// [RFC 5933]: https://tools.ietf.org/html/rfc5933
    (GOST => 3, "GOST R 34.11-94")

    /// Specifies that the SHA-384 hash function is used.
    ///
    /// Use of this hash function is described in [RFC 6605]. Implementing
    /// the function is optional.
    ///
    /// [RFC 6605]: https://tools.ietf.org/html/rfc6605
    (SHA384 => 4, "SHA-384")
}

int_enum_fromstr_decimal!(DigestAlgorithm, u8);
int_enum_display_decimal!(DigestAlgorithm, u8);
int_enum_zonefile_fmt_decimal!(DigestAlgorithm, "digest type");
// scan_impl!(DigestAlgorithm);
//
// int_enum_zonefile_fmt_decimal!(DigestAlgorithm, "digest type");
//
// // Display
// int_enum_impl_display_integer!(DigestAlgorithm);
//
// // FromStrError
// instantiate_fromstrerror_with_error_description!("unknown digest type");
//
// // serde::Serialize / serde::Deserialize
// int_enum_impl_serde_to_and_from_integer!(DigestAlgorithm, u8);
//
// // core::str::FromStr / from_bytes()
// int_enum_impl_fromstr_frombytes_from_integer!(DigestAlgorithm);

//============ Tests =========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use super::DigestAlgorithm;
        use serde_test::{assert_tokens, Token};

        assert_tokens(&DigestAlgorithm::SHA384, &[Token::U8(4)]);
        assert_tokens(&DigestAlgorithm(100), &[Token::U8(100)]);
    }
}
