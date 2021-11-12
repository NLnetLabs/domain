//! Delegation signer digest algorithm numbers.

//------------ DigestAlg -----------------------------------------------------

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
    DigestAlg, u8;

    /// Specifies that the SHA-1 hash function is used.
    ///
    /// Implementation of this function is currently mandatory.
    (Sha1 => 1, b"SHA-1")

    /// Specifies that the SHA-256 hash function is used.
    ///
    /// Implementation of this function is currently mandatory.
    (Sha256 => 2, b"SHA-256")

    /// Specifies that the GOST R 34.11-94 hash function is used.
    ///
    /// Use of this hash function is described in [RFC 5933]. Implementing
    /// the function is optional.
    ///
    /// [RFC 5933]: https://tools.ietf.org/html/rfc5933
    (Gost => 3, b"GOST R 34.11-94")

    /// Specifies that the SHA-384 hash function is used.
    ///
    /// Use of this hash function is described in [RFC 6605]. Implementing
    /// the function is optional.
    ///
    /// [RFC 6605]: https://tools.ietf.org/html/rfc6605
    (Sha384 => 4, b"SHA-384")
}

int_enum_str_decimal!(DigestAlg, u8);

//============ Tests =========================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use super::DigestAlg;
        use serde_test::{assert_tokens, Token};

        assert_tokens(
            &DigestAlg::Sha384,
            &[Token::U8(4)],
        );
        assert_tokens(
            &DigestAlg::Int(100),
            &[Token::U8(100)],
        );
    }
}

