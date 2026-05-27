//! IANA Definitions for DNS.
//!
//! This module contains enums for parameters defined in IANA registries
//! that are relevant for this crate.
//!
//! All types defined hereunder follow the same basic structure. They are
//! all enums with all well-defined values as variants. In addition they
//! have an `Int` variant that contains a raw integer value. Since we cannot
//! restrict that integer to only the undefined values, we generally allow
//! the full set of possible values. We treat this correctly, meaning that
//! the well-defined variant and the `Int` variant with the same integer
//! value compare to equal.
//!
//! There are two methods `from_int()` and `to_int()` to convert from and
//! to raw integer values as well as implementations of the `From` trait
//! for these. `FromStr` and `Display` are implemented to convert from
//! the string codes to the values and back. All of these are essentially
//! giant matches which may or may not be the smartest way to do this.
//!
//! Types also implement `parse()` and `scan()` functions for creation from
//! wire format and representation format, respectively, as well as a
//! `compose()` method for composing into wire format data.
//!
//! While each parameter type has a module of its own, they are all
//! re-exported here. This is mostly so we can have associated types like
//! `FromStrError` without having to resort to devilishly long names.

pub use self::class::Class;
pub use self::digestalg::DigestAlgorithm;
pub use self::exterr::ExtendedErrorCode;
pub use self::ipseckey::{IpseckeyAlgorithm, IpseckeyGatewayType};
pub use self::nsec3::Nsec3HashAlgorithm;
pub use self::opcode::Opcode;
pub use self::opt::OptionCode;
pub use self::rcode::{OptRcode, Rcode, TsigRcode};
pub use self::rtype::Rtype;
pub use self::secalg::SecurityAlgorithm;
pub use self::sshfp::{SshfpAlgorithm, SshfpType};
pub use self::svcb::SvcParamKey;
pub use self::tlsa::{TlsaCertificateUsage, TlsaMatchingType, TlsaSelector};
pub use self::zonemd::{ZonemdAlgorithm, ZonemdScheme};

#[macro_use]
mod macros;

pub mod class;
pub mod digestalg;
pub mod exterr;
pub mod ipseckey;
pub mod nsec3;
pub mod opcode;
pub mod opt;
pub mod rcode;
pub mod rtype;
pub mod secalg;
pub mod sshfp;
pub mod svcb;
pub mod tlsa;
pub mod zonemd;

#[cfg(feature = "serde")]
#[cfg(test)]
mod test {
    use crate::base::iana::class::Class;
    use crate::base::iana::digestalg::DigestAlgorithm;
    // use crate::base::iana::exterr::ExtendedErrorCode;
    use crate::base::iana::ipseckey::IpseckeyAlgorithm;
    use crate::base::iana::ipseckey::IpseckeyGatewayType;
    use crate::base::iana::nsec3::Nsec3HashAlgorithm;
    use crate::base::iana::opcode::Opcode;
    use crate::base::iana::opt::OptionCode;
    // use crate::base::iana::rcode::OptRcode;
    // use crate::base::iana::rcode::Rcode;
    use crate::base::iana::rcode::TsigRcode;
    use crate::base::iana::rtype::Rtype;
    use crate::base::iana::secalg::SecurityAlgorithm;
    use crate::base::iana::sshfp::SshfpAlgorithm;
    use crate::base::iana::sshfp::SshfpType;
    use crate::base::iana::svcb::SvcParamKey;
    use crate::base::iana::tlsa::TlsaCertificateUsage;
    use crate::base::iana::tlsa::TlsaMatchingType;
    use crate::base::iana::tlsa::TlsaSelector;
    use crate::base::iana::zonemd::ZonemdAlgorithm;
    use crate::base::iana::zonemd::ZonemdScheme;

    use core::fmt::Debug;
    use core::fmt::Display;
    use core::str::FromStr;

    use crate::base::zonefile_fmt::DisplayKind;
    use crate::base::zonefile_fmt::ZonefileFmt;

    /// `test_value`: T - This is used as the desired value
    /// `display_repr`: &str - Display MUST result in this string
    /// `debug_repr`: &str - Debug MUST result in this string
    /// `fromstr_list`: &[&str] - `FromStr` MUST result in `test_value`
    /// `zonefile_fmt_value`: &str - ZonefileFmt MUST result in this string
    /// `serde_serialize_value`: &str - Serialize MUST result in this string
    #[track_caller]
    fn validate_generic_representation<T>(
        test_value: T,
        display_repr: &str,
        debug_repr: &str,
        fromstr_list: &[&str],
        zonefile_fmt_value: &str,
        serde_serialize_value: &str,
    ) where
        T: Display
            + Debug
            + FromStr
            + PartialEq
            + ZonefileFmt
            + for<'a> serde::Deserialize<'a>
            + serde::Serialize,
        <T as core::str::FromStr>::Err: core::fmt::Debug,
    {
        // Display
        assert_eq!(
            display_repr,
            format!("{test_value}"),
            "Display representation"
        );

        // Debug
        assert_eq!(
            debug_repr,
            format!("{test_value:?}"),
            "Debug representation"
        );

        for value in fromstr_list {
            // FromStr mnemonic
            assert_eq!(
                value.parse::<T>().unwrap_or_else(|_| panic!(
                    "FromStr failed with {value}"
                )),
                test_value,
                "FromStr representation"
            );
        }

        // ZonefileFmt
        let display_zonefile =
            test_value.display_zonefile(DisplayKind::Simple);
        assert_eq!(
            zonefile_fmt_value,
            format!("{display_zonefile}"),
            "ZonefileFmt representation"
        );

        // serde::Serialize
        assert_eq!(
            serde_serialize_value,
            serde_json::to_string(&test_value).unwrap(),
            "serde_json::to_string(&test_value)"
        );

        // serde::Deserialize
        let value_as_json_string =
            serde_json::to_string(&test_value).unwrap();

        assert_eq!(
            test_value,
            serde_json::from_str(&value_as_json_string).unwrap_or_else(|_|
                panic!("serde_json::from_str() failed with {value_as_json_string}")
            ),
            "serde_json::from_str(&{value_as_json_string})"
        );

        let big_number_error: Result<T, serde_json::Error> =
            serde_json::from_str(&format!("{}", u32::MAX));
        assert!(
            big_number_error.is_err(),
            "Make sure too big integer (u32::MAX) throw an error {big_number_error:?}"
        );

        // NOTE: Currently there is no testing for `is_human_reable()` = false
        // option in this function.
        // https://docs.rs/serde/latest/serde/trait.Serializer.html#method.is_human_readable
    }

    #[test]
    fn validate_class_representation() {
        validate_generic_representation(
            Class::IN,
            "IN",
            "Class::IN",
            &["IN", "CLASS1"],
            "IN",
            r#""IN""#,
        );
        validate_generic_representation(
            Class::from_int(42),
            "CLASS42",
            "Class(42)",
            &["CLASS42"],
            "CLASS42",
            r#""CLASS42""#,
        );
    }

    #[test]
    fn validate_digest_algorithm_representation() {
        validate_generic_representation(
            DigestAlgorithm::SHA256,
            "2",
            "DigestAlgorithm::SHA-256",
            &["2"],
            "2",
            r#"2"#,
        );
        validate_generic_representation(
            DigestAlgorithm::from_int(42),
            "42",
            "DigestAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn validate_extended_error_code_representation() {
        todo!()
    }

    #[test]
    fn validate_ipseckey_algorithm_representation() {
        validate_generic_representation(
            IpseckeyAlgorithm::ECDSA,
            "3",
            "IpseckeyAlgorithm::ECDSA",
            &["3"], // not "ECDSA"
            "3",
            r#"3"#,
        );
        validate_generic_representation(
            IpseckeyAlgorithm::from_int(42),
            "42",
            "IpseckeyAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_ipseckey_gateway_type_representation() {
        validate_generic_representation(
            IpseckeyGatewayType::NONE,
            "0",
            "IpseckeyGatewayType::NONE",
            &["0"], // not "NONE"
            "0",
            r#"0"#,
        );
        validate_generic_representation(
            IpseckeyGatewayType::from_int(42),
            "42",
            "IpseckeyGatewayType(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_nsec3_hash_algorithm_representation() {
        validate_generic_representation(
            Nsec3HashAlgorithm::SHA1,
            "1",
            "Nsec3HashAlgorithm::SHA-1",
            &["1"], // "SHA-1"
            "1",
            r#"1"#,
        );
        validate_generic_representation(
            Nsec3HashAlgorithm::from_int(42),
            "42",
            "Nsec3HashAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_opcode_representation() {
        validate_generic_representation(
            Opcode::QUERY,
            "QUERY(0)",
            "Opcode::QUERY",
            &["QUERY", "0"],
            "QUERY",
            r#""QUERY""#,
        );
        validate_generic_representation(
            Opcode::from_int(42),
            "42",
            "Opcode(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_option_code_representation() {
        validate_generic_representation(
            OptionCode::COOKIE,
            "COOKIE(10)",
            "OptionCode::COOKIE",
            &["COOKIE", "10"],
            "COOKIE",
            r#""COOKIE""#,
        );
        validate_generic_representation(
            OptionCode::from_int(42),
            "42",
            "OptionCode(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn validate_opt_rcode_representation() {
        todo!()
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn validate_rcode_representation() {
        todo!()
    }

    #[test]
    fn validate_tsig_rcode_representation() {
        validate_generic_representation(
            TsigRcode::BADCOOKIE,
            "BADCOOKIE(23)",
            "TsigRcode::BADCOOKIE",
            &["23", "BADCOOKIE"],
            "BADCOOKIE",
            r#""BADCOOKIE""#,
        );
        validate_generic_representation(
            TsigRcode::from_int(42),
            "42",
            "TsigRcode(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_rtype_representation() {
        validate_generic_representation(
            Rtype::MX,
            "MX",
            "Rtype::MX",
            &["MX", "TYPE15"],
            "MX",
            r#""MX""#,
        );
        validate_generic_representation(
            Rtype::from_int(842),
            "TYPE842",
            "Rtype(842)",
            &["TYPE842"],
            "TYPE842",
            r#""TYPE842""#,
        );
    }

    #[test]
    fn validate_security_algorithm_representation() {
        validate_generic_representation(
            SecurityAlgorithm::DELETE,
            "0",
            "SecurityAlgorithm::DELETE",
            &["0"], // not "DELETE"
            "0",
            r#"0"#,
        );
        validate_generic_representation(
            SecurityAlgorithm::from_int(42),
            "42",
            "SecurityAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_sshfp_algorithm_representation() {
        validate_generic_representation(
            SshfpAlgorithm::ED25519,
            "4",
            "SshfpAlgorithm::Ed25519",
            &["4"],
            "4",
            r#"4"#,
        );
        validate_generic_representation(
            SshfpAlgorithm::from_int(42),
            "42",
            "SshfpAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_sshfp_type_representation() {
        validate_generic_representation(
            SshfpType::SHA256,
            "2",
            "SshfpType::SHA-256",
            &["2"],
            "2",
            r#"2"#,
        );
        validate_generic_representation(
            SshfpType::from_int(42),
            "42",
            "SshfpType(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_svc_param_key_representation() {
        validate_generic_representation(
            SvcParamKey::ALPN,
            "alpn",
            "SvcParamKey::alpn",
            &["alpn", "KEY1"],
            "alpn",
            r#""alpn""#,
        );
        validate_generic_representation(
            SvcParamKey::from_int(42),
            "key42",
            "SvcParamKey(42)",
            &["KEY42"],
            "key42",
            r#""key42""#,
        );
    }

    #[test]
    fn validate_tlsa_certificate_usage_representation() {
        validate_generic_representation(
            TlsaCertificateUsage::DANE_EE,
            "3",
            "TlsaCertificateUsage::DANE-EE",
            &["3"],
            "3",
            r#"3"#,
        );
        validate_generic_representation(
            TlsaCertificateUsage::from_int(42),
            "42",
            "TlsaCertificateUsage(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_tlsa_matching_type_representation() {
        validate_generic_representation(
            TlsaMatchingType::FULL,
            "0",
            "TlsaMatchingType::Full",
            &["0"],
            "0",
            r#"0"#,
        );
        validate_generic_representation(
            TlsaMatchingType::from_int(42),
            "42",
            "TlsaMatchingType(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_tlsa_selector_representation() {
        validate_generic_representation(
            TlsaSelector::CERT,
            "0",
            "TlsaSelector::Cert",
            &["0"],
            "0",
            r#"0"#,
        );
        validate_generic_representation(
            TlsaSelector::from_int(42),
            "42",
            "TlsaSelector(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_zonemd_algorithm_representation() {
        validate_generic_representation(
            ZonemdAlgorithm::SHA512,
            "2",
            "ZonemdAlgorithm::SHA512",
            &["2"],
            "2",
            "2",
        );
        validate_generic_representation(
            ZonemdAlgorithm::from_int(42),
            "42",
            "ZonemdAlgorithm(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }

    #[test]
    fn validate_zonemd_scheme_representation() {
        validate_generic_representation(
            ZonemdScheme::SIMPLE,
            "1",
            "ZonemdScheme::SIMPLE",
            &["1"],
            "1",
            "1",
        );
        validate_generic_representation(
            ZonemdScheme::from_int(42),
            "42",
            "ZonemdScheme(42)",
            &["42"],
            "42",
            r#"42"#,
        );
    }
}
