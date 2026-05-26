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
//!

// TODO; This is an example.
//! ## Representation of Variables
//!
//! The following table defines the output of for the variables in this module.
//! ### Type [`SecurityAlgorithm`]
//!
//! * [`Display`] returns mnemonic ("0")
//! * [`FromStr`] parses text with number or mnemonic ("0", "DELETE")
//! * [`ZonefileFmt`] returns text number ("0")
//! * [`serde::Serialize`] returns number (5)
//! * [`serde::Deserialize`] reads mnemonic ("RSASHA1") or number (5)
// ----- Aliases
//!
//! [`ZonefileFmt`]: crate::base::zonefile_fmt::ZonefileFmt
//! [`FromStr`]: core::str::FromStr
//! [`Display`]: std::fmt::Display

pub use self::class::Class;
pub use self::digestalg::DigestAlgorithm;
pub use self::exterr::ExtendedErrorCode;
pub use self::ipseckey::{IpseckeyAlgorithm, IpseckeyGatewayType};
pub use self::macros::IanaEnum;
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

    // TODO: REMOVE
    use crate::base::iana::macros::JannisTestEnum1;
    use crate::base::iana::macros::JannisTestEnum2;
    use crate::base::iana::macros::JannisTestEnum3;
    use crate::base::iana::macros::JannisTestEnum4;

    use core::fmt::Debug;
    use core::fmt::Display;
    use core::str::FromStr;
    use std::string::String;

    use crate::base::zonefile_fmt::DisplayKind;
    use crate::base::zonefile_fmt::ZonefileFmt;

    #[track_caller]
    fn validate_generic_representation<T>(
        test_value: T,              // This value is used as desired value
        display_repr: String,       // Display MUST result in this String
        debug_repr: String,         // Debug MUST result in this String
        fromstr_list: &[&str], // `&[&str]` `FromStr`s MUST result in `test_value`
        zonefile_fmt_value: String, // ZonefileFmt MUST result in this String
        serde_serialize_value: String, // ZonefileFmt MUST result in this String
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
        println!("assert fmt::Display");
        assert_eq!(
            display_repr,
            format!("{test_value}"),
            "Display representation"
        );

        // Debug
        println!("assert fmt::Debug");
        assert_eq!(
            debug_repr,
            format!("{test_value:?}"),
            "Debug representation"
        );

        for value in fromstr_list {
            // FromStr mnemonic
            println!("assert FromStr with {}", value);
            assert_eq!(
                value.parse::<T>().unwrap_or_else(|_| panic!(
                    "FromStr failed with {value}"
                )),
                test_value,
                "FromStr representation"
            );
        }

        // ZonefileFmt
        println!("assert ZonefileFmt");
        let display_zonefile =
            test_value.display_zonefile(DisplayKind::Simple);
        assert_eq!(
            zonefile_fmt_value,
            format!("{display_zonefile}"),
            "ZonefileFmt representation"
        );

        // serde::Serialize
        println!("assert Serialize");
        assert_eq!(
            serde_serialize_value,
            serde_json::to_string(&test_value).unwrap(),
            "serde_json::to_string(&test_value)"
        );

        // serde::Deserialize
        let value_as_json_string =
            serde_json::to_string(&test_value).unwrap();

        println!("assert Deserialize from #{}#", value_as_json_string);
        assert_eq!(
            test_value,
            serde_json::from_str(&value_as_json_string).unwrap(),
            "serde_json::from_str(&value_as_json_string)"
        );

        // TODO: Missing is the non-human-readable testing of serde!
    }

    #[test]
    fn validate_jannis1_representation() {
        validate_generic_representation(
            JannisTestEnum1::A,
            "0".into(),
            "JannisTestEnum1::A".into(),
            &["0"],
            "0".into(),
            r#"0"#.into(),
        );
        validate_generic_representation(
            JannisTestEnum1::from_int(42),
            "42".into(),
            "JannisTestEnum1(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
        // use serde_test::{assert_tokens, Configure, Token};
        // assert_tokens(&JannisTestEnum1::A.readable(), &[Token::Str("A")]);
        // assert_tokens(&JannisTestEnum1::from_int(42).readable(), &[Token::U8(42)]);
        //
        // assert_tokens(&JannisTestEnum1::A.compact(), &[Token::U8(0)]);
        // assert_tokens(&JannisTestEnum1::from_int(42).compact(), &[Token::U8(42)]);
    }

    #[test]
    fn validate_jannis2_representation() {
        validate_generic_representation(
            JannisTestEnum2::A,
            "A".into(),
            "JannisTestEnum2::A".into(),
            &["A", "J0"],
            "A".into(),
            r#""A""#.into(),
        );
        validate_generic_representation(
            JannisTestEnum2::from_int(42),
            "J42".into(),
            "JannisTestEnum2(42)".into(),
            &["J42"],
            "J42".into(),
            r#""J42""#.into(),
        );
    }

    #[test]
    fn validate_jannis3_representation() {
        validate_generic_representation(
            JannisTestEnum3::A,
            "A(0)".into(),
            "JannisTestEnum3::A".into(),
            &["A", "0"],
            "A".into(),
            r#""A""#.into(),
        );
        validate_generic_representation(
            JannisTestEnum3::from_int(42),
            "42".into(),
            "JannisTestEnum3(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_jannis4_representation() {
        validate_generic_representation(
            JannisTestEnum4::A,
            "A(0)".into(),
            "JannisTestEnum4::A".into(),
            &["0"],
            "0".into(),
            r#"0"#.into(),
        );
        validate_generic_representation(
            JannisTestEnum4::from_int(42),
            "42".into(),
            "JannisTestEnum4(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }
    #[test]
    fn validate_class_representation() {
        validate_generic_representation(
            Class::IN,
            "IN".into(),
            "Class::IN".into(),
            &["IN", "CLASS1"],
            "IN".into(),
            r#""IN""#.into(),
        );
        validate_generic_representation(
            Class::from_int(42),
            "CLASS42".into(),
            "Class(42)".into(),
            &["CLASS42"],
            "CLASS42".into(),
            r#""CLASS42""#.into(),
        );
    }

    #[test]
    fn validate_digest_algorithm_representation() {
        validate_generic_representation(
            DigestAlgorithm::SHA256,
            "2".into(),
            "DigestAlgorithm::SHA-256".into(),
            &["2"],
            "2".into(),
            r#"2"#.into(),
        );
        validate_generic_representation(
            DigestAlgorithm::from_int(42),
            "42".into(),
            "DigestAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
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
            "3".into(),
            "IpseckeyAlgorithm::ECDSA".into(),
            &["3", "ECDSA"],
            "3".into(),
            r#"3"#.into(),
        );
        validate_generic_representation(
            IpseckeyAlgorithm::from_int(42),
            "42".into(),
            "IpseckeyAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_ipseckey_gateway_type_representation() {
        validate_generic_representation(
            IpseckeyGatewayType::NONE,
            "0".into(),
            "IpseckeyGatewayType::NONE".into(),
            &["0", "NONE"],
            "0".into(),
            r#"0"#.into(),
        );
        validate_generic_representation(
            IpseckeyGatewayType::from_int(42),
            "42".into(),
            "IpseckeyGatewayType(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_nsec3_hash_algorithm_representation() {
        validate_generic_representation(
            Nsec3HashAlgorithm::SHA1,
            "1".into(),
            "Nsec3HashAlgorithm::SHA-1".into(),
            &["1", "SHA-1"],
            "1".into(),
            r#"1"#.into(),
        );
        validate_generic_representation(
            Nsec3HashAlgorithm::from_int(42),
            "42".into(),
            "Nsec3HashAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_opcode_representation() {
        validate_generic_representation(
            Opcode::QUERY,
            "QUERY(0)".into(),
            "Opcode::QUERY".into(),
            &["QUERY", "0"],
            "QUERY".into(),
            r#""QUERY""#.into(),
        );
        validate_generic_representation(
            Opcode::from_int(42),
            "42".into(),
            "Opcode(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_option_code_representation() {
        validate_generic_representation(
            OptionCode::COOKIE,
            "COOKIE(10)".into(),
            "OptionCode::COOKIE".into(),
            &["COOKIE", "10"],
            "COOKIE".into(),
            r#""COOKIE""#.into(),
        );
        validate_generic_representation(
            OptionCode::from_int(42),
            "42".into(),
            "OptionCode(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
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
            "BADCOOKIE(23)".into(),
            "TsigRcode::BADCOOKIE".into(),
            &["23", "BADCOOKIE"],
            "BADCOOKIE".into(),
            r#""BADCOOKIE""#.into(),
        );
        validate_generic_representation(
            TsigRcode::from_int(42),
            "42".into(),
            "TsigRcode(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_rtype_representation() {
        validate_generic_representation(
            Rtype::MX,
            "MX".into(),
            "Rtype::MX".into(),
            &["MX", "TYPE15"],
            "MX".into(),
            r#""MX""#.into(),
        );
        validate_generic_representation(
            Rtype::from_int(842),
            "TYPE842".into(),
            "Rtype(842)".into(),
            &["TYPE842"],
            "TYPE842".into(),
            r#""TYPE842""#.into(),
        );
    }

    #[test]
    fn validate_security_algorithm_representation() {
        validate_generic_representation(
            SecurityAlgorithm::DELETE,
            "DELETE(0)".into(),
            "SecurityAlgorithm::DELETE".into(),
            &["0", "DELETE"], // SPECIAL, read from mnemonic and int
            "0".into(),       // ...but print as integer
            r#"0"#.into(),
        );
        validate_generic_representation(
            SecurityAlgorithm::from_int(42),
            "42".into(),
            "SecurityAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_sshfp_algorithm_representation() {
        validate_generic_representation(
            SshfpAlgorithm::ED25519,
            "4".into(),
            "SshfpAlgorithm::Ed25519".into(),
            &["4"],
            "4".into(),
            r#"4"#.into(),
        );
        validate_generic_representation(
            SshfpAlgorithm::from_int(42),
            "42".into(),
            "SshfpAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_sshfp_type_representation() {
        validate_generic_representation(
            SshfpType::SHA256,
            "2".into(),
            "SshfpType::SHA-256".into(),
            &["2"],
            "2".into(),
            r#"2"#.into(),
        );
        validate_generic_representation(
            SshfpType::from_int(42),
            "42".into(),
            "SshfpType(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_svc_param_key_representation() {
        validate_generic_representation(
            SvcParamKey::ALPN,
            "alpn".into(),
            "SvcParamKey::alpn".into(),
            &["alpn", "KEY1"],
            "alpn".into(),
            r#""alpn""#.into(),
        );
        validate_generic_representation(
            SvcParamKey::from_int(42),
            "key42".into(),
            "SvcParamKey(42)".into(),
            &["KEY42"],
            "key42".into(),
            r#""key42""#.into(),
        );
    }

    #[test]
    fn validate_tlsa_certificate_usage_representation() {
        validate_generic_representation(
            TlsaCertificateUsage::DANE_EE,
            "3".into(),
            "TlsaCertificateUsage::DANE-EE".into(),
            &["3"],
            "3".into(),
            r#"3"#.into(),
        );
        validate_generic_representation(
            TlsaCertificateUsage::from_int(42),
            "42".into(),
            "TlsaCertificateUsage(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_tlsa_matching_type_representation() {
        validate_generic_representation(
            TlsaMatchingType::FULL,
            "0".into(),
            "TlsaMatchingType::Full".into(),
            &["0"],
            "0".into(),
            r#"0"#.into(),
        );
        validate_generic_representation(
            TlsaMatchingType::from_int(42),
            "42".into(),
            "TlsaMatchingType(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_tlsa_selector_representation() {
        validate_generic_representation(
            TlsaSelector::CERT,
            "0".into(),
            "TlsaSelector::Cert".into(),
            &["0"],
            "0".into(),
            r#"0"#.into(),
        );
        validate_generic_representation(
            TlsaSelector::from_int(42),
            "42".into(),
            "TlsaSelector(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_zonemd_algorithm_representation() {
        validate_generic_representation(
            ZonemdAlgorithm::SHA512,
            "2".into(),
            "ZonemdAlgorithm::SHA512".into(),
            &["2"],
            "2".into(),
            "2".into(),
        );
        validate_generic_representation(
            ZonemdAlgorithm::from_int(42),
            "42".into(),
            "ZonemdAlgorithm(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }

    #[test]
    fn validate_zonemd_scheme_representation() {
        validate_generic_representation(
            ZonemdScheme::SIMPLE,
            "1".into(),
            "ZonemdScheme::SIMPLE".into(),
            &["1"],
            "1".into(),
            "1".into(),
        );
        validate_generic_representation(
            ZonemdScheme::from_int(42),
            "42".into(),
            "ZonemdScheme(42)".into(),
            &["42"],
            "42".into(),
            r#"42"#.into(),
        );
    }
}
