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
    use std::string::String;

    use crate::base::zonefile_fmt::DisplayKind;
    use crate::base::zonefile_fmt::ZonefileFmt;

    #[track_caller]
    fn validate_generic_representation<T>(
        test_value: T,              // This value is used as desired value
        display_repr: String,       // Display MUST result in this String
        fromstr_list: &[&str], // `&[&str]` `FromStr`s MUST result in `test_value`
        zonefile_fmt_value: String, // ZonefileFmt MUST result in this String
    ) where
        T: Display + ZonefileFmt + FromStr + PartialEq + Debug,
        <T as core::str::FromStr>::Err: core::fmt::Debug,
    {
        // Display
        assert_eq!(
            display_repr,
            format!("{test_value}"),
            "Display representation"
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
    }

    #[test]
    fn validate_class_representation() {
        validate_generic_representation(
            Class::IN,
            "IN".into(),
            &["IN", "CLASS1"],
            "IN".into(),
        );
    }

    #[test]
    fn validate_digest_algorithm_representation() {
        validate_generic_representation(
            DigestAlgorithm::SHA256,
            "2".into(),
            &["2"],
            "2".into(),
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
            &["3"],
            "3".into(),
        );
    }

    #[test]
    fn validate_ipseckey_gateway_type_representation() {
        validate_generic_representation(
            IpseckeyGatewayType::NONE,
            "0".into(),
            &["0"],
            "0".into(),
        );
    }

    #[test]
    fn validate_nsec3_hash_algorithm_representation() {
        validate_generic_representation(
            Nsec3HashAlgorithm::SHA1,
            "1".into(),
            &["1"],
            "1".into(),
        );
    }

    #[test]
    fn validate_opcode_representation() {
        validate_generic_representation(
            Opcode::QUERY,
            "QUERY(0)".into(),
            &["0"],
            "QUERY".into(),
        );
    }

    #[test]
    fn validate_option_code_representation() {
        validate_generic_representation(
            OptionCode::COOKIE,
            "COOKIE(10)".into(),
            &["10"],
            "COOKIE".into(),
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
            &["23", "BADCOOKIE"],
            "BADCOOKIE".into(),
        );
    }

    #[test]
    fn validate_rtype_representation() {
        validate_generic_representation(
            Rtype::MX,
            "MX".into(),
            &["MX", "TYPE15"],
            "MX".into(),
        );
    }

    #[test]
    fn validate_security_algorithm_representation() {
        validate_generic_representation(
            SecurityAlgorithm::DELETE,
            "0".into(),
            &["0", "DELETE"],
            "0".into(),
        );
    }

    #[test]
    fn validate_sshfp_algorithm_representation() {
        validate_generic_representation(
            SshfpAlgorithm::ED25519,
            "4".into(),
            &["4"],
            "4".into(),
        );
    }

    #[test]
    fn validate_sshfp_type_representation() {
        validate_generic_representation(
            SshfpType::SHA256,
            "2".into(),
            &["2"],
            "2".into(),
        );
    }

    #[test]
    fn validate_svc_param_key_representation() {
        validate_generic_representation(
            SvcParamKey::ALPN,
            "alpn".into(),
            &["KEY1"],
            "alpn".into(),
        );
    }

    #[test]
    fn validate_tlsa_certificate_usage_representation() {
        validate_generic_representation(
            TlsaCertificateUsage::DANE_EE,
            "3".into(),
            &["3"],
            "3".into(),
        );
    }

    #[test]
    fn validate_tlsa_matching_type_representation() {
        validate_generic_representation(
            TlsaMatchingType::FULL,
            "0".into(),
            &["0"],
            "0".into(),
        );
    }

    #[test]
    fn validate_tlsa_selector_representation() {
        validate_generic_representation(
            TlsaSelector::CERT,
            "0".into(),
            &["0"],
            "0".into(),
        );
    }

    #[test]
    fn validate_zonemd_algorithm_representation() {
        validate_generic_representation(
            ZonemdAlgorithm::SHA512,
            "2".into(),
            &["2"],
            "2".into(),
        );
    }

    #[test]
    fn validate_zonemd_scheme_representation() {
        validate_generic_representation(
            ZonemdScheme::SIMPLE,
            "1".into(),
            &["1"],
            "1".into(),
        );
    }
}
