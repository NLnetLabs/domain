#![cfg(feature = "unstable-new")]
//------------ Tests --------------------------------------------------------

use std::fmt::Debug;

use domain::new::base::{OpCode, RClass, RType};

/// `test_value`: T - This is used as the desired value
/// `debug_repr`: &str - Debug MUST result in this string
#[track_caller]
fn validate_generic_representation<T>(test_value: T, debug_repr: &str)
where
    T: Debug + PartialEq,
{
    // Debug
    assert_eq!(
        debug_repr,
        format!("{test_value:?}"),
        "Debug representation"
    );
}
#[test]
fn validate_class_representation() {
    validate_generic_representation(RClass::IN, stringify!(RClass::IN));
    validate_generic_representation(RClass::new(42), "RClass(42)");
}

#[test]
fn validate_rtype_representation() {
    validate_generic_representation(RType::MX, stringify!(RType::MX));
    validate_generic_representation(RType::new(842), "RType(842)");
}

#[test]
fn validate_opcode_representation() {
    validate_generic_representation(OpCode::QUERY, stringify!(OpCode::QUERY));
    validate_generic_representation(OpCode::new(42), "OpCode(42)");
}
