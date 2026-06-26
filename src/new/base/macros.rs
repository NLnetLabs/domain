//----------- Macros ---------------------------------------------------------
/// DNS Enum Type implementation
///
/// This Macros is used to write boilerplate `match` functions which turn the
/// Self type into the mnemonic and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - get_mnemonic()
/// - from_mnemonic()
macro_rules! enum_type{
    ( $(#[$attr:meta])* =>
      $enumtype:ident;
      $( $(#[$variant_attr:meta])*
    ( $variant:ident => $value:expr, $mnemonic:expr) )* ) => {
        // create constants
        impl $enumtype {
            $(
                $(#[$variant_attr])*
                pub const $variant: $enumtype = $enumtype::new($value);
            )*
        }

        // create conversion functions
        impl $enumtype{
            /// Returns mnemonic representation of this type if defined.
            #[must_use]
            pub fn get_mnemonic(&self) -> Option<&'static str> {
                match self {
                $(
                    &$enumtype::$variant => Some($mnemonic),
                )*
                    _ => None, // default case if mnemonic is unknown
                }
            }

            /// Returns Self if mnemonic is recognised.
            #[must_use]
            pub fn from_mnemonic(mnemonic: &str) -> Option<Self> {
                match mnemonic.to_uppercase().as_str() {
                $(
                     $mnemonic => Some($enumtype::$variant),
                )*
                    _ => None, // default case if mnemonic is unknown
                }
            }
        }
    }
}

/// From for Enum Type implementation
///
/// This macro implements conversions from the primitive type into the enum
/// type and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - fn from(value: $inttype) -> $enumtype
/// - fn from(value: $enumtype) -> $inttype
macro_rules! enum_type_from_and_to_primitive {
    ( $(#[$attr:meta])* =>
      $enumtype:ident, $inttype:ident;) => {
        //--- Conversion to and from primative
        impl From<$inttype> for $enumtype {
            fn from(value: $inttype) -> Self {
                Self::new(value)
            }
        }

        impl From<$enumtype> for $inttype {
            fn from(value: $enumtype) -> Self {
                value.code.get()
            }
        }
    };
}
