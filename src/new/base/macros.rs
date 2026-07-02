//! Macros for Enum Types

/// DNS Enum Type implementation
///
/// This Macros is used to write boilerplate `match` functions which turn the
/// Self type into the mnemonic and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - get_mnemonic()
/// - from_mnemonic()
macro_rules! define_known_values {
    (
        $(#[$type_attr:meta])*
        $type:ident:: (
            $values_vis:vis $values:ident ,
            $names_vis:vis $names:ident
        ) = [ $(
            $(#[$value_attr:meta])*
            $value_name:ident = $value:expr,
        )* ];
    ) => {
        $(#[$type_attr])*
        impl $type {
            $(
                $(#[$value_attr])*
                pub const $value_name: $type = $value;
            )*
        }

        // This block writes the list called $names. Containing all defined
        // values.
        impl $type {
            /// Contains all known values of that type.
            pub const $values: &'static [Self] = &[
                $($value,)*
            ];
        }

        // This block writes the list called $names. Containing all defined
        // names.
        impl $type {
            /// Contains the associated names of the Values if exists.
            pub const $names: &'static [&'static str] = &[
                $(
                    stringify!($value_name) ,
                )*
            ];
        }

        // create conversion functions
        impl $type {
            /// Returns mnemonic representation of this type if defined.
            #[must_use]
            pub fn get_mnemonic(&self) -> Option<&'static str> {
                if let Some(pos) =
                    Self::$values.iter().position(|t| t == self)
                {
                    return Self::$names.get(pos).map(|s| *s);
                };
                None
            }

            /// Returns Self if mnemonic is recognised.
            #[must_use]
            pub fn from_mnemonic(mnemonic: &str) -> Option<Self> {
                if let Some(pos) = Self::$names
                    .iter()
                    .position(|s| mnemonic.eq_ignore_ascii_case(s))
                {
                    return Self::$values.get(pos).map(|s| *s);
                };
                None
            }
        }
    };
}
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
                let types = [
                $(
                    ($mnemonic, Self::$variant),
                )*
                ];
                for candidate in types {
                    if mnemonic.eq_ignore_ascii_case(candidate.0) {
                        return Some(candidate.1)
                    }
                }
                None
            }
        }
    }
}

/// From implementation for DNS Enum Type
///
/// This macro implements conversions from the primitive type into the enum
/// type and vice versa.
///
/// Uses existing struct with a `::new()` function to implement:
/// - fn from(value: $inttype) -> $enumtype
/// - fn from(value: $enumtype) -> $inttype
macro_rules! enum_type_from_and_to_primitive {
    ( $enumtype:ident, $inttype:ident) => {
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
