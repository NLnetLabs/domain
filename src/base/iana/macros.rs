//! Macros making implementing IANA types easier.

/// Creates a standard IANA type wrapping an integer.
///
/// This adds impls for `From`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, and
/// `Hash`.
///
/// For `FromStr` and `Display`, see one of the other macros in this module.
macro_rules! int_enum {
    ( $(#[$attr:meta])* =>
      $ianatype:ident, $inttype:path;
      $( $(#[$variant_attr:meta])* ( $variant:ident =>
                                        $value:expr, $mnemonic:expr) )* ) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
        pub struct $ianatype($inttype);

        impl $ianatype {
            $(
                $(#[$variant_attr])*
                pub const $variant: $ianatype = $ianatype($value);
            )*
        }

        impl $ianatype {
            /// Returns a value from its raw integer value.
            #[must_use]
            pub const fn from_int(value: $inttype) -> Self {
                Self(value)
            }

            /// Returns the raw integer value for a value.
            #[must_use]
            pub const fn to_int(self) -> $inttype {
                self.0
            }

            /// Returns a value from a well-defined mnemonic.
            #[must_use]
            pub fn from_mnemonic(m: &[u8]) -> Option<Self> {
                $(
                    if m.eq_ignore_ascii_case($mnemonic.as_bytes()) {
                        return Some($ianatype::$variant)
                    }
                )*
                None
            }

            /// Returns the mnemonic for this value if there is one.
            ///
            /// This will also return a mnemonic if a well-defined variant
            /// is hidden in a `Int` variant.
            #[must_use]
            pub const fn to_mnemonic(self) -> Option<&'static [u8]> {
                match self.to_mnemonic_str() {
                    Some(m) => Some(m.as_bytes()),
                    None => None,
                }
            }

            /// Returns the mnemonic as a `&str` for this value if there is one
            pub const fn to_mnemonic_str(self) -> Option<&'static str> {
                match self {
                    $(
                        $ianatype::$variant => {
                            Some($mnemonic)
                        }
                    )*
                    _ => None
                }
            }

            pub fn parse<'a, Octs: AsRef<[u8]> + ?Sized> (
                parser: &mut octseq::parse::Parser<'a, Octs>
            ) -> Result<Self, $crate::base::wire::ParseError> {
                <$inttype as $crate::base::wire::Parse<'a, Octs>>::parse(
                    parser
                ).map(Self::from_int)
            }

            pub const COMPOSE_LEN: u16 =
                <$inttype as $crate::base::wire::Compose>::COMPOSE_LEN;

            pub fn compose<Target: octseq::builder::OctetsBuilder + ?Sized>(
                &self,
                target: &mut Target
            ) -> Result<(), Target::AppendError> {
                $crate::base::wire::Compose::compose(&self.to_int(), target)
            }
        }


        //--- From

        impl From<$inttype> for $ianatype {
            fn from(value: $inttype) -> Self {
                $ianatype::from_int(value)
            }
        }

        impl From<$ianatype> for $inttype {
            fn from(value: $ianatype) -> Self {
                value.to_int()
            }
        }

        impl<'a> From<&'a $ianatype> for $inttype {
            fn from(value: &'a $ianatype) -> Self {
                value.to_int()
            }
        }

        //--- Debug

        impl core::fmt::Debug for $ianatype {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.to_mnemonic().and_then(|bytes| {
                    core::str::from_utf8(bytes).ok()
                }) {
                    Some(mnemonic) => {
                        write!(
                            f,
                            concat!(stringify!($ianatype), "::{}"),
                            mnemonic
                        )
                    }
                    None => {
                        f.debug_tuple(stringify!($ianatype))
                            .field(&self.0)
                            .finish()
                    }
                }
            }
        }
    }
}

/*
/// Adds impls for `FromStr` and `Display` to the type given as first argument.
///
/// The `FromStr` impl matches only well known mnemonics ignoring case,
/// otherwise it returns an error of the second argument.
///
/// For `Display`, it will display a decimal number for values without
/// mnemonic.
macro_rules! int_enum_str_mnemonics_only {
    ($ianatype:ident, $error:expr) => {
        impl ::std::str::FromStr for $ianatype {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                $ianatype::from_mnemonic(s.as_bytes()).ok_or(FromStrError)
            }
        }

        impl ::std::fmt::Display for $ianatype {
            fn fmt(&self, f: &mut ::std::fmt::Formatter)
                   -> ::std::fmt::Result {
                use ::std::fmt::Write;

                match self.to_mnemonic() {
                    Some(m) => {
                        for ch in m {
                            f.write_char(*ch as char)?
                        }
                        Ok(())
                    }
                    None => {
                        write!(f, "{}", self.to_int())
                    }
                }
            }
        }

        from_str_error!($error);
    }
}
*/

/// Adds impls for `FromStr` and `Display` to the type given as first argument.
///
/// For `FromStr`, recognizes only the decimal values. For `Display`, it will
/// only print the decimal values.
///
/// If the `serde` feature is enabled, also adds implementation for
/// `Serialize` and `Deserialize`, serializing values as their decimal values.
macro_rules! int_enum_fromstr_decimal {
    ($ianatype:ident, $inttype:ident) => {
        impl $ianatype {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                core::str::from_utf8(bytes)
                    .ok()
                    .and_then(|r| r.parse().ok().map($ianatype::from_int))
            }
        }

        impl core::str::FromStr for $ianatype {
            type Err = core::num::ParseIntError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                s.parse().map($ianatype::from_int)
            }
        }

        scan_impl!($ianatype);

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ianatype {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                $inttype::deserialize(deserializer).map(Into::into)
            }
        }
    };
}

macro_rules! int_enum_display_decimal {
    ($ianatype:ident, $inttype:ident) => {
        impl core::fmt::Display for $ianatype {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                write!(f, "{}", self.to_int())
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $ianatype {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                self.to_int().serialize(serializer)
            }
        }
    };
}

/// Adds impls for `FromStr` and `Display` to the type given as first argument.
///
/// For `FromStr`, recognizes all mnemonics case-insensitively as well as a
/// decimal number representing any value.
///
/// For `Display`, it will display a decimal number for values without
/// mnemonic.
///
/// If the `serde` feature is enabled, also adds implementation for
/// `Serialize` and `Deserialize`. Values will be serialized using the
/// mnemonic if availbale or otherwise the integer value for human readable
/// formats and the integer value for compact formats. Both mnemonics and
/// integer values can be deserialized.
macro_rules! int_enum_fromstr_mnemonic {
    ($ianatype:ident, $inttype:ident, $error:expr) => {
        impl $ianatype {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                $ianatype::from_mnemonic(bytes).or_else(|| {
                    core::str::from_utf8(bytes)
                        .ok()
                        .and_then(|r| r.parse().ok().map($ianatype::from_int))
                })
            }
        }

        impl core::str::FromStr for $ianatype {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                match $ianatype::from_mnemonic(s.as_bytes()) {
                    Some(res) => Ok(res),
                    None => {
                        if let Ok(res) = s.parse() {
                            Ok($ianatype::from_int(res))
                        } else {
                            Err(FromStrError(()))
                        }
                    }
                }
            }
        }

        scan_impl!($ianatype);

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ianatype {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use crate::base::serde::DeserializeNativeOrStr;

                $inttype::deserialize_native_or_str(deserializer)
            }
        }

        from_str_error!($error);
    };
}

macro_rules! int_enum_display_mnemonic {
    ($ianatype:ident, $inttype:ident, $error:expr) => {
        impl core::fmt::Display for $ianatype {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => {
                        write!(f, "{m}({})", self.to_int())
                    }
                    None => {
                        write!(f, "{}", self.to_int())
                    }
                }
            }
        }

        #[cfg(feature = "serde")]
        impl serde::Serialize for $ianatype {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    match self
                        .to_mnemonic()
                        .and_then(|value| core::str::from_utf8(value).ok())
                    {
                        Some(value) => value.serialize(serializer),
                        None => self.to_int().serialize(serializer),
                    }
                } else {
                    self.to_int().serialize(serializer)
                }
            }
        }
    };
}

/// Adds impls for `FromStr` and `Display` to the type given as first argument.
///
/// For `FromStr` recognizes all defined mnemonics ignoring case. Additionally
/// recognizes a value starting with the prefix given in the second argument
/// (again, ignoring case) directly followed by a decimal number.
///
/// For `Display`, values without mnemonic will be written starting with the
/// prefix directly followed by the decimal representation of the value.
macro_rules! int_enum_str_with_prefix {
    ($ianatype:ident, $str_prefix:expr, $u8_prefix:expr, $inttype:ident,
     $error:expr) => {
        impl $ianatype {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                $ianatype::from_mnemonic(bytes).or_else(|| {
                    if bytes.len() <= $u8_prefix.len() {
                        return None;
                    }
                    let (l, r) = bytes.split_at($u8_prefix.len());
                    if !l.eq_ignore_ascii_case($u8_prefix) {
                        return None;
                    }
                    let r = match core::str::from_utf8(r) {
                        Ok(r) => r,
                        Err(_) => return None,
                    };
                    r.parse().ok().map($ianatype::from_int)
                })
            }
        }

        impl core::str::FromStr for $ianatype {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                match $ianatype::from_mnemonic(s.as_bytes()) {
                    Some(res) => Ok(res),
                    None => {
                        if let Some((n, _)) =
                            s.char_indices().nth($str_prefix.len())
                        {
                            let (l, r) = s.split_at(n);
                            if l.eq_ignore_ascii_case($str_prefix) {
                                let value = match r.parse() {
                                    Ok(x) => x,
                                    Err(..) => return Err(FromStrError(())),
                                };
                                Ok($ianatype::from_int(value))
                            } else {
                                Err(FromStrError(()))
                            }
                        } else {
                            Err(FromStrError(()))
                        }
                    }
                }
            }
        }

        impl core::fmt::Display for $ianatype {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => f.write_str(m),
                    None => {
                        write!(f, "{}{}", $str_prefix, self.to_int())
                    }
                }
            }
        }

        scan_impl!($ianatype);

        #[cfg(feature = "serde")]
        impl serde::Serialize for $ianatype {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.collect_str(&format_args!("{}", self))
                } else {
                    self.to_int().serialize(serializer)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ianatype {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use crate::base::serde::DeserializeNativeOrStr;

                $inttype::deserialize_native_or_str(deserializer)
            }
        }

        from_str_error!($error);
    };
}

macro_rules! int_enum_zonefile_fmt_decimal {
    ($ianatype:ident, $name:expr) => {
        impl $crate::base::zonefile_fmt::ZonefileFmt for $ianatype {
            fn fmt(
                &self,
                p: &mut impl $crate::base::zonefile_fmt::Formatter,
            ) -> $crate::base::zonefile_fmt::Result {
                p.write_token(self.to_int())?;
                if let Some(mnemonic) = self.to_mnemonic_str() {
                    p.write_comment(format_args!("{}: {}", $name, mnemonic))
                } else {
                    p.write_comment($name)
                }
            }
        }
    };
}

macro_rules! int_enum_zonefile_fmt_with_decimal {
    ($ianatype:ident) => {
        impl $crate::base::zonefile_fmt::ZonefileFmt for $ianatype {
            fn fmt(
                &self,
                p: &mut impl $crate::base::zonefile_fmt::Formatter,
            ) -> $crate::base::zonefile_fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => p.write_token(m),
                    None => p.write_token(self.to_int()),
                }
            }
        }
    };
}

macro_rules! int_enum_zonefile_fmt_with_prefix {
    ($ianatype:ident, $str_prefix:expr) => {
        impl $crate::base::zonefile_fmt::ZonefileFmt for $ianatype {
            fn fmt(
                &self,
                p: &mut impl $crate::base::zonefile_fmt::Formatter,
            ) -> $crate::base::zonefile_fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => p.write_token(m),
                    None => p.write_token(format_args!(
                        "{}{}",
                        $str_prefix,
                        self.to_int()
                    )),
                }
            }
        }
    };
}

macro_rules! scan_impl {
    ($ianatype:ident) => {
        impl $ianatype {
            pub fn scan<S: $crate::base::scan::Scanner>(
                scanner: &mut S,
            ) -> Result<Self, S::Error> {
                scanner.scan_ascii_str(|s| {
                    core::str::FromStr::from_str(s).map_err(|_| {
                        $crate::base::scan::ScannerError::custom(concat!(
                            "expected ",
                            stringify!($ianatype)
                        ))
                    })
                })
            }
        }
    };
}

macro_rules! from_str_error {
    ($description:expr) => {
        #[derive(Clone, Debug)]
        pub struct FromStrError(());

        impl core::error::Error for FromStrError {
            fn description(&self) -> &str {
                $description
            }
        }

        impl core::fmt::Display for FromStrError {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                $description.fmt(f)
            }
        }
    };
}

// --- TODO: NEW VERSION, FINISH IT!

/// --- FromStrError ---
/// This macro defines a new struct which is used as an error type in
/// core::str::FromStr. The description is used to std::fmt::Display the
/// error.
macro_rules! instantiate_fromstrerror_with_error_description {
    ($error_description:expr) => {
        #[derive(Clone, Debug)]
        pub struct FromStrError(());

        impl core::error::Error for FromStrError {
            fn description(&self) -> &str {
                $error_description
            }
        }

        impl core::fmt::Display for FromStrError {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                $error_description.fmt(f)
            }
        }
    };
}
// ---

/// --- FromBytes / FromStr --- COMBINATION VERSION
/// This macro implements core::str::FromStr and the function from_bytes(). It
/// tries to parse the bytes as mnemonic first and falls back to parsing it as
/// an integer if that is not possible.
macro_rules! int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer {
    ($enum_type:ident) => {
        impl $enum_type {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                $enum_type::from_mnemonic(bytes).or_else(|| {
                    core::str::from_utf8(bytes).ok().and_then(|r| {
                        r.parse().ok().map($enum_type::from_int)
                    })
                })
            }
        }

        impl core::str::FromStr for $enum_type {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                match $enum_type::from_mnemonic(s.as_bytes()) {
                    Some(res) => Ok(res),
                    None => {
                        if let Ok(res) = s.parse() {
                            Ok($enum_type::from_int(res))
                        } else {
                            Err(FromStrError(()))
                        }
                    }
                }
            }
        }
    };
}
// ---
//
/// --- FromBytes / FromStr --- INTEGER VERSION
/// This macro implements core::str::FromStr and the function from_bytes(). It
/// parses the value from the integer associated with it.
macro_rules! int_enum_impl_fromstr_frombytes_from_integer {
    ($enum_type:ident) => {
        impl $enum_type {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                $enum_type::from_mnemonic(bytes).or_else(|| {
                    core::str::from_utf8(bytes).ok().and_then(|r| {
                        r.parse().ok().map($enum_type::from_int)
                    })
                })
            }
        }

        impl core::str::FromStr for $enum_type {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                match $enum_type::from_mnemonic(s.as_bytes()) {
                    Some(res) => Ok(res),
                    None => {
                        if let Ok(res) = s.parse() {
                            Ok($enum_type::from_int(res))
                        } else {
                            Err(FromStrError(()))
                        }
                    }
                }
            }
        }
    };
}
// ---

/// --- FromBytes / FromStr --- PREFIX VERSION
/// This macro implements core::str::FromStr and the function from_bytes(). It
/// tries to parse the bytes as mnemonic first and falls back to parsing it as
/// an integer with a specific prefix if that is not possible.
macro_rules! int_enum_impl_fromstr_frombytes_from_mnemonics_or_prefix {
    ($enum_type:ident, $str_prefix:expr, $prefix_bytes:expr) => {
        impl $enum_type {
            #[must_use]
            pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
                $enum_type::from_mnemonic(bytes).or_else(|| {
                    if bytes.len() <= $prefix_bytes.len() {
                        return None;
                    }
                    let (l, r) = bytes.split_at($prefix_bytes.len());
                    if !l.eq_ignore_ascii_case($prefix_bytes) {
                        return None;
                    }
                    let r = match core::str::from_utf8(r) {
                        Ok(r) => r,
                        Err(_) => return None,
                    };
                    r.parse().ok().map($enum_type::from_int)
                })
            }
        }

        impl core::str::FromStr for $enum_type {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                // We assume all mnemonics are always ASCII, so using
                // the bytes representation of `s` is safe.
                match $enum_type::from_mnemonic(s.as_bytes()) {
                    Some(res) => Ok(res),
                    None => {
                        if let Some((n, _)) =
                            s.char_indices().nth($str_prefix.len())
                        {
                            let (l, r) = s.split_at(n);
                            if l.eq_ignore_ascii_case($str_prefix) {
                                let value = match r.parse() {
                                    Ok(x) => x,
                                    Err(..) => return Err(FromStrError(())),
                                };
                                Ok($enum_type::from_int(value))
                            } else {
                                Err(FromStrError(()))
                            }
                        } else {
                            Err(FromStrError(()))
                        }
                    }
                }
            }
        }
    };
}
// ---

/// --- Display --- COMBINATION VERSION
/// This macro implements std::fmt::Display. If the value has a mnemonic it
/// formats the string as "<mnemonic>(<integer>)" including the interger in
/// parenthesis. If the value does not have a mnemonic it falls back to the
/// integer and formats the String as "<integer>".
macro_rules! int_enum_impl_display_mnemonics_with_integer_fallback_integer {
    ($enum_type:ident) => {
        impl std::fmt::Display for $enum_type {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => {
                        write!(f, "{m}({})", self.to_int())
                    }
                    None => {
                        write!(f, "{}", self.to_int())
                    }
                }
            }
        }
    };
}
// ---

/// --- Display --- MNEMONIC PREFIX VERSION
/// This macro implements std::fmt::Display. If the value has a mnemonic it
/// formats the string as "<mnemonic>". If the value does not have a mnemonic
/// it falls back to the integer and formats the String as "<integer>".
macro_rules! int_enum_impl_display_mnemonics_fallback_prefix_integer {
    ($enum_type:ident, $prefix:expr) => {
        impl std::fmt::Display for $enum_type {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => {
                        write!(f, "{}", m)
                    }
                    None => {
                        write!(f, "{}{}", $prefix, self.to_int())
                    }
                }
            }
        }
    };
}
// ---

/// --- Display --- MNEMONIC VERSION
/// This macro implements std::fmt::Display. If the value has a mnemonic it
/// formats the string as "<mnemonic>". If the value does not have a mnemonic
/// it falls back to the integer and formats the String as "<integer>".
macro_rules! int_enum_impl_display_mnemonics_fallback_integer {
    ($enum_type:ident) => {
        impl std::fmt::Display for $enum_type {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                match self.to_mnemonic_str() {
                    Some(m) => {
                        write!(f, "{}", m)
                    }
                    None => {
                        write!(f, "{}", self.to_int())
                    }
                }
            }
        }
    };
}
// ---
//
/// --- Display --- INTEGER VERSION
/// This macro implements std::fmt::Display. The value will always be formated
/// with the integer associated with it.
macro_rules! int_enum_impl_display_integer {
    ($enum_type:ident) => {
        impl std::fmt::Display for $enum_type {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                write!(f, "{}", self.to_int())
            }
        }
    };
}
// ---

/// --- Serialization / Deserialization --- INTEGER VERSION
/// This macro implements serde::Serialize and serde::Deserialize. The token
/// represented in the JSON string is an integer without quotes surrounding
/// it.
/// {
///    "value": 42
/// }
macro_rules! int_enum_impl_serde_to_and_from_integer {
    ($enum_type:ident, $enum_integer_type:ident) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $enum_type {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                self.to_int().serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $enum_type {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                $enum_integer_type::deserialize(deserializer).map(Into::into)
            }
        }
    };
}
// ---

/// --- Serialization / Deserialization --- MNEMONIC FALLBACK INTEGER
/// This macro implements serde::Serialize and serde::Deserialize. The token
/// represented in the JSON is the mnemonic version if possible otherwise the
/// associated integer.
/// {
///    "value": "SHA1",
///    "value2": 42
/// }
macro_rules! int_enum_impl_serde_to_and_from_mnemonic {
    ($enum_type:ident, $enum_integer_type:ident) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $enum_type {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    match self.to_mnemonic_str() {
                        Some(m) => {
                            serializer.collect_str(&format_args!("{}", m))
                        }
                        None => self.to_int().serialize(serializer),
                    }
                } else {
                    self.to_int().serialize(serializer)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $enum_type {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use crate::base::serde::DeserializeNativeOrStr;

                $enum_integer_type::deserialize_native_or_str(deserializer)
            }
        }
    };
}

/// --- Serialization / Deserialization --- MNEMONIC FALLBACK PREFIX INTEGER
/// This macro implements serde::Serialize and serde::Deserialize. The token
/// represented in the JSON is the mnemonic version if possible otherwise the
/// associated integer with a prefix.
/// {
///    "value": "SHA1",
///    "value2": 42
/// }
macro_rules! int_enum_impl_serde_to_and_from_mnemonic_fallback_prefix {
    ($enum_type:ident, $enum_integer_type:ident, $int_prefix:expr) => {
        #[cfg(feature = "serde")]
        impl serde::Serialize for $enum_type {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    match self.to_mnemonic_str() {
                        Some(m) => {
                            serializer.collect_str(&format_args!("{}", m))
                        }
                        None => serializer.collect_str(&format_args!(
                            "{}{}",
                            $int_prefix,
                            self.to_int()
                        )),
                    }
                } else {
                    self.to_int().serialize(serializer)
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $enum_type {
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                use crate::base::serde::DeserializeNativeOrStr;

                $enum_integer_type::deserialize_native_or_str(deserializer)
            }
        }
    };
}
// ---

// --- TRY AGAIN VERSION 3 :)
// Plan now is to only make one gianc function

// (=> $name:ident, $int:ident; fmt:decimal, zonefile:decimal($zname:expr); $($variants:tt)*) => {
macro_rules! iana_enum_implementation {
    // INTEGER ONLY
    (=> $name:ident, $int_type:ident;
    fmt:integer) => {
        instantiate_fromstrerror_with_error_description!(concat!(
            "unknown ",
            stringify!($ianatype),
        ));

        // fmt::Display INTEGER ONLY
        int_enum_impl_display_integer!($name);
        // FromStr and frombytes() INTEGER ONLY
        int_enum_impl_fromstr_frombytes_from_integer!($name);
        // JSON INTEGER ONLY
        int_enum_impl_serde_to_and_from_integer!($name, $int_type);
        // Zonefile Format INTEGER
        int_enum_zonefile_fmt_decimal!($name, stringify!($name));
    };

    // MNEMONICS WITH PREFIX
    (=> $name:ident, $int_type:ident;
    fmt:mnemonic, prefix($int_prefix:expr, $int_byte_prefix:expr)) => {
        // fmt::Display MNEMONICS fallback integer with prefix
        int_enum_impl_display_mnemonics_fallback_prefix_integer!(
            $name,
            $int_prefix
        );
        // READ MNEMONICS fallback integer with prefix
        int_enum_impl_fromstr_frombytes_from_mnemonics_or_prefix!(
            $name,
            $int_prefix,
            $int_byte_prefix
        );
        // JSON MNEMONICS fallback integer with prefix
        int_enum_impl_serde_to_and_from_mnemonic_fallback_prefix!(
            $name,
            $int_type,
            $int_prefix
        );
        // Zonefile Format INTEGER
        int_enum_zonefile_fmt_with_prefix!($name, $int_prefix);
    };

    // MNEMONICS BUT `fmt::Display` WITH INTEGER IN PARENTHESES
    (=> $name:ident, $int_type:ident;
    fmt:mnemonic_display_with_combination) => {
        // fmt::Display MNEMONIC with () fallback integer only
        int_enum_impl_display_mnemonics_with_integer_fallback_integer!($name);
        // READ MNEMONIC
        int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer!($name);
        // JSON MNEMONIC
        int_enum_impl_serde_to_and_from_mnemonic!($name, $int_type);
        // Zonefile Format MNEMONIC
        int_enum_zonefile_fmt_with_decimal!($name);
    };

    // INTEGER with integer in parentheses for display
    (=> $name:ident, $int_type:ident;
    fmt:integer_display_with_combination) => {
        // fmt::Display MNEMONIC with () fallback integer only
        int_enum_impl_display_mnemonics_with_integer_fallback_integer!($name);
        // READ MNEMONIC
        int_enum_impl_fromstr_frombytes_from_mnemonics_or_integer!($name);
        // JSON MNEMONIC
        int_enum_impl_serde_to_and_from_integer!($name, $int_type);
        // Zonefile Format MNEMONIC
        int_enum_zonefile_fmt_decimal!($name, stringify!($name));
    };
}

macro_rules! iana_enum {
    ( $(#[$attr:meta])* =>
      $ianatype:ident, $inttype:path;
      $display_function:tt,
      $parse_function:tt,
      $serde_serialize:tt,
      $serde_deserialize:tt,
      $prefix:expr;
      $( $(#[$variant_attr:meta])* ( $variant:ident =>
                                        $value:expr, $mnemonic:expr) )* ) => {
        $(#[$attr])*
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
        pub struct $ianatype($inttype);

        impl $ianatype {
            $(
                $(#[$variant_attr])*
                pub const $variant: $ianatype = $ianatype($value);
            )*
        }

        impl IanaEnum <'_>for $ianatype {
            type INT = $inttype;
            type ParseError = FromStrError;
            fn get_prefix() -> &'static str {
                $prefix
            }
            /// Returns a value from its raw integer value.
            fn from_int(value: $inttype) -> Self {
                Self(value)
            }

            /// Returns the raw integer value for a value.
            fn get_integer(&self) -> $inttype {
                self.0
            }

            /// Returns a value from a well-defined mnemonic.
            fn from_mnemonic(m: &[u8]) -> Option<Self> {
                $(
                    if m.eq_ignore_ascii_case($mnemonic.as_bytes()) {
                        return Some($ianatype::$variant)
                    }
                )*
                None
            }

            /// Returns the mnemonic as a `&str` for this value if there is one
            fn get_mnemonic_str(&self) -> Option<&'static str> {
                match self {
                    $(
                        &$ianatype::$variant => {
                            Some($mnemonic)
                        }
                    )*
                    _ => None
                }
            }

        }
        impl $ianatype {
            pub fn parse<'a, Octs: AsRef<[u8]> + ?Sized> (
                parser: &mut octseq::parse::Parser<'a, Octs>
            ) -> Result<Self, $crate::base::wire::ParseError> {
                <$inttype as $crate::base::wire::Parse<'a, Octs>>::parse(
                    parser
                ).map(Self::from_int)
            }

            pub const COMPOSE_LEN: u16 =
                <$inttype as $crate::base::wire::Compose>::COMPOSE_LEN;

        }


        //--- From

        impl From<$inttype> for $ianatype {
            fn from(value: $inttype) -> Self {
                $ianatype::from_int(value)
            }
        }

        impl From<$ianatype> for $inttype {
            fn from(value: $ianatype) -> Self {
                value.get_integer()
            }
        }

        impl<'a> From<&'a $ianatype> for $inttype {
            fn from(value: &'a $ianatype) -> Self {
                value.get_integer()
            }
        }

        impl core::str::FromStr for $ianatype {
            type Err = FromStrError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $ianatype::$parse_function(s)
            }
        }

        scan_impl!($ianatype);

        //--- Display
        impl core::fmt::Display for $ianatype {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.$display_function())
            }
        }

        //--- Debug

        impl core::fmt::Debug for $ianatype {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.get_mnemonic_bytes().and_then(|bytes| {
                    core::str::from_utf8(bytes).ok()
                }) {
                    Some(mnemonic) => {
                        write!(
                            f,
                            concat!(stringify!($ianatype), "::{}"),
                            mnemonic
                        )
                    }
                    None => {
                        f.debug_tuple(stringify!($ianatype))
                            .field(&self.0)
                            .finish()
                    }
                }
            }
        }

        //--- Serde
        #[cfg(feature = "serde")]
        impl serde::Serialize for $ianatype{
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                self.$serde_serialize(serializer)
            }
        }

        #[cfg(feature = "serde")]
        impl<'de> serde::Deserialize<'de> for $ianatype{
            fn deserialize<D: serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                Self::$serde_deserialize(deserializer)
            }
        }
    }
}
#[derive(Clone, Debug)]
pub struct FromStrError(());

impl core::error::Error for FromStrError {
    fn description(&self) -> &str {
        "unknown TODO"
    }
}

impl core::fmt::Display for FromStrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        "unkown TODO".fmt(f)
    }
}
iana_enum! {
    =>
    JannisTestEnum1, u8;
    display_integer,
    parse_from_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";
    (A => 0, "A")
    (B => 1, "B")
}
iana_enum! {
    =>
    JannisTestEnum2, u8;
    display_mnemonic_fallback_prefix_integer,
    parse_from_mnemonic_or_prefix_integer,
    serialize_to_mnemonic_fallback_prefix_integer,
    deserialize_from_mnemonic_or_prefix_integer,
    "J";
    (A => 0, "A")
    (B => 1, "B")
}
iana_enum! {
    =>
    JannisTestEnum3, u8;
    display_mnemonic_with_integer,
    parse_from_mnemonic_or_integer,
    serialize_to_mnemonic_fallback_integer,
    deserialize_from_mnemonic_or_integer,
    "";
    (A => 0, "A")
    (B => 1, "B")
}
iana_enum! {
    =>
    JannisTestEnum4, u8;
    display_mnemonic_with_integer,
    parse_from_integer,
    serialize_to_integer,
    deserialize_from_integer,
    "";
    (A => 0, "A")
    (B => 1, "B")
}

use core::fmt::Display;
use std::string::String;
use std::string::ToString;

use serde::Deserialize;
use serde::Serialize;

use crate::base::serde::DeserializeNativeOrStr;

pub trait IanaEnum<'de>: Sized {
    type INT: Default
        + std::string::ToString
        + crate::base::wire::Compose
        + core::str::FromStr
        + Deserialize<'de>
        + Into<Self>
        + Serialize
        + Display
        + DeserializeNativeOrStr<'de, Self>;
    // + core::str::FromStr<Err = core::num::ParseIntError>

    type ParseError;

    fn get_prefix() -> &'static str;
    fn from_int(value: Self::INT) -> Self;
    fn from_mnemonic(m: &[u8]) -> Option<Self>;
    fn get_mnemonic_str(&self) -> Option<&'static str>;
    fn get_mnemonic_bytes(&self) -> Option<&'static [u8]> {
        match self.get_mnemonic_str() {
            Some(m) => Some(m.as_bytes()),
            None => None,
        }
    }
    fn to_mnemonic_str(self) -> Option<&'static str> {
        self.get_mnemonic_str()
    }

    fn get_integer(&self) -> Self::INT;
    fn to_int(self) -> Self::INT {
        self.get_integer()
    }

    fn compose<Target: octseq::builder::OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        crate::base::wire::Compose::compose(&self.get_integer(), target)
    }

    //--- Display
    fn display_integer(&self) -> String {
        self.get_integer().to_string()
    }
    fn display_mnemonic_fallback_integer(&self) -> String {
        match self.get_mnemonic_str() {
            Some(m) => m.to_string(),
            None => self.get_integer().to_string(),
        }
    }
    fn display_mnemonic_fallback_prefix_integer(&self) -> String {
        match self.get_mnemonic_str() {
            Some(m) => m.to_string(),
            None => format!(
                "{}{}",
                Self::get_prefix(),
                self.get_integer().to_string()
            ),
        }
    }
    fn display_mnemonic_with_integer(&self) -> String {
        match self.get_mnemonic_str() {
            Some(m) => format!("{}({})", m, self.get_integer()),
            None => format!("{}", self.get_integer()),
        }
    }

    //--- PARSING
    fn parse_from_integer(value: &str) -> Result<Self, FromStrError> {
        match value.parse().map(Self::from_int) {
            Ok(v) => Ok(v),
            Err(_) => Err(FromStrError(())),
        }
    }
    fn parse_from_mnemonic_or_integer(
        value: &str,
    ) -> Result<Self, FromStrError> {
        match Self::from_mnemonic(value.as_bytes()) {
            Some(v) => Ok(v),
            None => match value.parse().map(Self::from_int) {
                Ok(v) => Ok(v),
                Err(_) => Err(FromStrError(())),
            },
        }
    }

    fn parse_from_mnemonic_or_prefix_integer(
        value: &str,
    ) -> Result<Self, FromStrError> {
        match Self::from_mnemonic(value.as_bytes()) {
            Some(res) => Ok(res),
            None => {
                if let Some((n, _)) =
                    value.char_indices().nth(Self::get_prefix().len())
                {
                    let (l, r) = value.split_at(n);
                    if l.eq_ignore_ascii_case(Self::get_prefix()) {
                        let value = match r.parse() {
                            Ok(x) => x,
                            Err(..) => return Err(FromStrError(())),
                        };
                        Ok(Self::from_int(value))
                    } else {
                        Err(FromStrError(()))
                    }
                } else {
                    Err(FromStrError(()))
                }
            }
        }
    }

    //--- serde::Serialize
    fn serialize_to_integer<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        self.get_integer().serialize(serializer)
    }

    fn serialize_to_mnemonic_fallback_integer<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self.get_mnemonic_str() {
            Some(m) => m.serialize(serializer),
            None => self.get_integer().serialize(serializer),
        }
    }

    fn serialize_to_mnemonic_fallback_prefix_integer<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self.get_mnemonic_str() {
            Some(m) => m.serialize(serializer),
            None => format!("{}{}", Self::get_prefix(), self.get_integer())
                .serialize(serializer),
        }
    }

    //--- serde::Deserialize
    fn deserialize_from_integer<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, <D as serde::Deserializer<'de>>::Error> {
        Self::INT::deserialize(deserializer).map(Self::from_int)
    }

    fn deserialize_from_mnemonic_or_integer<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, <D as serde::Deserializer<'de>>::Error> {
        Self::INT::deserialize_native_or_str(deserializer)
    }

    fn deserialize_from_mnemonic_or_prefix_integer<
        D: serde::Deserializer<'de>,
    >(
        deserializer: D,
    ) -> Result<Self, <D as serde::Deserializer<'de>>::Error> {
        Self::INT::deserialize_native_or_str(deserializer)
    }
}

int_enum_zonefile_fmt_decimal!(JannisTestEnum1, "jannis1");
int_enum_zonefile_fmt_with_prefix!(JannisTestEnum2, "J");
int_enum_zonefile_fmt_with_decimal!(JannisTestEnum3);
int_enum_zonefile_fmt_decimal!(JannisTestEnum4, "jannis4");

//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn security_algorithm_to_json_string() {
        use crate::base::iana::SecurityAlgorithm;
        use alloc::string::String;
        let secalg: SecurityAlgorithm = SecurityAlgorithm::DELETE;

        let secalg_json_str: String = serde_json::to_string(&secalg).unwrap();

        println!(
            "#{secalg}#{secalg:?}#: #{secalg_json_str}#{secalg_json_str:?}#"
        );

        let secalg_from_str: Result<SecurityAlgorithm, serde_json::Error> =
            serde_json::from_str(&secalg_json_str);

        println!("{:?}", secalg_from_str);
        assert!(secalg_from_str.is_ok())
    }
}
