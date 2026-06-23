//! Traits, types, and functions helping with implementing serialization.
#![cfg(feature = "serde")]

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

//------------ DeserializeNativeOrStr ----------------------------------------

/// A trait for deserializing from a native type or a string.
///
/// The trait should be implemented for simple types natively supported by
/// Serde. The implementation should prefer the string variant for human
/// readable formats and the native variant for compact formats.
///
/// The trait exists because we currently cannot fabricate the necessary
/// `Deserializer::deserialize_` and `Visitor::visit_` method names for a
/// given type in simple macros.
pub trait DeserializeNativeOrStr<'de, T>: Sized {
    fn deserialize_native_or_str<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error>;
}

impl<'de, T> DeserializeNativeOrStr<'de, T> for u8
where
    T: From<Self> + FromStr,
    T::Err: fmt::Display,
{
    fn deserialize_native_or_str<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<T> serde::de::Visitor<'_> for Visitor<T>
        where
            T: From<u8> + FromStr,
            T::Err: fmt::Display,
        {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a u8 or string")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<T, E> {
                match v.try_into() {
                    Ok(u8_value) => Ok(T::from(u8_value)),
                    Err(e) => Err(E::custom(format_args!(
                        "value too big, expected u8: {e}"
                    ))),
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<T, E> {
                T::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor(PhantomData))
    }
}

impl<'de, T> DeserializeNativeOrStr<'de, T> for u16
where
    T: From<Self> + FromStr,
    T::Err: fmt::Display,
{
    fn deserialize_native_or_str<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<T> serde::de::Visitor<'_> for Visitor<T>
        where
            T: From<u16> + FromStr,
            T::Err: fmt::Display,
        {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a u16 or string")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<T, E> {
                match v.try_into() {
                    Ok(u16_value) => Ok(T::from(u16_value)),
                    Err(e) => Err(E::custom(format_args!(
                        "value too big, expected u16: {e}"
                    ))),
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<T, E> {
                T::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor(PhantomData))
    }
}

impl<'de, T> DeserializeNativeOrStr<'de, T> for u32
where
    T: From<Self> + FromStr,
    T::Err: fmt::Display,
{
    fn deserialize_native_or_str<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        struct Visitor<T>(PhantomData<T>);

        impl<T> serde::de::Visitor<'_> for Visitor<T>
        where
            T: From<u32> + FromStr,
            T::Err: fmt::Display,
        {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a u32 or string")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<T, E> {
                match v.try_into() {
                    Ok(u32_value) => Ok(T::from(u32_value)),
                    Err(e) => Err(E::custom(format_args!(
                        "value too big, expected u32: {e}"
                    ))),
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<T, E> {
                T::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(Visitor(PhantomData))
    }
}
