//! Integer primitives for the DNS wire format.

use core::{
    cmp::Ordering,
    fmt,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor,
        BitXorAssign, Not, Sub, SubAssign,
    },
};

use domain_macros::*;

use super::{
    ParseBytes, ParseBytesByRef, ParseError, SplitBytes, SplitBytesByRef,
};

//----------- define_int -----------------------------------------------------

/// Define a network endianness integer primitive.
macro_rules! define_int {
    { $(
        $(#[$docs:meta])*
        $name:ident([u8; $size:literal]) = $base:ident;
    )* } => { $(
        $(#[$docs])*
        #[derive(
            Copy,
            Clone,
            Default,
            PartialEq,
            Eq,
            Hash,
            AsBytes,
            BuildBytes,
            ParseBytesByRef,
            SplitBytesByRef,
        )]
        #[repr(transparent)]
        pub struct $name([u8; $size]);

        //--- Conversion to and from integer primitive types

        impl $name {
            /// Convert an integer to network endianness.
            pub const fn new(value: $base) -> Self {
                Self(value.to_be_bytes())
            }

            /// Convert an integer from network endianness.
            pub const fn get(self) -> $base {
                <$base>::from_be_bytes(self.0)
            }
        }

        impl From<$base> for $name {
            fn from(value: $base) -> Self {
                Self::new(value)
            }
        }

        impl From<$name> for $base {
            fn from(value: $name) -> Self {
                value.get()
            }
        }

        //--- Parsing from bytes

        impl<'b> ParseBytes<'b> for $name {
            fn parse_bytes(bytes: &'b [u8]) -> Result<Self, ParseError> {
                Self::parse_bytes_by_ref(bytes).copied()
            }
        }

        impl<'b> SplitBytes<'b> for $name {
            fn split_bytes(
                bytes: &'b [u8],
            ) -> Result<(Self, &'b [u8]), ParseError> {
                Self::split_bytes_by_ref(bytes)
                    .map(|(&this, rest)| (this, rest))
            }
        }

        //--- Comparison

        impl PartialEq<$base> for $name {
            fn eq(&self, other: &$base) -> bool {
                self.get() == *other
            }
        }

        impl PartialOrd<$base> for $name {
            fn partial_cmp(&self, other: &$base) -> Option<Ordering> {
                self.get().partial_cmp(other)
            }
        }

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.get().cmp(&other.get())
            }
        }

        //--- Formatting

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.get()).finish()
            }
        }

        //--- Arithmetic

        impl Add for $name {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self::new(self.get() + rhs.get())
            }
        }

        impl AddAssign for $name {
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl Add<$base> for $name {
            type Output = Self;

            fn add(self, rhs: $base) -> Self::Output {
                Self::new(self.get() + rhs)
            }
        }

        impl AddAssign<$base> for $name {
            fn add_assign(&mut self, rhs: $base) {
                *self = *self + rhs;
            }
        }

        impl Sub for $name {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                Self::new(self.get() - rhs.get())
            }
        }

        impl SubAssign for $name {
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl Sub<$base> for $name {
            type Output = Self;

            fn sub(self, rhs: $base) -> Self::Output {
                Self::new(self.get() - rhs)
            }
        }

        impl SubAssign<$base> for $name {
            fn sub_assign(&mut self, rhs: $base) {
                *self = *self - rhs;
            }
        }

        impl Not for $name {
            type Output = Self;

            fn not(self) -> Self::Output {
                Self::new(!self.get())
            }
        }

        //--- Bitwise operations

        impl BitAnd for $name {
            type Output = Self;

            fn bitand(self, rhs: Self) -> Self::Output {
                Self::new(self.get() & rhs.get())
            }
        }

        impl BitAndAssign for $name {
            fn bitand_assign(&mut self, rhs: Self) {
                *self = *self & rhs;
            }
        }

        impl BitAnd<$base> for $name {
            type Output = Self;

            fn bitand(self, rhs: $base) -> Self::Output {
                Self::new(self.get() & rhs)
            }
        }

        impl BitAndAssign<$base> for $name {
            fn bitand_assign(&mut self, rhs: $base) {
                *self = *self & rhs;
            }
        }

        impl BitOr for $name {
            type Output = Self;

            fn bitor(self, rhs: Self) -> Self::Output {
                Self::new(self.get() | rhs.get())
            }
        }

        impl BitOrAssign for $name {
            fn bitor_assign(&mut self, rhs: Self) {
                *self = *self | rhs;
            }
        }

        impl BitOr<$base> for $name {
            type Output = Self;

            fn bitor(self, rhs: $base) -> Self::Output {
                Self::new(self.get() | rhs)
            }
        }

        impl BitOrAssign<$base> for $name {
            fn bitor_assign(&mut self, rhs: $base) {
                *self = *self | rhs;
            }
        }

        impl BitXor for $name {
            type Output = Self;

            fn bitxor(self, rhs: Self) -> Self::Output {
                Self::new(self.get() ^ rhs.get())
            }
        }

        impl BitXorAssign for $name {
            fn bitxor_assign(&mut self, rhs: Self) {
                *self = *self ^ rhs;
            }
        }

        impl BitXor<$base> for $name {
            type Output = Self;

            fn bitxor(self, rhs: $base) -> Self::Output {
                Self::new(self.get() ^ rhs)
            }
        }

        impl BitXorAssign<$base> for $name {
            fn bitxor_assign(&mut self, rhs: $base) {
                *self = *self ^ rhs;
            }
        }
    )* };
}

define_int! {
    /// An unsigned 16-bit integer in network endianness.
    U16([u8; 2]) = u16;

    /// An unsigned 32-bit integer in network endianness.
    U32([u8; 4]) = u32;

    /// An unsigned 64-bit integer in network endianness.
    U64([u8; 8]) = u64;
}
