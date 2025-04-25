//! Parsing bytes in the basic network format.

use core::fmt;
use core::mem::MaybeUninit;

use crate::utils::dst::UnsizedCopy;

//----------- ParseBytes -----------------------------------------------------

/// Parsing from a byte sequence.
pub trait ParseBytes<'a>: Sized {
    /// Parse a value of [`Self`] from the given byte sequence.
    ///
    /// The returned value may borrow from the byte sequence.  This allows it
    /// to avoid copying data unnecessarily.
    ///
    /// The entirety of the input must be used.  If some input bytes would be
    /// left over, [`ParseError`] should be returned.
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError>;
}

impl<'a> ParseBytes<'a> for u8 {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let [result] = bytes else {
            return Err(ParseError);
        };

        Ok(*result)
    }
}

impl<'a, T: ?Sized + ParseBytesZC> ParseBytes<'a> for &'a T {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        T::parse_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: SplitBytes<'a>, const N: usize> ParseBytes<'a> for [T; N] {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

#[cfg(feature = "std")]
impl<'a, T: ParseBytes<'a>> ParseBytes<'a> for std::boxed::Box<T> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        T::parse_bytes(bytes).map(std::boxed::Box::new)
    }
}

#[cfg(feature = "std")]
impl<'a> ParseBytes<'a> for std::vec::Vec<u8> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Ok(bytes.to_vec())
    }
}

#[cfg(feature = "std")]
impl<'a> ParseBytes<'a> for std::string::String {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        str::parse_bytes_by_ref(bytes).map(std::string::String::from)
    }
}

/// Deriving [`ParseBytes`] automatically.
///
/// [`ParseBytes`] can be derived on `struct`s (not `enum`s or `union`s).  All
/// fields except the last must implement [`SplitBytes`], while the last field
/// only needs to implement [`ParseBytes`].
///
/// Here's a simple example:
///
/// ```no_run
/// # use domain::new_base::wire::{ParseBytes, SplitBytes, U32, ParseError};
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(ParseBytes)':
/// impl<'bytes, T> ParseBytes<'bytes> for Foo<T>
/// where
///     U32: SplitBytes<'bytes>,
///     Bar<T>: ParseBytes<'bytes>,
/// {
///     fn parse_bytes(
///         bytes: &'bytes [u8],
///     ) -> Result<Self, ParseError> {
///         let (field_a, bytes) = U32::split_bytes(bytes)?;
///         let field_b = <Bar<T>>::parse_bytes(bytes)?;
///         Ok(Self { a: field_a, b: field_b })
///     }
/// }
/// ```
pub use domain_macros::ParseBytes;

//----------- SplitBytes -----------------------------------------------------

/// Parsing from the start of a byte sequence.
pub trait SplitBytes<'a>: Sized + ParseBytes<'a> {
    /// Parse a value of [`Self`] from the start of the byte sequence.
    ///
    /// If parsing is successful, the parsed value and the rest of the input
    /// (the part that was not parsed) are returned.  On failure, a
    /// [`ParseError`] is returned.
    ///
    /// ## Non-Greedy Parsing
    ///
    /// This function is _non-greedy_.  This can be interpreted in several
    /// equivalent ways:
    ///
    /// - If `split_bytes()` returns successfully for some input sequence, it
    ///   would return exactly the same `Self` value if more bytes were added
    ///   to the end of the input.
    ///
    /// - The unparsed part of the input (that is returned on success) does
    ///   not influence the function; those bytes are not examined.
    ///
    /// - `Self` has an intrinsic length to it; this may be a constant, or it
    ///   may be determined by examining the parsed part of the input (e.g.
    ///   for size-prefixed data).
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError>;
}

impl<'a> SplitBytes<'a> for u8 {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        bytes.split_first().map(|(&f, r)| (f, r)).ok_or(ParseError)
    }
}

impl<'a, T: ?Sized + SplitBytesZC> SplitBytes<'a> for &'a T {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        T::split_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: SplitBytes<'a>, const N: usize> SplitBytes<'a> for [T; N] {
    fn split_bytes(
        mut bytes: &'a [u8],
    ) -> Result<(Self, &'a [u8]), ParseError> {
        // TODO: Rewrite when either 'array_try_map' or 'try_array_from_fn'
        // is stabilized.

        /// A guard for dropping initialized elements on panic / failure.
        struct Guard<T, const N: usize> {
            /// The array of elements being built up.
            buffer: [MaybeUninit<T>; N],

            /// The number of elements currently initialized.
            initialized: usize,
        }

        impl<T, const N: usize> Drop for Guard<T, N> {
            fn drop(&mut self) {
                for elem in &mut self.buffer[..self.initialized] {
                    // SAFETY: The first 'initialized' elems are initialized.
                    unsafe { elem.assume_init_drop() };
                }
            }
        }

        let mut guard = Guard::<T, N> {
            buffer: [const { MaybeUninit::uninit() }; N],
            initialized: 0,
        };

        while guard.initialized < N {
            let (elem, rest) = T::split_bytes(bytes)?;
            guard.buffer[guard.initialized].write(elem);
            bytes = rest;
            guard.initialized += 1;
        }

        // Disable the guard since we're moving data out now.
        guard.initialized = 0;

        // SAFETY: '[MaybeUninit<T>; N]' and '[T; N]' have the same layout,
        // because 'MaybeUninit<T>' and 'T' have the same layout, because it
        // is documented in the standard library.
        Ok((unsafe { core::mem::transmute_copy(&guard.buffer) }, bytes))
    }
}

#[cfg(feature = "std")]
impl<'a, T: SplitBytes<'a>> SplitBytes<'a> for std::boxed::Box<T> {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        T::split_bytes(bytes)
            .map(|(this, rest)| (std::boxed::Box::new(this), rest))
    }
}

/// Deriving [`SplitBytes`] automatically.
///
/// [`SplitBytes`] can be derived on `struct`s (not `enum`s or `union`s).  All
/// fields must implement [`SplitBytes`].
///
/// Here's a simple example:
///
/// ```no_run
/// # use domain::new_base::wire::{ParseBytes, SplitBytes, U32, ParseError};
/// #[derive(ParseBytes)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(SplitBytes)':
/// impl<'bytes, T> SplitBytes<'bytes> for Foo<T>
/// where
///     U32: SplitBytes<'bytes>,
///     Bar<T>: SplitBytes<'bytes>,
/// {
///     fn split_bytes(
///         bytes: &'bytes [u8],
///     ) -> Result<(Self, &'bytes [u8]), ParseError> {
///         let (field_a, bytes) = U32::split_bytes(bytes)?;
///         let (field_b, bytes) = <Bar<T>>::split_bytes(bytes)?;
///         Ok((Self { a: field_a, b: field_b }, bytes))
///     }
/// }
/// ```
pub use domain_macros::SplitBytes;

//----------- ParseBytesZC ---------------------------------------------------

/// Zero-copy parsing from a byte sequence.
///
/// # Safety
///
/// Every implementation of [`ParseBytesZC`] must satisfy the invariants
/// documented on [`parse_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
///
/// [`parse_bytes_by_ref()`]: Self::parse_bytes_by_ref()
///
/// Implementing types must also have no alignment (i.e. a valid instance of
/// [`Self`] can occur at any address).  This eliminates the possibility of
/// padding bytes when [`Self`] is part of a larger aggregate type.
pub unsafe trait ParseBytesZC: UnsizedCopy + 'static {
    /// Interpret a byte sequence as an instance of [`Self`].
    ///
    /// This method can only parse from immutable references; to parse within
    /// a different container type, use [`Self::parse_bytes_in()`].
    ///
    /// This will return successfully if and only if the entirety of the given
    /// byte sequence can be interpreted as an instance of [`Self`].  It will
    /// transmute the bytes reference into a reference to [`Self`] and return
    /// it.
    ///
    /// ## Invariants
    ///
    /// For the statement `let this: &T = T::parse_bytes_by_ref(bytes)?`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `ptr` has the same provenance as `bytes`.
    /// - `bytes.len() == core::mem::size_of_val(this)`.
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError>;

    /// Parse bytes within the given container.
    ///
    /// Given a container of a byte sequence, this function tries to parse the
    /// bytes as a valid instance of `Self`.  If this succeeds, the container
    /// as a whole is converted (in place) to hold `Self`.
    ///
    /// This is a convenience method for calling
    /// [`ParseBytesInPlace::parse_bytes_in_place()`].
    #[inline]
    fn parse_bytes_in<C: ParseBytesInPlace>(
        container: C,
    ) -> Result<C::WithParsed<Self>, (C, ParseError)> {
        C::parse_bytes_in_place(container)
    }
}

unsafe impl ParseBytesZC for u8 {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        if let [result] = bytes {
            Ok(result)
        } else {
            Err(ParseError)
        }
    }
}

unsafe impl ParseBytesZC for [u8] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Ok(bytes)
    }
}

unsafe impl ParseBytesZC for str {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        core::str::from_utf8(bytes).map_err(|_| ParseError)
    }
}

unsafe impl<T: SplitBytesZC, const N: usize> ParseBytesZC for [T; N] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let (this, rest) = Self::split_bytes_by_ref(bytes)?;
        if rest.is_empty() {
            Ok(this)
        } else {
            Err(ParseError)
        }
    }
}

/// Deriving [`ParseBytesZC`] automatically.
///
/// [`ParseBytesZC`] can be derived on `struct`s (not `enum`s or `union`s),
/// where a fixed memory layout (`repr(C)` or `repr(transparent)`) is used.
/// All fields except the last must implement [`SplitBytesZC`], while the last
/// field only needs to implement [`ParseBytesZC`].
///
/// Here's a simple example:
///
/// ```no_run
/// # use domain::new_base::wire::{ParseBytesZC, SplitBytesZC, U32, ParseError};
/// # use domain::utils::dst::UnsizedCopy;
/// #[derive(UnsizedCopy)]
/// #[repr(C)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(ParseBytesZC)':
/// unsafe impl<T> ParseBytesZC for Foo<T>
/// where Bar<T>: ParseBytesZC {
///     fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_ref(bytes)?;
///         let last = <Bar<T>>::parse_bytes_by_ref(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok(unsafe { &*(this as *const Self) })
///     }
/// }
/// ```
pub use domain_macros::ParseBytesZC;

//----------- SplitBytesZC ------------------------------------------------

/// Zero-copy parsing from the start of a byte sequence.
///
/// This is an extension of [`ParseBytesZC`] for types which can determine
/// their own length when parsing.  It is usually implemented by [`Sized`]
/// types (where the length is just the size of the type), although it can be
/// sometimes implemented by unsized types.
///
/// # Non-Greedy Parsing
///
/// This parsing functions provided by this trait are _non-greedy_.  This can
/// be interpreted in several equivalent ways:
///
/// - If `split_bytes_by_ref()` returns successfully for some input sequence, it
///   would return exactly the same `Self` value if more bytes were added to
///   the end of the input.
///
/// - The unparsed part of the input (that is returned on success) does
///   not influence the function; those bytes are not examined.
///
/// - `Self` has an intrinsic length to it; this may be a constant, or it
///   may be determined by examining the parsed part of the input (e.g.
///   for size-prefixed data).
///
/// # Safety
///
/// Every implementation of [`SplitBytesZC`] must satisfy the invariants
/// documented on [`split_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
///
/// [`split_bytes_by_ref()`]: Self::split_bytes_by_ref()
///
/// Note that [`ParseBytesZC`] and [`UnsizedCopy`], required by this trait,
/// also have several invariants that need to be considered with care.
pub unsafe trait SplitBytesZC: ParseBytesZC {
    /// Interpret the start of a byte sequence as an instance of [`Self`].
    ///
    /// The byte sequence will be validated and re-interpreted as a reference
    /// to [`Self`].  The length of [`Self`] will be determined, possibly
    /// based on the contents (but not the length!) of the input, and the
    /// remaining bytes will be returned.  If the input does not begin with a
    /// valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let (this, rest) = T::split_bytes_by_ref(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this) + rest.len()`.
    /// - `bytes.as_ptr().offset(size_of_val(this)) == rest.as_ptr()`.
    fn split_bytes_by_ref(bytes: &[u8])
        -> Result<(&Self, &[u8]), ParseError>;
}

unsafe impl SplitBytesZC for u8 {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        bytes.split_first().ok_or(ParseError)
    }
}

unsafe impl<T: SplitBytesZC, const N: usize> SplitBytesZC for [T; N] {
    fn split_bytes_by_ref(
        mut bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        let start = bytes.as_ptr();
        for _ in 0..N {
            (_, bytes) = T::split_bytes_by_ref(bytes)?;
        }

        // SAFETY:
        // - 'T::split_bytes_by_ref()' was called 'N' times on successive
        //   positions, thus the original 'bytes' starts with 'N' instances
        //   of 'T' (even if 'T' is a ZST and so all instances overlap).
        // - 'N' consecutive 'T's have the same layout as '[T; N]'.
        // - Thus it is safe to cast 'start' to '[T; N]'.
        // - The referenced data has the same lifetime as the output.
        Ok((unsafe { &*start.cast::<[T; N]>() }, bytes))
    }
}

/// Deriving [`SplitBytesZC`] automatically.
///
/// [`SplitBytesZC`] can be derived on `struct`s (not `enum`s or `union`s),
/// where a fixed memory layout (`repr(C)` or `repr(transparent)`) is used.
/// All fields must implement [`SplitBytesZC`].
///
/// Here's a simple example:
///
/// ```no_run
/// # use domain::new_base::wire::{ParseBytesZC, SplitBytesZC, U32, ParseError};
/// #[derive(ParseBytesZC)]
/// #[repr(C)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(SplitBytesZC)':
/// unsafe impl<T> SplitBytesZC for Foo<T>
/// where Bar<T>: SplitBytesZC {
///     fn split_bytes_by_ref(
///         bytes: &[u8],
///     ) -> Result<(&Self, &[u8]), ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_ref(bytes)?;
///         let (last, bytes) = <Bar<T>>::split_bytes_by_ref(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok((unsafe { &*(this as *const Self) }, bytes))
///     }
///
///     fn split_bytes_by_mut(
///         bytes: &mut [u8],
///     ) -> Result<(&mut Self, &mut [u8]), ParseError> {
///         let addr = bytes.as_ptr();
///         let (_, bytes) = U32::split_bytes_by_mut(bytes)?;
///         let (last, bytes) = <Bar<T>>::split_bytes_by_mut(bytes)?;
///         let this = last.ptr_with_address(addr as *const ());
///         Ok((unsafe { &mut *(this as *const Self as *mut Self) }, bytes))
///     }
/// }
/// ```
pub use domain_macros::SplitBytesZC;

//----------- ParseBytesInPlace ----------------------------------------------

/// Parsing from a byte sequence within an container.
///
/// This trait allows various "container types", like [`Box`] and [`Vec`], to
/// parse a stored byte sequence into a different type in place.  The target
/// type has to implement [`ParseBytesZC`].
///
/// [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
/// [`Vec`]: https://doc.rust-lang.org/std/vec/struct.Vec.html
pub trait ParseBytesInPlace: Sized {
    /// This container, but holding the given type instead.
    type WithParsed<T: ?Sized + ParseBytesZC>: Sized;

    /// Parse the byte sequence in this container in place.
    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)>;
}

impl<'a> ParseBytesInPlace for &'a [u8] {
    type WithParsed<T: ?Sized + ParseBytesZC> = &'a T;

    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)> {
        T::parse_bytes_by_ref(self).map_err(|err| (self, err))
    }
}

impl<'a> ParseBytesInPlace for &'a mut [u8] {
    type WithParsed<T: ?Sized + ParseBytesZC> = &'a mut T;

    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)> {
        let parsed = match T::parse_bytes_by_ref(self) {
            Ok(parsed) => parsed as *const T,
            Err(err) => return Err((self, err)),
        };

        // SAFETY: By the invariants of 'parse_bytes_by_ref()', '*parsed' has the
        // same address and layout as '*self'.  Thus, it is safe to use it to
        // reconstitute the reference.
        Ok(unsafe { &mut *parsed.cast_mut() })
    }
}

#[cfg(feature = "std")]
impl ParseBytesInPlace for std::boxed::Box<[u8]> {
    type WithParsed<T: ?Sized + ParseBytesZC> = std::boxed::Box<T>;

    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)> {
        let parsed = match T::parse_bytes_by_ref(&self) {
            Ok(parsed) => parsed as *const T,
            Err(err) => return Err((self, err)),
        };

        // SAFETY: By the invariants of 'parse_bytes_by_ref()', '*parsed' has the
        // same address and layout as '*self'.  Thus, it is safe to use it to
        // reconstitute the 'Box'.
        let _ = std::boxed::Box::into_raw(self);
        Ok(unsafe { std::boxed::Box::from_raw(parsed.cast_mut()) })
    }
}

#[cfg(feature = "std")]
impl ParseBytesInPlace for std::rc::Rc<[u8]> {
    type WithParsed<T: ?Sized + ParseBytesZC> = std::rc::Rc<T>;

    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)> {
        let parsed = match T::parse_bytes_by_ref(&self) {
            Ok(parsed) => parsed as *const T,
            Err(err) => return Err((self, err)),
        };

        // SAFETY: By the invariants of 'parse_bytes_by_ref()', '*parsed' has the
        // same address and layout as '*self'.  Thus, it is safe to use it to
        // reconstitute the 'Rc'.
        let _ = std::rc::Rc::into_raw(self);
        Ok(unsafe { std::rc::Rc::from_raw(parsed) })
    }
}

#[cfg(feature = "std")]
impl ParseBytesInPlace for std::sync::Arc<[u8]> {
    type WithParsed<T: ?Sized + ParseBytesZC> = std::sync::Arc<T>;

    fn parse_bytes_in_place<T: ?Sized + ParseBytesZC>(
        self,
    ) -> Result<Self::WithParsed<T>, (Self, ParseError)> {
        let parsed = match T::parse_bytes_by_ref(&self) {
            Ok(parsed) => parsed as *const T,
            Err(err) => return Err((self, err)),
        };

        // SAFETY: By the invariants of 'parse_bytes_by_ref()', '*parsed' has the
        // same address and layout as '*self'.  Thus, it is safe to use it to
        // reconstitute the 'Arc'.
        let _ = std::sync::Arc::into_raw(self);
        Ok(unsafe { std::sync::Arc::from_raw(parsed) })
    }
}

//----------- ParseError -----------------------------------------------------

/// A DNS message parsing error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParseError;

//--- Formatting

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS data could not be parsed from the wire format")
    }
}
