//! Working with dynamically sized types (DSTs).
//!
//! DSTs are types whose size is known at run-time instead of compile-time.
//! The primary examples of this are slices and [`str`].  While Rust provides
//! relatively good support for DSTs (e.g. they can be held by reference like
//! any other type), it has some rough edges.  The standard library tries to
//! paper over these with helpful functions and trait impls, but it does not
//! account for custom DST types.  In particular, [`new_base`] introduces a
//! large number of user-facing DSTs and needs to paper over the same rough
//! edges for all of them.
//!
//! [`new_base`]: crate::new_base
//!
//! ## Coping DSTs
//!
//! Because DSTs cannot be held by value, they must be handled and manipulated
//! through an indirection (a reference or a smart pointer of some kind).
//! Copying a DST into new container (e.g. [`Box`]) requires explicit support
//! from that container type.
//!
//! [`Box`]: https://doc.rust-lang.org/std/boxed/struct.Box.html
//!
//! This module introduces the [`UnsizedCopy`] trait (and a derive macro) that
//! types like [`str`] implement.  Container types that can support copying
//! DSTs implement [`UnsizedCopyFrom`].
//
// TODO: Example

//----------- UnsizedCopy ----------------------------------------------------

/// An extension of [`Copy`] to dynamically sized types.
///
/// This is a generalization of [`Copy`].  It is intended to simplify working
/// with DSTs that support zero-copy parsing techniques (as these are built
/// from byte sequences, they are inherently trivial to copy).
///
/// # Usage
///
/// To copy a type, call [`UnsizedCopy::unsized_copy_into()`] on the DST being
/// copied, or call [`UnsizedCopyFrom::unsized_copy_from()`] on the container
/// type to copy into.  The two function identically.
///
#[cfg_attr(
    feature = "bumpalo",
    doc = "The [`copy_to_bump()`] function is useful for copying data into [`bumpalo`]-based allocations."
)]
///
/// # Safety
///
/// A type `T` can implement `UnsizedCopy` if all of the following hold:
///
/// - It is an aggregate type (`struct`, `enum`, or `union`) and every field
///   implements [`UnsizedCopy`].
///
/// - `T::Alignment` has exactly the same alignment as `T`.
///
/// - `T::ptr_with_addr()` satisfies the documented invariants.
pub unsafe trait UnsizedCopy {
    /// Copy `self` into a new container.
    ///
    /// A new container of the specified type (which is usually inferred) is
    /// allocated, and the contents of `self` are copied into it.  This is a
    /// convenience method that calls [`unsized_copy_from()`].
    ///
    /// [`unsized_copy_from()`]: UnsizedCopyFrom::unsized_copy_from().
    #[inline]
    fn unsized_copy_into<T: UnsizedCopyFrom<Source = Self>>(&self) -> T {
        T::unsized_copy_from(self)
    }

    /// Copy `self` and return it by value.
    ///
    /// This offers equivalent functionality to the regular [`Copy`] trait,
    /// which is also why it has the same [`Sized`] bound.
    #[inline]
    fn copy(&self) -> Self
    where
        Self: Sized,
    {
        // The compiler can't tell that 'Self' is 'Copy', so we're just going
        // to copy it manually.  Hopefully this optimizes fine.

        // SAFETY: 'self' is a valid reference, and is thus safe for reads.
        unsafe { core::ptr::read(self) }
    }

    /// A type with the same alignment as `Self`.
    ///
    /// At the moment, Rust does not provide a way to determine the alignment
    /// of a dynamically sized type at compile-time.  This restriction exists
    /// because trait objects (which count as DSTs, but are not supported by
    /// [`UnsizedCopy`]) have an alignment determined by their implementation
    /// (which can vary at runtime).
    ///
    /// This associated type papers over this limitation, by simply requiring
    /// every implementation of [`UnsizedCopy`] to specify a type with the
    /// same alignment here.  This is used by internal plumbing code to know
    /// the alignment of `Self` at compile-time.
    ///
    /// ## Invariants
    ///
    /// The alignment of `Self::Alignment` must be the same as that of `Self`.
    type Alignment: Sized;

    /// Change the address of a pointer to `Self`.
    ///
    /// `Self` may be a DST, which means that references (and pointers) to it
    /// store metadata alongside the usual memory address.  For example, the
    /// metadata for a slice type is its length.  In order to construct a new
    /// instance of `Self` (as is done by copying), a new pointer must be
    /// created, and the appropriate metadata must be inserted.
    ///
    /// At the moment, Rust does not provide a way to examine this metadata
    /// for an arbitrary type.  This method papers over this limitation, and
    /// provides a way to copy the metadata from an existing pointer while
    /// changing the pointer address.
    ///
    /// # Implementing
    ///
    /// Most users will derive [`UnsizedCopy`] and so don't need to worry
    /// about this.  In any case, when Rust builds in support for extracting
    /// metadata, this function will gain a default implementation, and will
    /// eventually be deprecated.
    ///
    /// For manual implementations for unsized types:
    ///
    /// ```no_run
    /// pub struct Foo {
    ///     a: i32,
    ///     b: [u8],
    /// }
    ///
    /// unsafe impl UnsizedCopy for Foo {
    ///     fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
    ///         // Delegate to the same function on the last field.
    ///         //
    ///         // Rust knows that 'Self' has the same metadata as '[u8]',
    ///         // and so permits casting pointers between those types.
    ///         self.b.ptr_with_addr(addr) as *const Self
    ///     }
    /// }
    /// ```
    ///
    /// For manual implementations for sized types:
    ///
    /// ```no_run
    /// pub struct Foo {
    ///     a: i32,
    ///     b: Option<f64>,
    /// }
    ///
    /// unsafe impl UnsizedCopy for Foo {
    ///     fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
    ///         // Since 'Self' is 'Sized', there is no metadata.
    ///         addr.cast::<Self>()
    ///     }
    /// }
    /// ```
    ///
    /// # Invariants
    ///
    /// For the statement `let result = Self::ptr_with_addr(ptr, addr);`, the
    /// following always hold:
    ///
    /// - `result as usize == addr as usize`.
    /// - `core::ptr::metadata(result) == core::ptr::metadata(ptr)`.
    ///
    /// It is undefined behaviour for an implementation of [`UnsizedCopy`] to
    /// break these invariants.
    fn ptr_with_addr(&self, addr: *const ()) -> *const Self;
}

/// Deriving [`UnsizedCopy`] automatically.
///
/// [`UnsizedCopy`] can be derived on any aggregate type.  `enum`s and
/// `union`s are inherently [`Sized`] types, and [`UnsizedCopy`] will simply
/// require every field to implement [`Copy`] on them.  For `struct`s, all but
/// the last field need to implement [`Copy`]; the last field needs to
/// implement [`UnsizedCopy`].
///
/// Here's a simple example:
///
/// ```no_run
/// # use domain::utils::dst::UnsizedCopy;
/// struct Foo<T: ?Sized> {
///     a: u32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T: ?Sized> { data: T }
///
/// // The generated impl with 'derive(UnsizedCopy)':
/// unsafe impl<T: ?Sized> UnsizedCopy for Foo<T>
/// where
///     u32: Copy,
///     Bar<T>: UnsizedCopy,
/// {
///     // This type has the same alignment as 'Foo<T>'.
///     type Alignment = (u32, <Bar<T> as UnsizedCopy>::Alignment);
///
///     fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
///         self.b.ptr_with_addr(addr) as *const Self
///     }
/// }
/// ```
pub use domain_macros::UnsizedCopy;

macro_rules! impl_primitive_unsized_copy {
    ($($type:ty),+) => {
        $(unsafe impl UnsizedCopy for $type {
            type Alignment = Self;

            fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
                addr.cast::<Self>()
            }
        })+
    };
}

impl_primitive_unsized_copy!((), bool, char);
impl_primitive_unsized_copy!(u8, u16, u32, u64, u128, usize);
impl_primitive_unsized_copy!(i8, i16, i32, i64, i128, isize);
impl_primitive_unsized_copy!(f32, f64);

unsafe impl<T: ?Sized> UnsizedCopy for &T {
    type Alignment = Self;

    fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
        addr.cast::<Self>()
    }
}

unsafe impl UnsizedCopy for str {
    // 'str' has no alignment.
    type Alignment = u8;

    fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
        // NOTE: The Rust Reference indicates that 'str' has the same layout
        // as '[u8]' [1].  This is also the most natural layout for it.  Since
        // there's no way to construct a '*const str' from raw parts, we will
        // just construct a raw slice and transmute it.
        //
        // [1]: https://doc.rust-lang.org/reference/type-layout.html#str-layout

        self.as_bytes().ptr_with_addr(addr) as *const Self
    }
}

unsafe impl<T: UnsizedCopy> UnsizedCopy for [T] {
    type Alignment = T;

    fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
        core::ptr::slice_from_raw_parts(addr.cast::<T>(), self.len())
    }
}

unsafe impl<T: UnsizedCopy, const N: usize> UnsizedCopy for [T; N] {
    type Alignment = T;

    fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
        addr.cast::<Self>()
    }
}

macro_rules! impl_unsized_copy_tuple {
    ($($type:ident),*; $last:ident) => {
        unsafe impl<$($type: Copy,)* $last: ?Sized + UnsizedCopy>
        UnsizedCopy for ($($type,)* $last,) {
            type Alignment = ($($type,)* <$last>::Alignment,);

            fn ptr_with_addr(&self, addr: *const ()) -> *const Self {
                let (.., last) = self;
                last.ptr_with_addr(addr) as *const Self
            }
        }
    };
}

impl_unsized_copy_tuple!(; A);
impl_unsized_copy_tuple!(A; B);
impl_unsized_copy_tuple!(A, B; C);
impl_unsized_copy_tuple!(A, B, C; D);
impl_unsized_copy_tuple!(A, B, C, D; E);
impl_unsized_copy_tuple!(A, B, C, D, E; F);
impl_unsized_copy_tuple!(A, B, C, D, E, F; G);
impl_unsized_copy_tuple!(A, B, C, D, E, F, G; H);
impl_unsized_copy_tuple!(A, B, C, D, E, F, G, H; I);
impl_unsized_copy_tuple!(A, B, C, D, E, F, G, H, I; J);
impl_unsized_copy_tuple!(A, B, C, D, E, F, G, H, I, J; K);
impl_unsized_copy_tuple!(A, B, C, D, E, F, G, H, I, J, K; L);

//----------- UnsizedCopyFrom ------------------------------------------------

/// A container type that can be copied into.
pub trait UnsizedCopyFrom: Sized {
    /// The source type to copy from.
    type Source: ?Sized + UnsizedCopy;

    /// Create a new `Self` by copying the given value.
    fn unsized_copy_from(value: &Self::Source) -> Self;
}

#[cfg(feature = "std")]
impl<T: ?Sized + UnsizedCopy> UnsizedCopyFrom for std::boxed::Box<T> {
    type Source = T;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        use std::alloc;

        let layout = alloc::Layout::for_value(value);
        let ptr = unsafe { alloc::alloc(layout) };
        if ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        let src = value as *const _ as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, ptr, layout.size()) };
        let ptr = value.ptr_with_addr(ptr.cast()).cast_mut();
        unsafe { std::boxed::Box::from_raw(ptr) }
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + UnsizedCopy> UnsizedCopyFrom for std::rc::Rc<T> {
    type Source = T;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        use core::mem::MaybeUninit;

        /// A [`u8`] with a custom alignment.
        #[derive(Copy, Clone)]
        #[repr(C)]
        struct AlignedU8<T>([T; 0], u8);

        // TODO(1.82): Use 'Rc::new_uninit_slice()'.
        // 'impl FromIterator for Rc' describes performance characteristics.
        // For efficiency, the iterator should implement 'TrustedLen', which
        // is (currently) a nightly-only trait.  However, we can use the
        // existing 'std' types which happen to implement it.
        let size = core::mem::size_of_val(value);
        let rc: std::rc::Rc<[MaybeUninit<AlignedU8<T::Alignment>>]> =
            (0..size).map(|_| MaybeUninit::uninit()).collect();

        let src = value as *const _ as *const u8;
        let dst = std::rc::Rc::into_raw(rc).cast_mut();
        // SAFETY: 'rc' was just constructed and has never been copied.  Thus,
        //   its contents can be mutated without violating any references.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.cast(), size) };

        let ptr = value.ptr_with_addr(dst.cast());
        unsafe { std::rc::Rc::from_raw(ptr) }
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + UnsizedCopy> UnsizedCopyFrom for std::sync::Arc<T> {
    type Source = T;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        use core::mem::MaybeUninit;

        /// A [`u8`] with a custom alignment.
        #[derive(Copy, Clone)]
        #[repr(C)]
        struct AlignedU8<T>([T; 0], u8);

        // TODO(1.82): Use 'Arc::new_uninit_slice()'.
        // 'impl FromIterator for Arc' describes performance characteristics.
        // For efficiency, the iterator should implement 'TrustedLen', which
        // is (currently) a nightly-only trait.  However, we can use the
        // existing 'std' types which happen to implement it.
        let size = core::mem::size_of_val(value);
        let arc: std::sync::Arc<[MaybeUninit<AlignedU8<T::Alignment>>]> =
            (0..size).map(|_| MaybeUninit::uninit()).collect();

        let src = value as *const _ as *const u8;
        let dst = std::sync::Arc::into_raw(arc).cast_mut();
        // SAFETY: 'arc' was just constructed and has never been copied.  Thus,
        //   its contents can be mutated without violating any references.
        unsafe { core::ptr::copy_nonoverlapping(src, dst.cast(), size) };

        let ptr = value.ptr_with_addr(dst.cast());
        unsafe { std::sync::Arc::from_raw(ptr) }
    }
}

#[cfg(feature = "std")]
impl<T: UnsizedCopy> UnsizedCopyFrom for std::vec::Vec<T> {
    type Source = [T];

    fn unsized_copy_from(value: &Self::Source) -> Self {
        // We can't use 'impl From<&[T]> for Vec<T>', because that requires
        // 'T' to implement 'Clone'.  We could reuse the 'UnsizedCopyFrom'
        // impl for 'Box', but a manual implementation is probably better.

        let mut this = Self::with_capacity(value.len());
        let src = value.as_ptr();
        let dst = this.spare_capacity_mut() as *mut _ as *mut T;
        unsafe { core::ptr::copy_nonoverlapping(src, dst, value.len()) };
        // SAFETY: The first 'value.len()' elements are now initialized.
        unsafe { this.set_len(value.len()) };
        this
    }
}

#[cfg(feature = "std")]
impl UnsizedCopyFrom for std::string::String {
    type Source = str;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        value.into()
    }
}

//----------- copy_to_bump ---------------------------------------------------

/// Copy a value into a [`Bump`] allocator.
///
/// This works with [`UnsizedCopy`] values, which extends [`Bump`]'s native
/// functionality.
///
/// [`Bump`]: bumpalo::Bump
#[cfg(feature = "bumpalo")]
#[allow(clippy::mut_from_ref)] // using a memory allocator
pub fn copy_to_bump<'a, T: ?Sized + UnsizedCopy>(
    value: &T,
    bump: &'a bumpalo::Bump,
) -> &'a mut T {
    let layout = std::alloc::Layout::for_value(value);
    let ptr = bump.alloc_layout(layout).as_ptr();
    let src = value as *const _ as *const u8;
    unsafe { core::ptr::copy_nonoverlapping(src, ptr, layout.size()) };
    let ptr = value.ptr_with_addr(ptr.cast()).cast_mut();
    unsafe { &mut *ptr }
}
