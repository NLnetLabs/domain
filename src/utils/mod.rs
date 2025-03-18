//! Various utility modules.

use core::{ops::Deref, ptr::addr_of_mut};

#[cfg(feature = "std")]
use std::{alloc::Layout, boxed::Box, vec::Vec};

pub mod base16;
pub mod base32;
pub mod base64;

#[cfg(feature = "net")]
pub(crate) mod config;

//----------- UnsizedClone ---------------------------------------------------

/// The ability to clone a (possibly unsized) value.
///
/// # Safety
///
/// If `unsized_clone()` returns successfully (i.e. without panicking), `dst`
/// is initialized to a valid instance of `Self`.
pub unsafe trait UnsizedClone {
    /// Clone this value into the given space.
    ///
    /// # Safety
    ///
    /// `dst` must be allocated with the same size and alignment as `self`.
    unsafe fn unsized_clone(&self, dst: *mut ());

    /// Change the address of a pointer to [`Self`].
    ///
    /// When [`Self`] is used as the last field in a type that also implements
    /// [`ParseBytesByRef`], it may be dynamically sized, and so a pointer (or
    /// reference) to it may include additional metadata.  This metadata is
    /// included verbatim in any reference/pointer to the containing type.
    ///
    /// When the containing type implements [`UnsizedClone`], it needs to
    /// construct a reference/pointer to itself, which includes this metadata.
    /// Rust does not currently offer a general way to extract this metadata
    /// or pair it with another address, so this function is necessary.  The
    /// caller can construct a reference to [`Self`], then change its address
    /// to point to the containing type, then cast that pointer to the right
    /// type.
    ///
    /// # Implementing
    ///
    /// Most users will derive [`UnsizedClone`] and so don't need to worry
    /// about this.  For manual implementations:
    ///
    /// In the future, an adequate default implementation for this function
    /// may be provided.  Until then, it should be implemented using one of
    /// the following expressions:
    ///
    /// ```text
    /// fn ptr_with_address(
    ///     &self,
    ///     addr: *mut (),
    /// ) -> *const Self {
    ///     // If 'Self' is Sized:
    ///     addr.cast::<Self>()
    ///
    ///     // If 'Self' is an aggregate whose last field is 'last':
    ///     self.last.ptr_with_address(addr) as *mut Self
    /// }
    /// ```
    ///
    /// # Invariants
    ///
    /// For the statement `let result = Self::ptr_with_address(ptr, addr);`:
    ///
    /// - `result as usize == addr as usize`.
    /// - `core::ptr::metadata(result) == core::ptr::metadata(ptr)`.
    fn ptr_with_address(&self, addr: *mut ()) -> *mut Self;
}

macro_rules! impl_primitive_unsized_clone {
    ($type:ty) => {
        unsafe impl UnsizedClone for $type {
            unsafe fn unsized_clone(&self, dst: *mut ()) {
                let this = self.clone();
                unsafe { dst.cast::<Self>().write(this) };
            }

            fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
                addr.cast::<Self>()
            }
        }
    };
}

impl_primitive_unsized_clone!(bool);
impl_primitive_unsized_clone!(char);

impl_primitive_unsized_clone!(u8);
impl_primitive_unsized_clone!(u16);
impl_primitive_unsized_clone!(u32);
impl_primitive_unsized_clone!(u64);
impl_primitive_unsized_clone!(u128);
impl_primitive_unsized_clone!(usize);

impl_primitive_unsized_clone!(i8);
impl_primitive_unsized_clone!(i16);
impl_primitive_unsized_clone!(i32);
impl_primitive_unsized_clone!(i64);
impl_primitive_unsized_clone!(i128);
impl_primitive_unsized_clone!(isize);

impl_primitive_unsized_clone!(f32);
impl_primitive_unsized_clone!(f64);

unsafe impl<T: ?Sized> UnsizedClone for &T {
    unsafe fn unsized_clone(&self, dst: *mut ()) {
        unsafe { dst.cast::<Self>().write(*self) };
    }

    fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
        addr.cast()
    }
}

unsafe impl UnsizedClone for str {
    unsafe fn unsized_clone(&self, dst: *mut ()) {
        unsafe {
            self.as_bytes()
                .as_ptr()
                .copy_to_nonoverlapping(dst.cast(), self.len());
        }
    }

    fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
        // NOTE: The Rust Reference indicates that 'str' has the same layout
        // as '[u8]' [1].  This is also the most natural layout for it.  Since
        // there's no way to construct a '*const str' from raw parts, we will
        // just construct a raw slice and transmute it.
        //
        // [1]: https://doc.rust-lang.org/reference/type-layout.html#str-layout

        self.as_bytes().ptr_with_address(addr) as *mut Self
    }
}

unsafe impl<T: Clone> UnsizedClone for [T] {
    unsafe fn unsized_clone(&self, dst: *mut ()) {
        /// A drop guard.
        struct Guard<T> {
            /// The slice being written into.
            dst: *mut T,

            /// The number of initialized elements.
            num: usize,
        }

        impl<T> Drop for Guard<T> {
            fn drop(&mut self) {
                // Drop all initialized elements.
                unsafe {
                    core::ptr::slice_from_raw_parts_mut(self.dst, self.num)
                        .drop_in_place()
                };
            }
        }

        let mut guard = Guard {
            dst: dst.cast::<T>(),
            num: 0,
        };

        for elem in self {
            let elem = elem.clone();
            unsafe {
                guard.dst.add(guard.num).write(elem);
            }
            guard.num += 1;
        }
    }

    fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
        core::ptr::slice_from_raw_parts_mut(addr.cast(), self.len())
    }
}

unsafe impl<T: Clone, const N: usize> UnsizedClone for [T; N] {
    unsafe fn unsized_clone(&self, dst: *mut ()) {
        let this = self.clone();
        unsafe { dst.cast::<Self>().write(this) };
    }

    fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
        addr as *mut Self
    }
}

impl_primitive_unsized_clone!(());

macro_rules! impl_unsized_clone_tuple {
    ($last_idx:tt: $last_type:ident $(, $idx:tt: $type:ident)*) => {
        unsafe impl
        <$($type: Clone,)* $last_type: ?Sized + UnsizedClone>
        UnsizedClone for ($($type,)* $last_type,) {
            unsafe fn unsized_clone(&self, dst: *mut ()) {
                let dst: *mut Self = self.ptr_with_address(dst);
                unsafe {
                    $(addr_of_mut!((*dst).$idx).write(self.$idx.clone());)*
                    self.$last_idx.unsized_clone(addr_of_mut!((*dst).$last_idx).cast());
                }
            }

            fn ptr_with_address(&self, addr: *mut ()) -> *mut Self {
                self.$last_idx.ptr_with_address(addr) as *mut Self
            }
        }
    };
}

impl_unsized_clone_tuple!(0: A);
impl_unsized_clone_tuple!(1: B, 0: A);
impl_unsized_clone_tuple!(2: C, 0: A, 1: B);
impl_unsized_clone_tuple!(3: D, 0: A, 1: B, 2: C);
impl_unsized_clone_tuple!(4: E, 0: A, 1: B, 2: C, 3: D);
impl_unsized_clone_tuple!(5: F, 0: A, 1: B, 2: C, 3: D, 4: E);
impl_unsized_clone_tuple!(6: G, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F);
impl_unsized_clone_tuple!(7: H, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G);
impl_unsized_clone_tuple!(8: I, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H);
impl_unsized_clone_tuple!(9: J, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H, 8: I);
impl_unsized_clone_tuple!(10: K, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J);
impl_unsized_clone_tuple!(11: L, 0: A, 1: B, 2: C, 3: D, 4: E, 5: F, 6: G, 7: H, 8: I, 9: J, 10: K);

//----------- CloneFrom ------------------------------------------------------

/// A container that can be built by cloning.
pub trait CloneFrom: Sized + Deref {
    /// Clone a value into this container.
    fn clone_from(value: &Self::Target) -> Self;
}

#[cfg(feature = "std")]
impl<T: ?Sized + UnsizedClone> CloneFrom for Box<T> {
    fn clone_from(value: &Self::Target) -> Self {
        let layout = Layout::for_value(value);
        let ptr = unsafe { std::alloc::alloc(layout) };
        unsafe { value.unsized_clone(ptr.cast()) };
        let ptr = value.ptr_with_address(ptr.cast());
        unsafe { Box::from_raw(ptr) }
    }
}

#[cfg(feature = "std")]
impl<T: Clone> CloneFrom for Vec<T> {
    fn clone_from(value: &Self::Target) -> Self {
        value.into()
    }
}

//----------- clone_to_bump --------------------------------------------------

/// Clone a value into a [`Bump`] allocator.
///
/// This works with [`UnsizedClone`] values, which extends [`Bump`]'s native
/// functionality.
#[cfg(feature = "bumpalo")]
#[allow(clippy::mut_from_ref)] // using a memory allocator
pub fn clone_to_bump<'a, T: ?Sized + UnsizedClone>(
    value: &T,
    bump: &'a bumpalo::Bump,
) -> &'a mut T {
    let layout = Layout::for_value(value);
    let ptr = bump.alloc_layout(layout).as_ptr().cast::<()>();
    unsafe {
        value.unsized_clone(ptr);
    };
    let ptr = value.ptr_with_address(ptr);
    unsafe { &mut *ptr }
}
