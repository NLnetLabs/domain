use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::Deref,
};

/// A type backed by a byte string.
///
/// # Safety
///
/// A type `T` can implement `Octets` if and only if:
///
/// - It has the same layout as `[u8]` or `[u8; N]`.
/// - It can be safely transmuted into a byte slice.
/// - It can be fallibly transmuted from a byte slice.
pub unsafe trait Octets {
    /// Assume a byte string is a valid instance of `Self`.
    ///
    /// # Safety
    ///
    /// This function can only be called if `bytes` is known to be a valid
    /// instance of `Self` -- for example, if it was the result of `as_bytes()`.
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self;

    /// Access the byte string underlying `Self`.
    fn as_bytes(&self) -> &[u8];
}

unsafe impl Octets for [u8] {
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        bytes
    }

    fn as_bytes(&self) -> &[u8] {
        self
    }
}

unsafe impl<const N: usize> Octets for [u8; N] {
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        bytes.try_into().unwrap_unchecked()
    }

    fn as_bytes(&self) -> &[u8] {
        self
    }
}

unsafe impl Octets for str {
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        core::str::from_utf8_unchecked(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A bytes-backed type which can be stored in a buffer.
///
/// This trait should be implemented by types which can be stored in buffers of
/// some fixed size.  Due to limitations in const generics, the size cannot be
/// expressed as an associated constant; implementing types should support any
/// buffer type that implements `AsRef<[u8; MAX_SIZE]>`.
///
/// # Safety
///
/// A type `T` can soundly implement `SmallOctets<Buffer>` if:
///
/// - `Buffer` implements `AsRef<[u8; MAX_SIZE]>` for some `MAX_SIZE`.
/// - The size of `T` is always less than or equal to `MAX_SIZE`.
/// - `as_ref()` and `as_mut()` on `Buffer` always return the same slice.
pub unsafe trait SmallOctets<Buffer: AsRef<[u8]>>: Octets {}

unsafe impl<Buffer, const N: usize> SmallOctets<Buffer> for [u8; N] where
    Buffer: AsRef<[u8; N]> + AsRef<[u8]>
{
}

/// A byte string in a fixed-sized buffer.
pub struct Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + ?Sized,
{
    /// The underlying buffer.
    buffer: Buffer,

    /// The size of the value, in bytes.
    length: usize,

    /// The phantom representation of the value.
    _value: PhantomData<T>,
}

impl<Buffer, T> Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + ?Sized,
{
    /// Copy a value into an owned buffer.
    pub fn copy_from(value: &T) -> Self
    where
        Buffer: Default + AsMut<[u8]>,
    {
        let bytes = value.as_bytes();
        let length = bytes.len();
        let mut buffer = Buffer::default();
        buffer.as_mut()[..length].copy_from_slice(bytes);

        Self {
            buffer,
            length,
            _value: PhantomData,
        }
    }
}

impl<Buffer, T> Clone for Owned<Buffer, T>
where
    Buffer: Clone + AsRef<[u8]>,
    T: SmallOctets<Buffer> + ?Sized,
{
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            length: self.length,
            _value: PhantomData,
        }
    }
}

impl<Buffer, T, U> AsRef<U> for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + AsRef<U> + ?Sized,
    U: ?Sized,
{
    fn as_ref(&self) -> &U {
        let bytes = &self.buffer.as_ref()[..self.length];
        unsafe { T::from_bytes_unchecked(bytes) }.as_ref()
    }
}

impl<Buffer, T> Borrow<T> for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + ?Sized,
{
    fn borrow(&self) -> &T {
        let bytes = &self.buffer.as_ref()[..self.length];
        unsafe { T::from_bytes_unchecked(bytes) }
    }
}

impl<Buffer, T> PartialEq for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + PartialEq + ?Sized,
{
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<Buffer, T> Eq for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + Eq + ?Sized,
{
}

impl<Buffer, T> PartialOrd for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + PartialOrd + ?Sized,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<Buffer, T> Ord for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + Ord + ?Sized,
{
    fn cmp(&self, other: &Self) -> Ordering {
        (**self).cmp(&**other)
    }
}

impl<Buffer, T> Hash for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + Hash + ?Sized,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl<Buffer, T> Deref for Owned<Buffer, T>
where
    Buffer: AsRef<[u8]>,
    T: SmallOctets<Buffer> + ?Sized,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        let bytes = &self.buffer.as_ref()[..self.length];
        unsafe { T::from_bytes_unchecked(bytes) }
    }
}
