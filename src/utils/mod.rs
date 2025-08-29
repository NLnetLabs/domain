//! Various utility modules.

use core::cmp::Ordering;

pub mod base16;
pub mod base32;
pub mod base64;

pub mod decoding;
pub mod dst;
pub mod encoding;

#[cfg(feature = "net")]
pub(crate) mod config;

//----------- CmpIter --------------------------------------------------------

/// A wrapper for comparing iterators.
#[derive(Copy, Clone, Debug)]
pub struct CmpIter<T>(pub T);

//--- Equality

impl<T, U> PartialEq<CmpIter<U>> for CmpIter<T>
where
    T: IntoIterator + Clone,
    U: IntoIterator + Clone,
    T::Item: PartialEq<U::Item>,
{
    fn eq(&self, other: &CmpIter<U>) -> bool {
        self.0.clone().into_iter().eq(other.0.clone())
    }
}

impl<T> Eq for CmpIter<T>
where
    T: IntoIterator + Clone,
    T::Item: Eq,
{
}

//--- Ordering

impl<T, U> PartialOrd<CmpIter<U>> for CmpIter<T>
where
    T: IntoIterator + Clone,
    U: IntoIterator + Clone,
    T::Item: PartialOrd<U::Item>,
{
    fn partial_cmp(&self, other: &CmpIter<U>) -> Option<Ordering> {
        self.0.clone().into_iter().partial_cmp(other.0.clone())
    }
}

impl<T> Ord for CmpIter<T>
where
    T: IntoIterator + Clone,
    T::Item: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.clone().into_iter().cmp(other.0.clone())
    }
}
