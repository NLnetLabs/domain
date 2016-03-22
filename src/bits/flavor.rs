//! The flavors of DNS data.
//!
//! Because of the various types of domain names, all DNS data comes
//! in one of three flavors: it can be `Owned`, that is, entirely
//! self-contained; `Ref` when its data references an underlying bytes
//! slice; `Lazy` when its data references an underlying DNS message and
//! domain names can be compressed.
//!
//! This module defines the `Flavor` trait for referencing these three
//! flavors as well as the actual flavors as types.

use std::marker::PhantomData;
use super::name;
use super::nest;


/// The trait for the three flavors of DNS data.
///
/// This trait doesn’t actually define any methods but rather only collects
/// the associated types for each flavor.
pub trait Flavor<'a>: Sized {
    type DName: name::DName;
    type Nest: nest::Nest<'a, Self>;
}


/// The flavor for owned DNS data.
pub struct Owned;

impl<'a> Flavor<'a> for Owned {
    type DName = name::OwnedDName;
    type Nest = nest::OwnedNest;
}

/// The flavor for DNS data referencing an underlying bytes slice.
pub struct Ref<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor<'a> for Ref<'a> {
    type DName = name::DNameRef<'a>;
    type Nest = nest::NestRef<'a>;
}


/// The flavor for DNS data referencing an underlying DNS message.
pub struct Lazy<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor<'a> for Lazy<'a> {
    type DName = name::LazyDName<'a>;
    type Nest = nest::LazyNest<'a>;
}
