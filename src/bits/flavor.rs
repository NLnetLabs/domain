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
use super::cstring;
use super::name;
use super::nest;


/// The trait for the three flavors of DNS data.
///
/// This trait doesn’t actually define any methods but rather only collects
/// the associated types for each flavor.
pub trait Flavor: Sized {
    type DName: name::DName;
    type CString: cstring::CString;
}

/// The trait for DNS data that is stored in unparsed format.
pub trait FlatFlavor<'a>: Flavor {
    type Nest: nest::Nest<'a, Self>;
}

/// The flavor for owned DNS data.
pub struct Owned;

impl Flavor for Owned {
    type DName = name::OwnedDName;
    type CString = cstring::OwnedCString;
}

/// The flavor for DNS data referencing an underlying bytes slice.
pub struct Ref<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor for Ref<'a> {
    type DName = name::DNameRef<'a>;
    type CString = cstring::CStringRef<'a>;
}

impl<'a> FlatFlavor<'a> for Ref<'a> {
    type Nest = nest::NestRef<'a>;
}


/// The flavor for DNS data referencing an underlying DNS message.
pub struct Lazy<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor for Lazy<'a> {
    type DName = name::LazyDName<'a>;
    type CString = cstring::CStringRef<'a>;
}

impl<'a> FlatFlavor<'a> for Lazy<'a> {
    type Nest = nest::LazyNest<'a>;
}
