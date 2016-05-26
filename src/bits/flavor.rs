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
use super::octets;
use super::parse;


//------------ Flavor and FlatFlavor ----------------------------------------

/// The trait for the three flavors of DNS data.
///
/// This trait doesn’t actually define any methods but rather only collects
/// the associated types for each flavor.
pub trait Flavor: Sized {
    /// The type for domain names.
    type DName: name::DName;

    /// The type for character strings.
    type CString: cstring::CString;

    /// The type for opaque octet sequences.
    type Octets: octets::Octets;

    /// The type for nests.
    type Nest: nest::Nest;
}

/// The trait for DNS data stored in unparsed format: `Ref` and `Lazy`.
pub trait FlatFlavor<'a>: Flavor {
    /// The type for nests.
    type FlatNest: nest::FlatNest<'a, Self>;

    /// The type for parsers from this data.
    type Parser: parse::ParseFlavor<'a, Self> + Clone;
}


//------------ Owned --------------------------------------------------------

/// The flavor for owned DNS data.
///
/// With the owned flavor, all types used for storing the data are owning
/// data. For composite types this means that all members in turn own their
/// own data, too.
#[derive(Debug)]
pub struct Owned;

impl Flavor for Owned {
    type DName = name::OwnedDName;
    type CString = cstring::OwnedCString;
    type Octets = octets::OwnedOctets;
    type Nest = nest::OwnedNest;
}


//------------ Ref ----------------------------------------------------------

/// The flavor for DNS data referencing an underlying bytes slice.
///
/// With the ref flavor, data that is not `Copy` (generally everything
/// except simple integers) is kept in its wire format in the
/// underlying bytes slice.
#[derive(Debug)]
pub struct Ref<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor for Ref<'a> {
    type DName = name::DNameRef<'a>;
    type CString = cstring::CStringRef<'a>;
    type Octets = octets::OctetsRef<'a>;
    type Nest = nest::NestRef<'a>;
}

impl<'a> FlatFlavor<'a> for Ref<'a> {
    type FlatNest = nest::NestRef<'a>;
    type Parser = parse::SliceParser<'a>;
}


//------------ Lazy----------------------------------------------------------

/// The flavor for DNS data referencing an underlying DNS message.
///
/// The lazy flavor is generally the same as the `Ref` flavor except for
/// domain names which can be compressed and therefore need to keep a
/// slice of the original message around for transforming into uncompressed
/// domain names.
#[derive(Debug)]
pub struct Lazy<'a> {
    marker: PhantomData<&'a u8>
}

impl<'a> Flavor for Lazy<'a> {
    type DName = name::LazyDName<'a>;
    type CString = cstring::CStringRef<'a>;
    type Octets = octets::OctetsRef<'a>;
    type Nest = nest::LazyNest<'a>;
}

impl<'a> FlatFlavor<'a> for Lazy<'a> {
    type FlatNest = nest::LazyNest<'a>;
    type Parser = parse::ContextParser<'a>;
}

