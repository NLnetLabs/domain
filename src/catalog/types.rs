//! Core types for representing catalog zones.

use core::fmt;

use std::vec::Vec;

use bytes::Bytes;

use crate::base::Serial;
use crate::zonetree::types::StoredName;

//------------ Catalog -------------------------------------------------------

/// The membership information held in an RFC 9432 catalog zone.
///
/// A catalog zone is an ordinary DNS zone whose contents describe a set of
/// _member zones_. This type captures the information that a catalog consumer
/// or producer cares about: the catalog's own apex, its SOA serial (if known)
/// and the list of member zones together with their properties.
///
/// Use [`Catalog::parse_zone`] or [`Catalog::parse_records`] to extract this
/// information from a catalog zone, and [`Catalog::to_zone`] or
/// [`Catalog::to_records`] to generate a catalog zone from it.
///
/// [`Catalog::parse_zone`]: Catalog::parse_zone
/// [`Catalog::parse_records`]: Catalog::parse_records
/// [`Catalog::to_zone`]: Catalog::to_zone
/// [`Catalog::to_records`]: Catalog::to_records
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    /// The apex name of the catalog zone.
    apex: StoredName,

    /// The serial of the catalog zone, if it was determined while parsing.
    serial: Option<Serial>,

    /// The member zones described by the catalog.
    members: Vec<CatalogMember>,
}

impl Catalog {
    /// Creates a new, empty catalog with the given apex name.
    #[must_use]
    pub fn new(apex: StoredName) -> Self {
        Self {
            apex,
            serial: None,
            members: Vec::new(),
        }
    }

    /// Returns the apex name of the catalog zone.
    pub fn apex(&self) -> &StoredName {
        &self.apex
    }

    /// Returns the SOA serial of the catalog zone, if known.
    ///
    /// This is populated when the catalog is parsed from a zone that contains
    /// an apex SOA record. It is `None` for catalogs created via
    /// [`Catalog::new`].
    pub fn serial(&self) -> Option<Serial> {
        self.serial
    }

    /// Sets the SOA serial of the catalog zone.
    pub fn set_serial(&mut self, serial: Serial) {
        self.serial = Some(serial);
    }

    /// Returns the member zones described by the catalog.
    pub fn members(&self) -> &[CatalogMember] {
        &self.members
    }

    /// Adds a member zone to the catalog.
    pub fn push_member(&mut self, member: CatalogMember) {
        self.members.push(member);
    }
}

//------------ CatalogMember -------------------------------------------------

/// A single member zone described by a catalog zone.
///
/// Each member is identified within the catalog by a unique label and points
/// to a member zone name via a PTR record at `<id>.zones.<catalog-apex>`. A
/// member may additionally carry a `group` property which a consumer can use
/// to select differing configuration for the member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogMember {
    /// The unique identifier label of the member within the catalog.
    ///
    /// This is the single label found immediately before the `zones` label
    /// in the member's owner name. It carries no semantics beyond uniquely
    /// identifying the member within the catalog.
    id: Bytes,

    /// The name of the member zone.
    name: StoredName,

    /// The value of the member's `group` property, if present.
    group: Option<Bytes>,
}

impl CatalogMember {
    /// Creates a new member with the given identifier and zone name.
    #[must_use]
    pub fn new(id: Bytes, name: StoredName) -> Self {
        Self {
            id,
            name,
            group: None,
        }
    }

    /// Returns the unique identifier label of the member.
    pub fn id(&self) -> &[u8] {
        self.id.as_ref()
    }

    /// Returns the name of the member zone.
    pub fn name(&self) -> &StoredName {
        &self.name
    }

    /// Returns the value of the member's `group` property, if present.
    pub fn group(&self) -> Option<&[u8]> {
        self.group.as_ref().map(|group| group.as_ref())
    }

    /// Sets the value of the member's `group` property.
    pub fn set_group(&mut self, group: Bytes) {
        self.group = Some(group);
    }
}

//============ Error types ===================================================

//------------ ParseCatalogError ---------------------------------------------

/// An error that occurred while parsing a catalog zone.
///
/// Only catalog-wide problems are reported as errors. Individual member
/// entries that cannot be interpreted are silently ignored, in keeping with
/// the leniency expected of catalog consumers by RFC 9432.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseCatalogError {
    /// The catalog zone did not contain a schema version record.
    ///
    /// RFC 9432 requires a TXT record at `version.<catalog-apex>`.
    MissingSchemaVersion,

    /// The catalog zone declared a schema version that is not supported.
    ///
    /// This crate supports schema version 2 as defined by RFC 9432.
    UnsupportedSchemaVersion,
}

//--- Display and Error

impl fmt::Display for ParseCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseCatalogError::MissingSchemaVersion => {
                f.write_str("missing catalog zone schema version")
            }
            ParseCatalogError::UnsupportedSchemaVersion => {
                f.write_str("unsupported catalog zone schema version")
            }
        }
    }
}

impl std::error::Error for ParseCatalogError {}

//------------ BuildCatalogError ---------------------------------------------

/// An error that occurred while generating a catalog zone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuildCatalogError {
    /// A constructed owner name was not a valid domain name.
    ///
    /// This happens if a member identifier is not a valid label or if the
    /// resulting owner name would exceed the maximum domain name length.
    BadName,

    /// A property value could not be encoded as TXT record data.
    BadValue,
}

//--- Display and Error

impl fmt::Display for BuildCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildCatalogError::BadName => {
                f.write_str("invalid catalog member owner name")
            }
            BuildCatalogError::BadValue => {
                f.write_str("invalid catalog property value")
            }
        }
    }
}

impl std::error::Error for BuildCatalogError {}
