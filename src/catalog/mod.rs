#![cfg(feature = "unstable-catalog")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-catalog")))]
#![warn(missing_docs)]
//! Reading and writing of catalog zones.
//!
//! A catalog zone, as defined by [RFC 9432], is an ordinary DNS zone whose
//! contents describe a collection of _member zones_. Catalog zones provide a
//! means of provisioning zones onto secondary name servers without per-zone
//! configuration: a _catalog producer_ publishes a catalog zone listing its
//! member zones, and a _catalog consumer_ transfers the catalog and adds or
//! removes the member zones automatically.
//!
//! This module provides the building blocks for both roles. The central type
//! is [`Catalog`], which captures the apex of a catalog zone together with
//! its [member zones][CatalogMember].
//!
//! # Consuming a catalog zone
//!
//! Given a catalog zone as a [`Zone`] (or a sequence of records), the
//! membership can be extracted with [`Catalog::parse_zone`] (or
//! [`Catalog::parse_records`]):
//!
//! ```no_run
//! use domain::catalog::Catalog;
//! use domain::zonetree::Zone;
//!
//! # fn example(zone: &Zone) -> Result<(), Box<dyn std::error::Error>> {
//! let catalog = Catalog::parse_zone(zone)?;
//! for member in catalog.members() {
//!     println!("member zone {}", member.name());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Producing a catalog zone
//!
//! Conversely, a [`Catalog`] can be turned into a [`Zone`] with
//! [`Catalog::to_zone`] or into a sequence of records with
//! [`Catalog::to_records`], ready to be served to catalog consumers.
//!
//! # Schema version and properties
//!
//! Only schema version 2 as defined by [RFC 9432] is supported. The
//! per-member `group` property (as used by, e.g., BIND) is recognised and
//! preserved; other properties are tolerated but ignored.
//!
//! [RFC 9432]: https://datatracker.ietf.org/doc/html/rfc9432
//! [`Zone`]: crate::zonetree::Zone

mod build;
mod parse;
mod types;

pub use self::types::{
    BuildCatalogError, Catalog, CatalogMember, ParseCatalogError,
};

#[cfg(test)]
mod test {
    use bytes::Bytes;

    use crate::base::iana::Class;
    use crate::base::name::Name;
    use crate::base::{Serial, Ttl};
    use crate::rdata::Soa;

    use super::{Catalog, CatalogMember, ParseCatalogError};

    /// Returns a catalog apex name for use in tests.
    fn apex() -> Name<Bytes> {
        Name::bytes_from_str("catalog.example.").unwrap()
    }

    /// Returns a member zone name for use in tests.
    fn member_name(label: &str) -> Name<Bytes> {
        Name::bytes_from_str(&format!("{label}.example.")).unwrap()
    }

    /// Returns an SOA record suitable for a generated catalog zone.
    fn soa(serial: u32) -> Soa<Name<Bytes>> {
        Soa::new(
            Name::bytes_from_str("invalid.").unwrap(),
            Name::bytes_from_str("invalid.").unwrap(),
            Serial(serial),
            Ttl::from_secs(3600),
            Ttl::from_secs(600),
            Ttl::from_secs(86400),
            Ttl::from_secs(3600),
        )
    }

    /// Builds a sample catalog with two members, one of which has a group.
    fn sample_catalog() -> Catalog {
        let mut catalog = Catalog::new(apex());
        catalog.push_member(CatalogMember::new(
            Bytes::from_static(b"id1"),
            member_name("one"),
        ));
        let mut member = CatalogMember::new(
            Bytes::from_static(b"id2"),
            member_name("two"),
        );
        member.set_group(Bytes::from_static(b"production"));
        catalog.push_member(member);
        catalog
    }

    #[test]
    fn build_then_parse_round_trips() {
        let original = sample_catalog();
        let ns = [Name::bytes_from_str("invalid.").unwrap()];
        let zone = original.to_zone(soa(1), &ns, Ttl::from_secs(0)).unwrap();

        let parsed = Catalog::parse_zone(&zone).unwrap();

        assert_eq!(parsed.apex(), original.apex());
        assert_eq!(parsed.serial(), Some(Serial(1)));
        assert_eq!(parsed.members(), original.members());
    }

    #[test]
    fn parse_records_collects_members_and_group() {
        let ns = [Name::bytes_from_str("invalid.").unwrap()];
        let records = sample_catalog()
            .to_records(soa(7), &ns, Ttl::from_secs(0))
            .unwrap();

        let catalog = Catalog::parse_records(apex(), records).unwrap();

        assert_eq!(catalog.members().len(), 2);
        assert_eq!(catalog.members()[0].id(), b"id1");
        assert_eq!(catalog.members()[0].name(), &member_name("one"));
        assert_eq!(catalog.members()[0].group(), None);
        assert_eq!(catalog.members()[1].id(), b"id2");
        let group = catalog.members()[1].group();
        assert_eq!(group, Some(b"production".as_ref()));
    }

    #[test]
    fn missing_version_is_rejected() {
        // A catalog with no version record at all.
        let apex = apex();
        let records = std::vec::Vec::new();
        assert_eq!(
            Catalog::parse_records(apex, records),
            Err(ParseCatalogError::MissingSchemaVersion),
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let ns = [Name::bytes_from_str("invalid.").unwrap()];
        let mut records = sample_catalog()
            .to_records(soa(1), &ns, Ttl::from_secs(0))
            .unwrap();

        // Replace the version TXT value with an unsupported version.
        use crate::base::name::NameBuilder;
        use crate::base::record::Record;
        use crate::rdata::{Txt, ZoneRecordData};
        let mut builder = NameBuilder::new_bytes();
        builder.append_label(b"version").unwrap();
        let version_name = builder.append_origin(&apex()).unwrap();
        records.retain(|record| record.owner() != &version_name);
        let bad_version = Txt::<Bytes>::build_from_slice(b"99").unwrap();
        records.push(Record::new(
            version_name,
            Class::IN,
            Ttl::from_secs(0),
            ZoneRecordData::Txt(bad_version),
        ));

        assert_eq!(
            Catalog::parse_records(apex(), records),
            Err(ParseCatalogError::UnsupportedSchemaVersion),
        );
    }
}
