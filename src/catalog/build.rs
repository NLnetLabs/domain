//! Generating a catalog zone from its membership.

use std::collections::HashMap;
use std::vec::Vec;

use bytes::Bytes;

use crate::base::Ttl;
use crate::base::iana::{Class, Rtype};
use crate::base::name::NameBuilder;
use crate::base::record::Record;
use crate::rdata::{Ns, Ptr, Soa, Txt, ZoneRecordData};
use crate::zonetree::types::{
    Rrset, StoredName, StoredRecord, StoredRecordData,
};
use crate::zonetree::{Zone, ZoneBuilder};

use super::types::{BuildCatalogError, Catalog};

/// The schema version emitted in generated catalog zones.
const SUPPORTED_SCHEMA_VERSION: &[u8] = b"2";

/// The label introducing the member zone collection (`<id>.zones.<apex>`).
const ZONES_LABEL: &[u8] = b"zones";

/// The label carrying the catalog zone schema version.
const VERSION_LABEL: &[u8] = b"version";

/// The per-member property label carrying the group of a member zone.
const GROUP_LABEL: &[u8] = b"group";

impl Catalog {
    /// Generates the records of a catalog zone from this catalog.
    ///
    /// The generated zone consists of the apex SOA and NS records, the schema
    /// version record at `version.<apex>` and, for each member, a PTR record
    /// at `<id>.zones.<apex>` plus an optional `group` property record. All
    /// records use the given `ttl`.
    pub fn to_records(
        &self,
        soa: Soa<StoredName>,
        ns: &[StoredName],
        ttl: Ttl,
    ) -> Result<Vec<StoredRecord>, BuildCatalogError> {
        let apex = self.apex();
        let mut records = Vec::new();

        records.push(record(apex.clone(), ttl, ZoneRecordData::Soa(soa)));

        for nsdname in ns {
            records.push(record(
                apex.clone(),
                ttl,
                ZoneRecordData::Ns(Ns::new(nsdname.clone())),
            ));
        }

        let version_name = make_name(&[VERSION_LABEL], apex)?;
        let version = txt(SUPPORTED_SCHEMA_VERSION)?;
        records.push(record(version_name, ttl, version));

        for member in self.members() {
            let member_name = make_name(&[member.id(), ZONES_LABEL], apex)?;
            records.push(record(
                member_name,
                ttl,
                ZoneRecordData::Ptr(Ptr::new(member.name().clone())),
            ));

            if let Some(group) = member.group() {
                let labels = [GROUP_LABEL, member.id(), ZONES_LABEL];
                let group_name = make_name(&labels, apex)?;
                records.push(record(group_name, ttl, txt(group)?));
            }
        }

        Ok(records)
    }

    /// Generates a catalog [`Zone`] from this catalog.
    ///
    /// See [`Catalog::to_records`] for the records that make up the zone.
    pub fn to_zone(
        &self,
        soa: Soa<StoredName>,
        ns: &[StoredName],
        ttl: Ttl,
    ) -> Result<Zone, BuildCatalogError> {
        let records = self.to_records(soa, ns, ttl)?;

        let mut rrsets: HashMap<(StoredName, Rtype), Rrset> = HashMap::new();
        for record in records {
            let key = (record.owner().clone(), record.rtype());
            rrsets
                .entry(key)
                .or_insert_with(|| Rrset::new(record.rtype(), record.ttl()))
                .push_data(record.into_data());
        }

        let mut builder = ZoneBuilder::new(self.apex().clone(), Class::IN);
        for ((owner, _rtype), rrset) in rrsets {
            builder
                .insert_rrset(&owner, rrset.into_shared())
                .map_err(|_| BuildCatalogError::BadName)?;
        }

        Ok(builder.build())
    }
}

//------------ Helper functions ----------------------------------------------

/// Creates a stored record with the given owner, TTL and data.
fn record(
    owner: StoredName,
    ttl: Ttl,
    data: StoredRecordData,
) -> StoredRecord {
    Record::new(owner, Class::IN, ttl, data)
}

/// Builds TXT record data from a single octets slice.
fn txt(value: &[u8]) -> Result<StoredRecordData, BuildCatalogError> {
    Txt::<Bytes>::build_from_slice(value)
        .map(ZoneRecordData::Txt)
        .map_err(|_| BuildCatalogError::BadValue)
}

/// Builds an owner name by prepending the given labels to `apex`.
fn make_name(
    labels: &[&[u8]],
    apex: &StoredName,
) -> Result<StoredName, BuildCatalogError> {
    let mut builder = NameBuilder::new_bytes();
    for label in labels {
        builder
            .append_label(label)
            .map_err(|_| BuildCatalogError::BadName)?;
    }
    builder
        .append_origin(apex)
        .map_err(|_| BuildCatalogError::BadName)
}
