//! Parsing the membership of a catalog zone.

use std::boxed::Box;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use bytes::Bytes;

use crate::base::iana::Class;
use crate::base::name::Label;
use crate::base::record::Record;
use crate::rdata::ZoneRecordData;
use crate::zonetree::Zone;
use crate::zonetree::types::{StoredName, StoredRecord};

use super::types::{Catalog, CatalogMember, ParseCatalogError};

/// The catalog zone schema version supported by this crate.
const SUPPORTED_SCHEMA_VERSION: &[u8] = b"2";

/// The label introducing the member zone collection (`<id>.zones.<apex>`).
const ZONES_LABEL: &[u8] = b"zones";

/// The label carrying the catalog zone schema version.
const VERSION_LABEL: &[u8] = b"version";

/// The per-member property label carrying the group of a member zone.
const GROUP_LABEL: &[u8] = b"group";

impl Catalog {
    /// Parses the membership of a catalog zone from a [`Zone`].
    ///
    /// This walks the entire zone, interpreting its records according to
    /// RFC 9432. The catalog's apex is taken from the zone.
    ///
    /// Returns an error if the zone does not declare a supported schema
    /// version. Member entries that cannot be interpreted are ignored.
    pub fn parse_zone(zone: &Zone) -> Result<Self, ParseCatalogError> {
        let apex = zone.apex_name().clone();
        let records = Arc::new(Mutex::new(Vec::new()));
        let collector = records.clone();
        zone.read()
            .walk(Box::new(move |owner, rrset, _at_zone_cut| {
                let mut records = collector.lock().unwrap();
                for data in rrset.data() {
                    records.push(Record::new(
                        owner.clone(),
                        Class::IN,
                        rrset.ttl(),
                        data.clone(),
                    ));
                }
            }));

        // The walk has completed, so we are the only remaining reference.
        let records = Arc::try_unwrap(records)
            .map(|mutex| mutex.into_inner().unwrap())
            .unwrap_or_default();

        Self::parse_records(apex, records)
    }

    /// Parses the membership of a catalog zone from its records.
    ///
    /// The `apex` is the apex name of the catalog zone. The records may be
    /// supplied in any order.
    ///
    /// Returns an error if the records do not declare a supported schema
    /// version. Member entries that cannot be interpreted are ignored.
    pub fn parse_records<I>(
        apex: StoredName,
        records: I,
    ) -> Result<Self, ParseCatalogError>
    where
        I: IntoIterator<Item = StoredRecord>,
    {
        let mut version = Version::Missing;
        let mut serial = None;
        let mut members: HashMap<Bytes, PartialMember> = HashMap::new();

        for record in records {
            let owner = record.owner();
            let Some(prefix) = relative_labels(owner, &apex) else {
                continue;
            };

            match prefix.as_slice() {
                // The apex SOA gives us the catalog serial.
                [] => {
                    if let ZoneRecordData::Soa(soa) = record.data() {
                        serial = Some(soa.serial());
                    }
                }

                // `version.<apex>` carries the schema version.
                [label] if label_eq(label, VERSION_LABEL) => {
                    if let ZoneRecordData::Txt(txt) = record.data() {
                        let value = txt.text::<Vec<u8>>();
                        version = if value == SUPPORTED_SCHEMA_VERSION {
                            Version::Supported
                        } else {
                            Version::Unsupported
                        };
                    }
                }

                // `<id>.zones.<apex>` PTR points to a member zone.
                [id, zones] if label_eq(zones, ZONES_LABEL) => {
                    if let ZoneRecordData::Ptr(ptr) = record.data() {
                        let entry =
                            members.entry(label_bytes(id)).or_default();
                        entry.name = Some(ptr.ptrdname().clone());
                    }
                }

                // `<property>.<id>.zones.<apex>` carries a member property.
                [property, id, zones]
                    if label_eq(zones, ZONES_LABEL)
                        && label_eq(property, GROUP_LABEL) =>
                {
                    if let ZoneRecordData::Txt(txt) = record.data() {
                        let entry =
                            members.entry(label_bytes(id)).or_default();
                        entry.group =
                            Some(Bytes::from(txt.text::<Vec<u8>>()));
                    }
                }

                _ => {}
            }
        }

        match version {
            Version::Missing => {
                return Err(ParseCatalogError::MissingSchemaVersion);
            }
            Version::Unsupported => {
                return Err(ParseCatalogError::UnsupportedSchemaVersion);
            }
            Version::Supported => {}
        }

        let mut catalog = Catalog::new(apex);
        if let Some(serial) = serial {
            catalog.set_serial(serial);
        }

        // Only entries with a PTR record are valid members. Sort by
        // identifier to give callers a deterministic ordering.
        let mut entries: Vec<(Bytes, PartialMember)> =
            members.into_iter().collect();
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (id, entry) in entries {
            if let Some(name) = entry.name {
                let mut member = CatalogMember::new(id, name);
                if let Some(group) = entry.group {
                    member.set_group(group);
                }
                catalog.push_member(member);
            }
        }

        Ok(catalog)
    }
}

//------------ Version -------------------------------------------------------

/// The schema version state observed while parsing.
enum Version {
    /// No version record has been seen.
    Missing,

    /// A supported version record has been seen.
    Supported,

    /// A version record with an unsupported value has been seen.
    Unsupported,
}

//------------ PartialMember -------------------------------------------------

/// A member zone being assembled from several records.
#[derive(Default)]
struct PartialMember {
    /// The member zone name from its PTR record.
    name: Option<StoredName>,

    /// The value of the member's `group` property, if seen.
    group: Option<Bytes>,
}

//------------ Helper functions ----------------------------------------------

/// Returns the labels of `owner` that precede `apex`, if `owner` is in zone.
///
/// For an owner name of `<id>.zones.<apex>` this returns the labels `id` and
/// `zones`. Returns `None` if `owner` is not contained within `apex`.
fn relative_labels<'a>(
    owner: &'a StoredName,
    apex: &StoredName,
) -> Option<Vec<&'a Label>> {
    if !owner.ends_with(apex) {
        return None;
    }
    let prefix_len = owner.label_count().checked_sub(apex.label_count())?;
    Some(owner.iter().take(prefix_len).collect())
}

/// Compares a label against a byte slice, ignoring ASCII case.
fn label_eq(label: &Label, text: &[u8]) -> bool {
    label.as_slice().eq_ignore_ascii_case(text)
}

/// Copies the content of a label into a [`Bytes`].
fn label_bytes(label: &Label) -> Bytes {
    Bytes::copy_from_slice(label.as_slice())
}
