//! Importing from and exporting to a zonefiles.

use tracing::trace;

use crate::base::iana::{Class, Rtype};
use crate::base::name::FlattenInto;
use crate::base::ToDname;
use crate::rdata::ZoneRecordData;
use crate::zonetree::{
    CnameError, Rrset, SharedRr, StoredDname, StoredRecord, ZoneBuilder,
    ZoneCutError,
};
use core::convert::Infallible;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::vec::Vec;

use super::inplace::{self, Entry};

//------------ Zonefile ------------------------------------------------------

/// The content of a zonefile.
///
/// Note: This is a very simple version of how this may look later. It just
/// reads all the records and stores them so we can then insert them into the
/// zone tree.
#[derive(Clone)]
pub struct Zonefile {
    /// The name of the apex of the zone.
    apex: StoredDname,

    /// The class of the zone.
    class: Class,

    /// The records for names that have regular RRsets attached to them.
    normal: Owners<Normal>,

    /// The records for names that are zone cuts.
    zone_cuts: Owners<ZoneCut>,

    /// The records for names that are CNAMEs.
    cnames: Owners<SharedRr>,

    /// Out of zone records.
    out_of_zone: Owners<Normal>,
}

impl Zonefile {
    pub fn new(apex: StoredDname, class: Class) -> Self {
        Zonefile {
            apex,
            class,
            normal: Default::default(),
            zone_cuts: Default::default(),
            cnames: Default::default(),
            out_of_zone: Default::default(),
        }
    }

    /// Inserts the record into the zone file.
    pub fn insert(
        &mut self,
        record: StoredRecord,
    ) -> Result<(), RecordError> {
        trace!("{record}");
        if record.class() != self.class {
            return Err(RecordError::ClassMismatch);
        }
        if !record.owner().ends_with(&self.apex) {
            self.out_of_zone
                .entry(record.owner().clone())
                .insert(record);
            Ok(())
        } else {
            match record.rtype() {
                // An Name Server (NS) record at the apex is a nameserver RR
                // that indicates a server for the zone. An NS record is only
                // an indication of a zone cut when it is NOT at the apex.
                //
                // A Delegation Signer (DS) record can only appear within the
                // parent zone and refer to a child zone, a DS record cannot
                // therefore appear at the apex.
                Rtype::Ns | Rtype::Ds if record.owner() != &self.apex => {
                    if self.normal.contains(record.owner())
                        || self.cnames.contains(record.owner())
                    {
                        return Err(RecordError::IllegalZoneCut);
                    }
                    self.zone_cuts
                        .entry(record.owner().clone())
                        .insert(record);
                    Ok(())
                }
                Rtype::Cname => {
                    if self.normal.contains(record.owner())
                        || self.zone_cuts.contains(record.owner())
                    {
                        return Err(RecordError::IllegalCname);
                    }
                    if self.cnames.contains(record.owner()) {
                        return Err(RecordError::MultipleCnames);
                    }
                    self.cnames.insert(record.owner().clone(), record.into());
                    Ok(())
                }
                _ => {
                    if self.zone_cuts.contains(record.owner())
                        || self.cnames.contains(record.owner())
                    {
                        return Err(RecordError::IllegalRecord);
                    }
                    self.normal.entry(record.owner().clone()).insert(record);
                    Ok(())
                }
            }
        }
    }

    /// Inserts the content as a new zone into a zone set.
    pub fn into_zone_builder(mut self) -> Result<ZoneBuilder, ZoneError> {
        let mut builder = ZoneBuilder::new(self.apex.clone(), self.class);
        let mut zone_err = ZoneError::default();

        // Insert all the zone cuts first. Fish out potential glue records
        // from the normal or out-of-zone records.
        for (name, cut) in self.zone_cuts.into_iter() {
            let ns = match cut.ns {
                Some(ns) => ns.into_shared(),
                None => {
                    zone_err.add_error(name, OwnerError::MissingNs);
                    continue;
                }
            };
            let ds = cut.ds.map(Rrset::into_shared);
            let mut glue = vec![];
            for rdata in ns.data() {
                if let ZoneRecordData::Ns(ns) = rdata {
                    glue.append(&mut self.normal.collect_glue(ns.nsdname()));
                }
            }

            if let Err(err) = builder.insert_zone_cut(&name, ns, ds, glue) {
                zone_err.add_error(name, OwnerError::InvalidZonecut(err))
            }
        }

        // Now insert all the CNAMEs.
        for (name, rrset) in self.cnames.into_iter() {
            if let Err(err) = builder.insert_cname(&name, rrset) {
                zone_err.add_error(name, OwnerError::InvalidCname(err))
            }
        }

        // Finally, all the normal records.
        for (name, rrsets) in self.normal.into_iter() {
            for (rtype, rrset) in rrsets.into_iter() {
                if builder.insert_rrset(&name, rrset.into_shared()).is_err() {
                    zone_err.add_error(
                        name.clone(),
                        OwnerError::OutOfZone(rtype),
                    );
                }
            }
        }

        // If there are out-of-zone records left, we will error to avoid
        // surprises.
        for (name, rrsets) in self.out_of_zone.into_iter() {
            for (rtype, _) in rrsets.into_iter() {
                zone_err
                    .add_error(name.clone(), OwnerError::OutOfZone(rtype));
            }
        }

        zone_err.into_result().map(|_| builder)
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zonefile {
    type Error = RecordError;

    fn try_from(mut source: inplace::Zonefile) -> Result<Self, Self::Error> {
        let mut non_soa_records = Vec::<StoredRecord>::new();

        let mut sink = loop {
            let entry = source
                .next_entry()
                .map_err(|err| RecordError::MalformedRecord(err))?
                .ok_or(RecordError::MissingSoa)?;

            if let Entry::Record(record) = entry {
                match record.rtype() {
                    Rtype::Soa => {
                        let apex = record
                            .owner()
                            .to_dname()
                            .map_err(|_: Infallible| unreachable!())?;

                        let mut sink = Zonefile::new(apex, record.class());

                        for r in non_soa_records {
                            sink.insert(r)?;
                        }
                        sink.insert(record.flatten_into())?;
                        break sink;
                    }

                    _ => {
                        non_soa_records.push(record.flatten_into());
                    }
                }
            }
        };

        for res in source {
            match res.map_err(|err| RecordError::MalformedRecord(err))? {
                Entry::Record(r) => sink.insert(r.flatten_into())?,
                entry => {
                    trace!("Skipping unsupported zone file entry: {entry:?}")
                }
            }
        }

        Ok(sink)
    }
}

//------------ Owners --------------------------------------------------------

#[derive(Clone)]
struct Owners<Content> {
    owners: BTreeMap<StoredDname, Content>,
}

impl<Content> Owners<Content> {
    fn contains(&self, name: &StoredDname) -> bool {
        self.owners.contains_key(name)
    }

    fn insert(&mut self, name: StoredDname, content: Content) -> bool {
        use std::collections::btree_map::Entry;

        match self.owners.entry(name) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(content);
                true
            }
        }
    }

    fn entry(&mut self, name: StoredDname) -> &mut Content
    where
        Content: Default,
    {
        self.owners.entry(name).or_default()
    }

    fn into_iter(self) -> impl Iterator<Item = (StoredDname, Content)> {
        self.owners.into_iter()
    }
}

impl Owners<Normal> {
    fn collect_glue(&mut self, name: &StoredDname) -> Vec<StoredRecord> {
        let mut glue_records = vec![];

        // https://www.rfc-editor.org/rfc/rfc9471.html
        // 2.1. Glue for In-Domain Name Servers

        // For each NS delegation find the names of the nameservers the NS
        // records point to, and then see if the A/AAAA records for this names
        // are defined in the authoritative (normal) data for this zone, and
        // if so extract them.
        if let Some(normal) = self.owners.get(name) {
            // Now see if A/AAAA records exists for the name in
            // this zone.
            for (_rtype, rrset) in
                normal.records.iter().filter(|(&rtype, _)| {
                    rtype == Rtype::A || rtype == Rtype::Aaaa
                })
            {
                for rdata in rrset.data() {
                    let glue_record = StoredRecord::new(
                        name.clone(),
                        Class::In,
                        rrset.ttl(),
                        rdata.clone(),
                    );
                    glue_records.push(glue_record);
                }
            }
        }

        glue_records
    }
}

impl<Content> Default for Owners<Content> {
    fn default() -> Self {
        Owners {
            owners: Default::default(),
        }
    }
}

//------------ Normal --------------------------------------------------------

#[derive(Clone, Default)]
struct Normal {
    records: HashMap<Rtype, Rrset>,
}

impl Normal {
    fn insert(&mut self, record: StoredRecord) {
        use std::collections::hash_map::Entry;

        match self.records.entry(record.rtype()) {
            Entry::Occupied(mut occupied) => {
                occupied.get_mut().push_record(record)
            }
            Entry::Vacant(vacant) => {
                vacant.insert(record.into());
            }
        }
    }

    fn into_iter(self) -> impl Iterator<Item = (Rtype, Rrset)> {
        self.records.into_iter()
    }
}

//------------ ZoneCut -------------------------------------------------------

#[derive(Clone, Default)]
struct ZoneCut {
    ns: Option<Rrset>,
    ds: Option<Rrset>,
}

impl ZoneCut {
    fn insert(&mut self, record: StoredRecord) {
        match record.rtype() {
            Rtype::Ns => {
                if let Some(ns) = self.ns.as_mut() {
                    ns.push_record(record)
                } else {
                    self.ns = Some(record.into())
                }
            }
            Rtype::Ds => {
                if let Some(ds) = self.ds.as_mut() {
                    ds.push_record(record)
                } else {
                    self.ds = Some(record.into())
                }
            }
            _ => panic!("inserting wrong rtype to zone cut"),
        }
    }
}

//============ Errors ========================================================

//------------ RecordError ---------------------------------------------------

#[derive(Clone, Debug)]
pub enum RecordError {
    /// The class of the record does not match the class of the zone.
    ClassMismatch,

    /// Attempted to add zone cut records where there is no zone cut.
    IllegalZoneCut,

    /// Attempted to add a normal record to a zone cut or CNAME.
    IllegalRecord,

    /// Attempted to add a CNAME record where there are other records.
    IllegalCname,

    /// Attempted to add multiple CNAME records for an owner.
    MultipleCnames,

    /// The record could not be parsed.
    MalformedRecord(inplace::Error),

    /// The record is parseable but not valid.
    InvalidRecord(ZoneError),

    /// The SOA record was not found.
    MissingSoa,
}

impl Display for RecordError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecordError::ClassMismatch => write!(f, "ClassMismatch"),
            RecordError::IllegalZoneCut => write!(f, "IllegalZoneCut"),
            RecordError::IllegalRecord => write!(f, "IllegalRecord"),
            RecordError::IllegalCname => write!(f, "IllegalCname"),
            RecordError::MultipleCnames => write!(f, "MultipleCnames"),
            RecordError::MalformedRecord(err) => {
                write!(f, "MalformedRecord: {err}")
            }
            RecordError::InvalidRecord(err) => {
                write!(f, "InvalidRecord: {err}")
            }
            RecordError::MissingSoa => write!(f, "MissingSoa"),
        }
    }
}

//------------ ZoneError -----------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct ZoneError {
    errors: Vec<(StoredDname, OwnerError)>,
}

impl ZoneError {
    fn add_error(&mut self, name: StoredDname, error: OwnerError) {
        self.errors.push((name, error))
    }

    fn into_result(self) -> Result<(), Self> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

impl Display for ZoneError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Zone file errors: [")?;
        for err in &self.errors {
            write!(f, "'{}': {},", err.0, err.1)?;
        }
        write!(f, "]")
    }
}

//------------ OwnerError ---------------------------------------------------

#[derive(Clone, Debug)]
enum OwnerError {
    /// A NS RRset is missing at a zone cut.
    ///
    /// (This happens if there is only a DS RRset.)
    MissingNs,

    /// A zone cut appeared where it shouldn’t have.
    InvalidZonecut(ZoneCutError),

    /// A CNAME appeared where it shouldn’t have.
    InvalidCname(CnameError),

    /// A record is out of zone.
    OutOfZone(Rtype),
}

impl Display for OwnerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OwnerError::MissingNs => write!(f, "MissingNs"),
            OwnerError::InvalidZonecut(_) => write!(f, "InvalidZonecut"),
            OwnerError::InvalidCname(_) => write!(f, "InvalidCname"),
            OwnerError::OutOfZone(_) => write!(f, "OutOfZone"),
        }
    }
}
