//! Importing from and exporting to a zonefiles.

use crate::base::iana::{Class, Rtype};
use crate::zonetree::{
    CnameError, Rrset, SharedRr, StoredDname, StoredRecord, ZoneBuilder,
    ZoneCutError,
};
use std::collections::{BTreeMap, HashMap};
use std::vec::Vec;

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
                Rtype::Ns | Rtype::Ds => {
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
    ///
    /// The content is inserted as the default flavor.
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
            let glue = self.normal.collect_glue(&name);

            if let Err(err) =
                builder.insert_zone_cut(&name, ns, ds, glue, None)
            {
                zone_err.add_error(name, OwnerError::InvalidZonecut(err))
            }
        }

        // Now insert all the CNAMEs.
        for (name, rrset) in self.cnames.into_iter() {
            if let Err(err) = builder.insert_cname(&name, rrset, None) {
                zone_err.add_error(name, OwnerError::InvalidCname(err))
            }
        }

        // Finally, all the normal records.
        for (name, rrsets) in self.normal.into_iter() {
            for (rtype, rrset) in rrsets.into_iter() {
                if builder
                    .insert_rrset(&name, rrset.into_shared(), None)
                    .is_err()
                {
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
    fn collect_glue(&mut self, _name: &StoredDname) -> Vec<StoredRecord> {
        unimplemented!()
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

/*
//------------ OwnerRecords --------------------------------------------------

/// The records of a single owner name.
#[derive(Clone, Default)]
pub struct OwnerRecords {
    records: HashMap<Rtype, Rrset>,
    special: Option<Special>,
}

impl OwnerRecords {
    fn insert(
        &mut self, record: StoredRecord
    ) -> Result<(), RecordError> {
        match record.rtype() {
            Rtype::Ns | Rtype::Ds => {
                self.switch_special(Special::ZoneCut)?;
            }
            Rtype::Cname => {
                self.switch_special(Special::Cname)?;
                if !self.records.is_empty() {
                    return Err(RecordError::MultipleCnames)
                }
            }
            _ => { }
        }
        let rrset = self.records.entry(record.rtype()).or_insert_with(|| {
            Rrset::new(record.rtype(), record.ttl())
        });
        rrset.limit_ttl(record.ttl());
        rrset.push_data(record.into_data());
        Ok(())
    }

    fn switch_special(
        &mut self, special: Special,
    ) -> Result<(), RecordError> {
        if self.special == Some(special) {
            Ok(())
        }
        else if self.special.is_none() && self.records.is_empty() {
            self.special = Some(special);
            Ok(())
        }
        else {
            match special {
                Special::ZoneCut => Err(RecordError::IllegalZoneCut),
                Special::Cname => Err(RecordError::IllegalCname)
            }
        }
    }

    /// Insert the records into a zone builder.
    fn insert_into_builder(
        self,
        name: StoredDname,
        additional: &BTreeMap<StoredDname, OwnerRecords>,
        builder: &mut ZoneBuilder
    ) {
        match self.special {
            None => {
                self.insert_builder_normal(name, additional, builder)
            }
            Some(Special::ZoneCut) => {
                self.insert_builder_cut(name, additional, builder)
            }
                /*
            Some(Special::Cname) => {
                self.insert_builder_cname(&mut builder, name, records)
            }
                */
            _ => unimplemented!()
        }
    }

    /// Insert the records of a non-special name into a zone builder.
    ///
    /// XXX This currently doesn’t do any additional section processing.
    fn insert_builder_normal(
        self,
        name: StoredDname,
        _additional: &BTreeMap<StoredDname, OwnerRecords>,
        builder: &mut ZoneBuilder
    ) {
        for record in self.records.into_values() {
            builder.insert_rrset(&name, record.into_shared(), None).unwrap();
        }
    }

    /// Inserts the records of a zone cut into a zone builder
    fn insert_builder_cut(
        self,
        name: StoredDname,
        _additional: &BTreeMap<StoredDname, OwnerRecords>,
        builder: &mut ZoneBuilder
    ) {
    }
}


//------------ Special -------------------------------------------------------

/// If an owner is special, what is it?
#[derive(Clone, Copy, Eq, PartialEq)]
enum Special {
    /// A zone cut.
    ZoneCut,

    /// A CNAME.
    Cname,
}
*/

//============ Errors ========================================================

//------------ RecordError ---------------------------------------------------

#[derive(Clone, Copy, Debug)]
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

/*
//------------ InsertZoneError -----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum InsertZoneError {
    /// The zone exist already.
    ZoneExists,
}
*/
