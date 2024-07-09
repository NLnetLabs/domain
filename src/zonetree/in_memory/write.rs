//! Write access to zones.

use core::future::ready;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::vec::Vec;
use std::{fmt, io};

use futures::future::Either;
use parking_lot::RwLock;
use tokio::sync::OwnedMutexGuard;
use tracing::debug;
use tracing::trace;

use crate::base::iana::Rtype;
use crate::base::name::Label;
use crate::base::NameBuilder;
use crate::zonetree::types::{ZoneCut, ZoneDiff};
use crate::zonetree::StoredName;
use crate::zonetree::{Rrset, SharedRr};
use crate::zonetree::{SharedRrset, WritableZone, WritableZoneNode};

use super::nodes::{Special, ZoneApex, ZoneNode};
use super::versioned::{Version, VersionMarker};
use crate::rdata::ZoneRecordData;

//------------ WriteZone -----------------------------------------------------

pub struct WriteZone {
    apex: Arc<ZoneApex>,
    _lock: Option<OwnedMutexGuard<()>>,
    version: Version,
    dirty: bool,
    zone_versions: Arc<RwLock<ZoneVersions>>,
    diff: Arc<Mutex<Option<Arc<Mutex<ZoneDiff>>>>>,
}

impl WriteZone {
    pub(super) fn new(
        apex: Arc<ZoneApex>,
        _lock: OwnedMutexGuard<()>,
        version: Version,
        zone_versions: Arc<RwLock<ZoneVersions>>,
    ) -> Self {
        WriteZone {
            apex,
            _lock: Some(_lock),
            version,
            dirty: false,
            zone_versions,
            diff: Arc::new(Mutex::new(None)),
        }
    }
}

//--- impl Clone

impl Clone for WriteZone {
    fn clone(&self) -> Self {
        Self {
            apex: self.apex.clone(),
            _lock: None,
            version: self.version,
            dirty: self.dirty,
            zone_versions: self.zone_versions.clone(),
            diff: self.diff.clone(),
        }
    }
}

//--- impl Drop

impl Drop for WriteZone {
    fn drop(&mut self) {
        if self.dirty {
            self.apex.rollback(self.version);
            self.dirty = false;
        }
    }
}

//--- impl WritableZone

impl WritableZone for WriteZone {
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
        create_diff: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let new_apex = WriteNode::new_apex(self.clone(), create_diff);

        if let Ok(write_node) = &new_apex {
            // Note: the start and end serial of the diff will be filled in
            // when commit() is invoked.
            *self.diff.lock().unwrap() = write_node.diff();
        }

        let res = new_apex
            .map(|node| Box::new(node) as Box<dyn WritableZoneNode>)
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Open error: {err}"),
                )
            });

        Box::pin(ready(res))
    }

    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<ZoneDiff>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let mut out_diff = None;

        // An empty zone that is being filled by AXFR won't have an existing SOA.
        if let Some(old_soa_rr) = self.apex.get_soa(self.version.prev()) {
            let ZoneRecordData::Soa(old_soa) = old_soa_rr.data() else {
                unreachable!()
            };
            debug!("Commit: old_soa={old_soa:#?}");

            if bump_soa_serial {
                // Ensure that the SOA record in the zone is updated.
                let mut new_soa_rrset =
                    Rrset::new(Rtype::SOA, old_soa_rr.ttl());
                let new_soa_serial = old_soa.serial().add(1);
                let new_soa_data = crate::rdata::Soa::new(
                    old_soa.mname().clone(),
                    old_soa.rname().clone(),
                    new_soa_serial,
                    old_soa.refresh(),
                    old_soa.retry(),
                    old_soa.expire(),
                    old_soa.minimum(),
                );
                new_soa_rrset.push_data(new_soa_data.into());
                debug!("Commit: new_soa={new_soa_rrset:#?}");
                let new_soa_shared_rrset = SharedRrset::new(new_soa_rrset);

                self.apex
                    .rrsets()
                    .update(new_soa_shared_rrset.clone(), self.version);
            }

            // Extract the created diff, if any.
            if let Some(diff) = self.diff.lock().unwrap().take() {
                let mut removed_soa_rrset =
                    Rrset::new(Rtype::SOA, old_soa_rr.ttl());
                removed_soa_rrset.push_data(old_soa_rr.data().clone());
                let removed_soa_rrset = SharedRrset::new(removed_soa_rrset);

                let new_soa_rr = self.apex.get_soa(self.version).unwrap();
                let ZoneRecordData::Soa(new_soa) = new_soa_rr.data() else {
                    unreachable!()
                };

                let mut new_soa_shared_rrset =
                    Rrset::new(Rtype::SOA, new_soa_rr.ttl());
                new_soa_shared_rrset.push_data(new_soa_rr.data().clone());
                let new_soa_shared_rrset =
                    SharedRrset::new(new_soa_shared_rrset);

                let diff = arc_into_inner(diff).unwrap();
                let mut diff = Mutex::into_inner(diff).unwrap();
                diff.start_serial = Some(old_soa.serial());
                diff.end_serial = Some(new_soa.serial());
                diff.removed
                    .entry(self.apex.name().clone())
                    .or_default()
                    .push(removed_soa_rrset);
                diff.added
                    .entry(self.apex.name().clone())
                    .or_default()
                    .push(new_soa_shared_rrset);

                out_diff = Some(diff);
            }
        }

        // Make the new version visible.
        debug!("Commit: Making zone version '{:#?}' current", self.version);
        let marker = self.zone_versions.write().update_current(self.version);
        self.zone_versions
            .write()
            .push_version(self.version, marker);

        debug!("Commit: zone versions: {:#?}", self.zone_versions);
        // trace!("Commit: zone dump:\n{:#?}", self.apex);

        // Start the next version.
        self.version = self.version.next();
        self.dirty = false;

        Box::pin(ready(Ok(out_diff)))
    }
}

#[rustversion::since(1.70.0)]
fn arc_into_inner(this: Arc<Mutex<ZoneDiff>>) -> Option<Mutex<ZoneDiff>> {
    #[allow(clippy::incompatible_msrv)]
    Arc::into_inner(this)
}

// Taken from: https://github.com/rust-lang/rust/blob/129f3b9964af4d4a709d1383930ade12dfe7c081/library/alloc/src/sync.rs#L63
#[rustversion::before(1.70.0)]
macro_rules! acquire {
    ($x:expr) => {
        atomic::fence(std::sync::atomic::Ordering::Acquire)
    };
}

// Taken from: https://github.com/rust-lang/rust/blob/129f3b9964af4d4a709d1383930ade12dfe7c081/library/alloc/src/sync.rs#L1086
#[rustversion::before(1.70.0)]
fn arc_into_inner(this: Arc<Mutex<ZoneDiff>>) -> Option<Mutex<ZoneDiff>> {
    // Make sure that the ordinary `Drop` implementation isn’t called as well
    let mut this = std::mem::ManuallyDrop::new(this);

    // Following the implementation of `drop` and `drop_slow`
    if this
        .inner()
        .strong
        .fetch_sub(1, std::sync::atomic::Ordering::Release)
        != 1
    {
        return None;
    }

    acquire!(this.inner().strong);

    // SAFETY: This mirrors the line
    //
    //     unsafe { ptr::drop_in_place(Self::get_mut_unchecked(self)) };
    //
    // in `drop_slow`. Instead of dropping the value behind the pointer,
    // it is read and eventually returned; `ptr::read` has the same
    // safety conditions as `ptr::drop_in_place`.

    let inner = unsafe { ptr::read(Self::get_mut_unchecked(&mut this)) };
    let alloc = unsafe { ptr::read(&this.alloc) };

    drop(Weak {
        ptr: this.ptr,
        alloc,
    });

    Some(inner)
}

//------------ WriteNode ------------------------------------------------------

pub struct WriteNode {
    /// The writer for the zone we are working with.
    zone: WriteZone,

    /// The node we are updating.
    node: Either<Arc<ZoneApex>, Arc<ZoneNode>>,

    /// The diff we are building, if enabled.
    diff: Option<(StoredName, Arc<Mutex<ZoneDiff>>)>,
}

impl WriteNode {
    fn new_apex(
        zone: WriteZone,
        create_diff: bool,
    ) -> Result<Self, io::Error> {
        let apex = zone.apex.clone();

        let diff = if create_diff {
            Some((
                zone.apex.name().clone(),
                Arc::new(Mutex::new(ZoneDiff::new())),
            ))
        } else {
            None
        };

        Ok(WriteNode {
            zone,
            node: Either::Left(apex),
            diff,
        })
    }

    fn update_child(&self, label: &Label) -> Result<WriteNode, io::Error> {
        let children = match self.node {
            Either::Left(ref apex) => apex.children(),
            Either::Right(ref node) => node.children(),
        };

        let (node, created) = children
            .with_or_default(label, |node, created| (node.clone(), created));

        let diff = self.diff.as_ref().map(|(owner, diff)| {
            let mut builder = NameBuilder::new_bytes();
            builder.append_label(label.as_slice()).unwrap();
            let new_owner = builder.append_origin(&owner).unwrap();
            (new_owner, diff.clone())
        });

        let node = WriteNode {
            zone: self.zone.clone(),
            node: Either::Right(node),
            diff,
        };

        if created {
            node.make_regular()?;
        }

        Ok(node)
    }

    fn update_rrset(&self, rrset: SharedRrset) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Right(ref apex) => apex.rrsets(),
            Either::Left(ref node) => node.rrsets(),
        };

        trace!("Updating RRset");
        if let Some((owner, diff)) = &self.diff {
            trace!(
                "Diff found: v={:?}, rrsets: {rrsets:?}",
                self.zone.version
            );
            let changed = if let Some(removed_rrset) =
                rrsets.get(rrset.rtype(), self.zone.version)
            {
                let changed = rrset != removed_rrset;
                trace!("Changed = {changed}");

                if changed {
                    diff.lock()
                        .unwrap()
                        .removed
                        .entry(owner.clone())
                        .or_default()
                        .push(removed_rrset.clone());
                }

                changed
            } else {
                true
            };

            if changed {
                diff.lock()
                    .unwrap()
                    .added
                    .entry(owner.clone())
                    .or_default()
                    .push(rrset.clone());
            }
        }

        rrsets.update(rrset, self.zone.version);
        self.check_nx_domain()?;
        Ok(())
    }

    fn remove_rrset(&self, rtype: Rtype) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };

        if let Some((owner, diff)) = &self.diff {
            if let Some(removed) = rrsets.get(rtype, self.zone.version) {
                diff.lock()
                    .unwrap()
                    .removed
                    .entry(owner.clone())
                    .or_default()
                    .push(removed.clone());
            }
        }

        rrsets.remove(rtype, self.zone.version);
        self.check_nx_domain()?;

        Ok(())
    }

    fn make_regular(&self) -> Result<(), io::Error> {
        if let Either::Right(ref node) = self.node {
            node.update_special(self.zone.version, None);
            self.check_nx_domain()?;
        }
        Ok(())
    }

    fn make_zone_cut(&self, cut: ZoneCut) -> Result<(), io::Error> {
        match self.node {
            Either::Left(_) => Err(WriteApexError::NotAllowed),
            Either::Right(ref node) => {
                node.update_special(
                    self.zone.version,
                    Some(Special::Cut(cut)),
                );
                Ok(())
            }
        }
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write apex error: {err}"),
            )
        })
    }

    fn make_cname(&self, cname: SharedRr) -> Result<(), io::Error> {
        match self.node {
            Either::Left(_) => Err(WriteApexError::NotAllowed),
            Either::Right(ref node) => {
                node.update_special(
                    self.zone.version,
                    Some(Special::Cname(cname)),
                );
                Ok(())
            }
        }
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Write apex error: {err}"),
            )
        })
    }

    /// Makes sure a NXDomain special is set or removed as necesssary.
    fn check_nx_domain(&self) -> Result<(), io::Error> {
        let node = match self.node {
            Either::Left(_) => return Ok(()),
            Either::Right(ref node) => node,
        };
        let opt_new_nxdomain =
            node.with_special(self.zone.version, |special| match special {
                Some(Special::NxDomain) => {
                    if !node.rrsets().is_empty(self.zone.version) {
                        Some(false)
                    } else {
                        None
                    }
                }
                None => {
                    if node.rrsets().is_empty(self.zone.version) {
                        Some(true)
                    } else {
                        None
                    }
                }
                _ => None,
            });
        if let Some(new_nxdomain) = opt_new_nxdomain {
            if new_nxdomain {
                node.update_special(
                    self.zone.version,
                    Some(Special::NxDomain),
                );
            } else {
                node.update_special(self.zone.version, None);
            }
        }
        Ok(())
    }

    fn diff(&self) -> Option<Arc<Mutex<ZoneDiff>>> {
        self.diff.as_ref().map(|(_, diff)| diff.clone())
    }
}

//--- impl WritableZoneNode

impl WritableZoneNode for WriteNode {
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send
                + Sync,
        >,
    > {
        let node = self
            .update_child(label)
            .map(|node| Box::new(node) as Box<dyn WritableZoneNode>);
        Box::pin(ready(node))
    }

    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.update_rrset(rrset)))
    }

    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.remove_rrset(rtype)))
    }

    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_regular()))
    }

    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_zone_cut(cut)))
    }

    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>
    {
        Box::pin(ready(self.make_cname(cname)))
    }
}

//------------ WriteApexError ------------------------------------------------

/// The requested operation is not allowed at the apex of a zone.
#[derive(Debug)]
pub enum WriteApexError {
    /// This operation is not allowed at the apex.
    NotAllowed,

    /// An IO error happened while processing the operation.
    Io(io::Error),
}

impl From<io::Error> for WriteApexError {
    fn from(src: io::Error) -> WriteApexError {
        WriteApexError::Io(src)
    }
}

impl From<WriteApexError> for io::Error {
    fn from(src: WriteApexError) -> io::Error {
        match src {
            WriteApexError::NotAllowed => io::Error::new(
                io::ErrorKind::Other,
                "operation not allowed at apex",
            ),
            WriteApexError::Io(err) => err,
        }
    }
}

impl fmt::Display for WriteApexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WriteApexError::NotAllowed => {
                f.write_str("operation not allowed")
            }
            WriteApexError::Io(ref err) => err.fmt(f),
        }
    }
}

//------------ ZoneVersions --------------------------------------------------

#[derive(Debug)]
pub struct ZoneVersions {
    current: (Version, Arc<VersionMarker>),
    all: Vec<(Version, Weak<VersionMarker>)>,
}

impl ZoneVersions {
    pub fn update_current(&mut self, version: Version) -> Arc<VersionMarker> {
        let marker = Arc::new(VersionMarker);
        trace!(
            "Changing current zone version from {:?} to {version:?}",
            self.current
        );
        self.current = (version, marker.clone());
        marker
    }

    pub fn push_version(
        &mut self,
        version: Version,
        marker: Arc<VersionMarker>,
    ) {
        trace!("Pushing new zone version {version:?}");
        self.all.push((version, Arc::downgrade(&marker)))
    }

    pub fn clean_versions(&mut self) -> Option<Version> {
        let mut max_version = None;
        self.all.retain(|item| {
            if item.1.strong_count() > 0 {
                true
            } else {
                match max_version {
                    Some(old) => {
                        if item.0 > old {
                            max_version = Some(item.0)
                        }
                    }
                    None => max_version = Some(item.0),
                }
                false
            }
        });
        max_version
    }

    pub fn current(&self) -> &(Version, Arc<VersionMarker>) {
        &self.current
    }
}

impl Default for ZoneVersions {
    fn default() -> Self {
        let marker = Arc::new(VersionMarker);
        let weak_marker = Arc::downgrade(&marker);
        ZoneVersions {
            current: (Version::default(), marker),
            all: vec![(Version::default(), weak_marker)],
        }
    }
}
