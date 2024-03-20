//! Write access to zones.

use super::nodes::{Special, ZoneApex, ZoneCut, ZoneNode};
use super::rrset::{SharedRr, SharedRrset};
use super::versioned::Version;
use super::zone::ZoneVersions;
use crate::base::iana::Rtype;
use crate::base::name::Label;
use core::future::ready;
use futures::future::Either;
use parking_lot::RwLock;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::{fmt, io};
use tokio::sync::OwnedMutexGuard;

//------------ WritableZone --------------------------------------------------

#[macro_export]
macro_rules! write_zone_node {
    ($node:ident.update_child($label:expr)) => {
        match $node.is_async() {
            true => $node.update_child_async($label).await,
            false => $node.update_child($label),
        }
    };

    ($node:ident.update_rrset($rrset:expr)) => {
        match $node.is_async() {
            true => $node.update_rrset_async($rrset).await,
            false => $node.update_rrset($rrset),
        }
    };

    ($node:ident.remove_rrset($rrtype:expr)) => {
        match $node.is_async() {
            true => $node.remove_rrset_async($rrtype).await,
            false => $node.remove_rrset($rrtype),
        }
    };

    ($node:ident.make_regular()) => {
        match $node.is_async() {
            true => $node.make_regular_async().await,
            false => $node.make_regular(),
        }
    };

    ($node:ident.make_zone_cut($cut:expr)) => {
        match $node.is_async() {
            true => $node.make_zone_cut_async($cut).await,
            false => $node.make_zone_cut($cut),
        }
    };

    ($node:ident.make_cname($cname:expr)) => {
        match $node.is_async() {
            true => $node.make_cname_async($cname).await,
            false => $node.make_cname($cname),
        }
    };
}

pub trait WriteableZoneNode {
    fn is_async(&self) -> bool {
        true
    }

    //--- Sync variants

    fn update_child(
        &self,
        _label: &Label,
    ) -> Result<Box<dyn WriteableZoneNode>, io::Error> {
        unimplemented!()
    }

    fn update_rrset(&self, _rrset: SharedRrset) -> Result<(), io::Error> {
        unimplemented!()
    }

    fn remove_rrset(&self, _rtype: Rtype) -> Result<(), io::Error> {
        unimplemented!()
    }

    fn make_regular(&self) -> Result<(), io::Error> {
        unimplemented!()
    }

    fn make_zone_cut(&self, _cut: ZoneCut) -> Result<(), io::Error> {
        unimplemented!()
    }

    fn make_cname(&self, _cname: SharedRr) -> Result<(), io::Error> {
        unimplemented!()
    }

    //--- Async variants

    #[allow(clippy::type_complexity)]
    fn update_child_async(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    > {
        Box::pin(ready(self.update_child(label)))
    }

    fn update_rrset_async(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.update_rrset(rrset)))
    }

    fn remove_rrset_async(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.remove_rrset(rtype)))
    }

    fn make_regular_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.make_regular()))
    }

    fn make_zone_cut_async(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.make_zone_cut(cut)))
    }

    fn make_cname_async(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.make_cname(cname)))
    }
}

#[macro_export]
macro_rules! write_zone {
    ($zone:ident.open()) => {
        match $zone.is_async() {
            true => $zone.open_async().await,
            false => $zone.open(),
        }
    };

    ($zone:ident.commit()) => {
        match $zone.is_async() {
            true => $zone.commit_async().await,
            false => $zone.commit(),
        }
    };
}

pub trait WriteableZone {
    fn is_async(&self) -> bool;

    //--- Sync variants

    fn open(&self) -> Result<Box<dyn WriteableZoneNode>, io::Error> {
        unimplemented!()
    }

    fn commit(&mut self) -> Result<(), io::Error> {
        unimplemented!()
    }

    //--- Async variants

    #[allow(clippy::type_complexity)]
    fn open_async(
        &self,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    > {
        Box::pin(ready(self.open()))
    }

    fn commit_async(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.commit()))
    }
}

//------------ WriteZone -----------------------------------------------------

pub struct WriteZone {
    apex: Arc<ZoneApex>,
    _lock: Option<OwnedMutexGuard<()>>,
    version: Version,
    dirty: bool,
    zone_versions: Arc<RwLock<ZoneVersions>>,
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
        }
    }
}

impl Clone for WriteZone {
    fn clone(&self) -> Self {
        Self {
            apex: self.apex.clone(),
            _lock: None,
            version: self.version,
            dirty: self.dirty,
            zone_versions: self.zone_versions.clone(),
        }
    }
}

impl Drop for WriteZone {
    fn drop(&mut self) {
        if self.dirty {
            self.apex.rollback(self.version);
            self.dirty = false;
        }
    }
}

//--- impl WriteableZone

impl WriteableZone for WriteZone {
    fn is_async(&self) -> bool {
        false
    }

    fn open(&self) -> Result<Box<dyn WriteableZoneNode>, io::Error> {
        WriteNode::new_apex(self.clone())
            .map(|node| Box::new(node) as Box<dyn WriteableZoneNode>)
            .map_err(|err| io::Error::other(format!("Open error: {err}")))
    }

    fn commit(&mut self) -> Result<(), io::Error> {
        // The order here is important so we don’t accidentally remove the
        // newly created version right away.
        let marker = self.zone_versions.write().update_current(self.version);
        if let Some(version) = self.zone_versions.write().clean_versions() {
            self.apex.clean(version)
        }
        self.zone_versions
            .write()
            .push_version(self.version, marker);

        // Start the next version.
        self.version = self.version.next();
        self.dirty = false;

        Ok(())
    }
}

//------------ WriteNode ------------------------------------------------------

pub struct WriteNode {
    /// The writer for the zone we are working with.
    zone: WriteZone,

    /// The node we are updating.
    node: Either<Arc<ZoneApex>, Arc<ZoneNode>>,
}

impl WriteNode {
    fn new_apex(zone: WriteZone) -> Result<Self, io::Error> {
        let apex = zone.apex.clone();
        Ok(WriteNode {
            zone,
            node: Either::Left(apex),
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
}

//--- impl WriteableZoneNode

impl WriteableZoneNode for WriteNode {
    fn is_async(&self) -> bool {
        false
    }

    fn update_child(
        &self,
        label: &Label,
    ) -> Result<Box<dyn WriteableZoneNode>, io::Error> {
        let children = match self.node {
            Either::Left(ref apex) => apex.children(),
            Either::Right(ref node) => node.children(),
        };
        let (node, created) = children
            .with_or_default(label, |node, created| (node.clone(), created));
        let node = WriteNode {
            zone: self.zone.clone(),
            node: Either::Right(node),
        };
        if created {
            node.make_regular()?;
        }

        Ok(Box::new(node) as Box<dyn WriteableZoneNode>)
    }

    fn update_rrset(&self, rrset: SharedRrset) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Right(ref apex) => apex.rrsets(),
            Either::Left(ref node) => node.rrsets(),
        };
        rrsets.update(rrset, self.zone.version);
        self.check_nx_domain()?;
        Ok(())
    }

    fn remove_rrset(&self, rtype: Rtype) -> Result<(), io::Error> {
        let rrsets = match self.node {
            Either::Left(ref apex) => apex.rrsets(),
            Either::Right(ref node) => node.rrsets(),
        };
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
        .map_err(|err| io::Error::other(format!("WriteApexError: {err}")))
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
        .map_err(|err| io::Error::other(format!("WriteApexError: {err}")))
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
