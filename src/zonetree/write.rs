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

pub trait WriteableZoneNode {
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    >;

    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;
}

pub trait WriteableZone {
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    >;

    fn commit(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;
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
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    > {
        let res = WriteNode::new_apex(self.clone())
            .map(|node| Box::new(node) as Box<dyn WriteableZoneNode>)
            .map_err(|err| io::Error::other(format!("Open error: {err}")));
        Box::pin(ready(res))
    }

    fn commit(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        let marker = self.zone_versions.write().update_current(self.version);
        self.zone_versions
            .write()
            .push_version(self.version, marker);

        // Start the next version.
        self.version = self.version.next();
        self.dirty = false;

        Box::pin(ready(Ok(())))
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
    fn update_child(&self, label: &Label) -> Result<WriteNode, io::Error> {
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

        Ok(node)
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
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<
                Output = Result<Box<dyn WriteableZoneNode>, io::Error>,
            >,
        >,
    > {
        let node = self
            .update_child(label)
            .map(|node| Box::new(node) as Box<dyn WriteableZoneNode>);
        Box::pin(ready(node))
    }

    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.update_rrset(rrset)))
    }

    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.remove_rrset(rtype)))
    }

    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.make_regular()))
    }

    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
        Box::pin(ready(self.make_zone_cut(cut)))
    }

    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>> {
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
