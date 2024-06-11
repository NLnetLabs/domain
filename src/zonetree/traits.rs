//! Traits for abstracting away the backing store of a [`ZoneTree`].
//!
//! <div class="warning">
//!
//! These interfaces are unstable and are likely to change in future.
//!
//! </div>
use core::future::ready;
use core::pin::Pin;

use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::sync::Arc;

use bytes::Bytes;

use crate::base::iana::Class;
use crate::base::name::Label;
use crate::base::{Name, Rtype};

use super::answer::Answer;
use super::error::OutOfZone;
use super::types::{ZoneCut, ZoneDiff};
use super::{SharedRr, SharedRrset, StoredName, WalkOp};
use core::any::Any;

//------------ ZoneStore -----------------------------------------------------

/// A [`Zone`] storage interface.
///
/// A [`ZoneStore`] provides a way to read [`Zone`]s from and write `Zone`s to
/// a particular backing store implementation.
///
/// [`Zone`]: super::Zone
pub trait ZoneStore: Debug + Sync + Send + Any {
    /// Returns the class of the zone.
    fn class(&self) -> Class;

    /// Returns the apex name of the zone.
    fn apex_name(&self) -> &StoredName;

    /// Get a read interface to this store.
    fn read(self: Arc<Self>) -> Box<dyn ReadableZone>;

    /// Get a write interface to this store.
    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send>>;

    /// TODO
    fn as_any(&self) -> &dyn Any;
}

//------------ ReadableZone --------------------------------------------------

/// A read interface to a [`Zone`].
///
/// A [`ReadableZone`] mplementation provides (a)synchronous read access to
/// the [`ZoneStore`] backing storage for a [`Zone`].
///
/// [`Zone`]: super::Zone
pub trait ReadableZone: Send + Sync {
    /// Returns true if ths `_async` variants of the functions offered by this
    /// trait should be used by callers instead of the non-`_async`
    /// equivalents.
    fn is_async(&self) -> bool {
        true
    }

    //--- Sync variants

    /// Lookup an [`Answer`] in the zone for a given QNAME and QTYPE.
    ///
    /// This function performs a synchronous query against the zone it
    /// provides access to, for a given QNAME and QTYPE. In combination with
    /// having first looked the zone up by CLASS this function enables a
    /// caller to obtain an [`Answer`] for an [RFC 1034 section 3.7.1]
    /// "Standard query".
    ///
    /// [RFC 1034 section 3.7.1]:
    ///     https://www.rfc-editor.org/rfc/rfc1034#section-3.7.1
    fn query(
        &self,
        _qname: Name<Bytes>,
        _qtype: Rtype,
    ) -> Result<Answer, OutOfZone>;

    /// Iterate over the entire contents of the zone.
    ///
    /// This function visits every node in the tree, synchronously, invoking
    /// the given callback function at every leaf node found.
    fn walk(&self, _op: WalkOp);

    //--- Async variants

    /// Asynchronous variant of `query()`.
    fn query_async(
        &self,
        qname: Name<Bytes>,
        qtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<Answer, OutOfZone>> + Send + Sync>>
    {
        Box::pin(ready(self.query(qname, qtype)))
    }

    /// Asynchronous variant of `walk()`.
    fn walk_async(
        &self,
        op: WalkOp,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> {
        self.walk(op);
        Box::pin(ready(()))
    }
}

//------------ WritableZone --------------------------------------------------

/// An asynchronous write interface to a [`Zone`].
///
/// [`Zone`]: super::Zone
pub trait WritableZone: Send {
    /// Start a write operation for the zone.
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
        create_diff: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send,
        >,
    >;

    /// Complete a write operation for the zone.
    ///
    /// This function commits the changes accumulated since [`open`] was
    /// invoked. Clients who obtain a [`ReadableZone`] interface to this zone
    /// _before_ this function has been called will not see any of the changes
    /// made since the last commit. Only clients who obtain a [`ReadableZone`]
    /// _after_ invoking this function will be able to see the changes made
    /// since [`open`] was called.
    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<ZoneDiff>, io::Error>> + Send>,
    >;
}

//------------ WritableZoneNode ----------------------------------------------

/// An asynchronous write interface to a particular node in a [`ZoneTree`].
///
/// [`ZoneTree`]: super::ZoneTree
pub trait WritableZoneNode: Send {
    /// Get a write interface to a child node of this node.
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>
                + Send,
        >,
    >;

    /// Replace the RRset at this node with the given RRset.
    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

    /// Remove an RRset of the given type at this node, if any.
    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

    /// Mark this node as a regular node.
    ///
    /// If this node has zone cut or CNAME data, calling this
    /// function will erase that data.
    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

    /// Mark this node as a zone cut.
    ///
    /// Any "regular" or CNAME data at this node will be lost.
    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

    /// Mark this node as a CNAME.
    ///
    /// Any "regular" or zone cut data at this node will be lost.
    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;
}
