//! Traits for abstracting away the backing store of a [`ZoneTree`].
//!
//! <div class="warning">
//!
//! These interfaces are unstable and are likely to change in future.
//!
//! </div>
//!
//! [`ZoneTree`]: super::ZoneTree
use core::any::Any;
use core::future::ready;
use core::ops::Deref;
use core::pin::Pin;

use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::Stream;

use crate::base::iana::Class;
use crate::base::name::Label;
use crate::base::{Name, Rtype, Serial, ToName};

use super::answer::Answer;
use super::error::OutOfZone;
use super::types::{InMemoryZoneDiff, ZoneCut};
use super::{SharedRr, SharedRrset, StoredName, WalkOp};

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
    ) -> Pin<
        Box<
            dyn Future<Output = Box<dyn WritableZone + 'static>>
                + Send
                + Sync
                + 'static,
        >,
    >;

    /// Returns an [`Any`] interface to the store.
    ///
    /// This can be used to obtain access to methods on the specific
    /// [`ZoneStore`] implementation. See [`Zone`] for how this can used to
    /// layer functionality on top of a zone.
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

    /// Asynchronous variant of [`query`][ReadableZone::query].
    fn query_async(
        &self,
        qname: Name<Bytes>,
        qtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<Answer, OutOfZone>> + Send + Sync>>
    {
        Box::pin(ready(self.query(qname, qtype)))
    }

    /// Asynchronous variant of [`walk`][ReadableZone::walk].
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
pub trait WritableZone: Send + Sync {
    /// Start a write operation for the zone.
    ///
    /// If `create_diff` is true the zone backing store is requested to create
    /// an [`InMemoryZoneDiff`] which will accumulate entries as changes are
    /// made to the zone and will be returned finally when [`commit()`] is
    /// invoked.
    ///
    /// Creating a diff is optional. If the backing store doesn't support
    /// diff creation [`commit()`] will return `None`.
    ///
    /// [`commit()`]: Self::commit
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
    >;

    /// Complete a write operation for the zone.
    ///
    /// This function commits the changes accumulated since [`open()`] was
    /// invoked. Clients who obtain a [`ReadableZone`] interface to this zone
    /// _before_ this function has been called will not see any of the changes
    /// made since the last commit. Only clients who obtain a [`ReadableZone`]
    /// _after_ invoking this function will be able to see the changes made
    /// since [`open()`] was called.
    ///
    /// If `create_diff` was set to `true` when [`open()`] was invoked then
    /// this function _may_ return `Some` if a diff was created. `None` may be
    /// returned if the zone backing store does not support creation of diffs
    /// or was unable to create a diff for some reason.
    ///
    /// [`open()`]: Self::open
    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<InMemoryZoneDiff>, io::Error>>
                + Send
                + Sync,
        >,
    >;
}

//------------ WritableZoneNode ----------------------------------------------

/// An asynchronous write interface to a particular node in a [`ZoneTree`].
///
/// [`ZoneTree`]: super::ZoneTree
pub trait WritableZoneNode: Send + Sync {
    /// Get a write interface to a child node of this node.
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
    >;

    /// Get an RRset of the given type at this node, if any.
    fn get_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<SharedRrset>, io::Error>>
                + Send
                + Sync,
        >,
    >;

    /// Replace the RRset at this node with the given RRset.
    fn update_rrset(
        &self,
        rrset: SharedRrset,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;

    /// Remove an RRset of the given type at this node, if any.
    fn remove_rrset(
        &self,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;

    /// Mark this node as a regular node.
    ///
    /// If this node has zone cut or CNAME data, calling this
    /// function will erase that data.
    fn make_regular(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;

    /// Mark this node as a zone cut.
    ///
    /// Any "regular" or CNAME data at this node will be lost.
    fn make_zone_cut(
        &self,
        cut: ZoneCut,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;

    /// Mark this node as a CNAME.
    ///
    /// Any "regular" or zone cut data at this node will be lost.
    fn make_cname(
        &self,
        cname: SharedRr,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;

    /// Recursively make all content at and below this point appear to be
    /// removed.
    fn remove_all(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send + Sync>>;
}

//------------ ZoneDiffItem ---------------------------------------------------

/// One difference item in a set of changes made to a zone.
///
/// Conceptually a diff is like a set of keys and values, representing a change
/// to a resource record set with key (owner name, resource type) and the value
/// being the changed resource records at that owner and with that type.
pub trait ZoneDiffItem {
    /// The owner name and resource record type.
    fn key(&self) -> &(StoredName, Rtype);

    /// The changed records.
    ///
    /// Each record has the same key (owner name and resource record type).
    fn value(&self) -> &SharedRrset;
}

//------------ ZoneDiff -------------------------------------------------------

/// A set of differences between two versions (SOA serial numbers) of a zone.
///
/// Often referred to simply as a "diff".
///
/// The default implementation of this trait supplied by the domain crate is
/// the [`InMemoryZoneDiff`]. As the name implies it stores its data in
/// memory.
///
/// In order however to support less local backing stores for diff data, such
/// as on-disk storage or in a database possibly reached via a network,
/// asynchronous access to the diff is supported via use of [`Future`]s and
/// [`Stream`]s.
pub trait ZoneDiff {
    /// A single item in the diff.
    type Item<'a>: ZoneDiffItem + Send
    where
        Self: 'a;

    /// The type of [`Stream`] used to access the diff records.
    type Stream<'a>: Stream<Item = Self::Item<'a>> + Send
    where
        Self: 'a;

    /// The serial number of the zone which was modified.
    fn start_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>>;

    /// The serial number of the zone that resulted from the modifications.
    fn end_serial(&self)
        -> Pin<Box<dyn Future<Output = Serial> + Send + '_>>;

    /// An stream of RRsets that were added to the zone.
    // TODO: Does this need to be Box<Pin<dyn Future<Output = Stream>>>?
    fn added(&self) -> Self::Stream<'_>;

    /// An stream of RRsets that were removed from the zone.
    // TODO: Does this need to be Box<Pin<dyn Future<Output = Stream>>>?
    fn removed(&self) -> Self::Stream<'_>;

    /// Get an RRset that was added to the zone, if present in the diff.
    fn get_added(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>>;

    /// Get an RRset that was removed from the zone, if present in the diff.
    fn get_removed(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>>;
}

//--- impl ZoneDiff for Arc

impl<T: ZoneDiff> ZoneDiff for Arc<T> {
    type Item<'a>
        = T::Item<'a>
    where
        Self: 'a;

    type Stream<'a>
        = T::Stream<'a>
    where
        Self: 'a;

    fn start_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Arc::deref(self).start_serial()
    }

    fn end_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Arc::deref(self).end_serial()
    }

    fn added(&self) -> Self::Stream<'_> {
        Arc::deref(self).added()
    }

    fn removed(&self) -> Self::Stream<'_> {
        Arc::deref(self).removed()
    }

    fn get_added(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Arc::deref(self).get_added(name, rtype)
    }

    fn get_removed(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Arc::deref(self).get_removed(name, rtype)
    }
}
