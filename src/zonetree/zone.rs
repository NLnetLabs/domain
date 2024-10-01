use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::zonefile::inplace;

use super::error::{RecordError, ZoneErrors};
use super::in_memory::ZoneBuilder;
use super::traits::WritableZone;
use super::types::StoredName;
use super::{parsed, ReadableZone, ZoneStore};

//------------ ZoneKey -------------------------------------------------------

/// A key that uniquely identifies a zone.
///
/// A zone is identified by the owner name of the apex and its class. Every
/// record in a zone must be at or under the apex owner name and be of the
/// same class.
pub type ZoneKey = (StoredName, Class);

//------------ Zone ----------------------------------------------------------

/// A single DNS zone.
///
/// # Abstract backing store
///
/// The actual backing store implementation used by a [`Zone`] is determined
/// by the [`ZoeStore`] impl it wraps. In this way one can treat in-memory
/// zone implementations and other backing store types (for example a database
/// backed zone) in the same way, and even to store zones with different
/// backing stores together in the same [`ZoneTree`].
///
/// # Layering functionality
///
/// The functionality of [`Zone`]s can be extended by creating a [`ZoneStore`]
/// implementation that wraps another [`ZoneStore`] implementation with the
/// purpose of wrapping the original zone with additional state and
/// functionality.
///
/// This could be used to detect changes to the [`Zone`] via your own
/// [`WritableZone`] impl e.g. to sign it or persist it, or to detect updated
/// SOA timers, and so on.
///
/// To layer [`ZoneStore`] implementations on top of one another, use
/// [`Zone::into_inner()`] to obtain backing store implementation of a
/// [`Zone`] then store that (via [`Arc<dyn ZoneStore`]) in a wrapper type
/// that itself implements [`ZoneStore`], and then use [`Zone::new()`] to
/// create a new [`Zone`] based on the outer backing store impl.
///
/// Then to gain access to the additional functionality and state use
/// [`ZoneStore::as_any()`] and attempt to [`Any::downcast()`] to a
/// [`ZoneStore`] implementing type that was used earlier.
#[derive(Clone, Debug)]
pub struct Zone {
    store: Arc<dyn ZoneStore>,
}

impl Zone {
    /// Creates a new [`Zone`] instance with the given data.
    pub fn new(data: impl ZoneStore + 'static) -> Self {
        Zone {
            store: Arc::new(data),
        }
    }

    /// Exchange this [`Zone`] wrapper for the actual underlying backing store
    /// implementation.
    pub fn into_inner(self) -> Arc<dyn ZoneStore> {
        self.store
    }

    /// Gets the CLASS of this zone.
    pub fn class(&self) -> Class {
        self.store.class()
    }

    /// Gets the apex name of this zone.
    pub fn apex_name(&self) -> &StoredName {
        self.store.apex_name()
    }

    /// Gets a read interface to this zone.
    pub fn read(&self) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    /// Gets a write interface to this zone.
    pub fn write(
        &self,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send + Sync>>
    {
        self.store.clone().write()
    }

    /// Gets a key that uniquely identifies this zone.
    ///
    /// Note: Assumes that there is only ever one instance of a zone with a
    /// given apex name and class in a set of zones.
    pub fn key(&self) -> ZoneKey {
        (self.apex_name().clone(), self.class())
    }
}

impl AsRef<dyn ZoneStore> for Zone {
    fn as_ref(&self) -> &dyn ZoneStore {
        self.store.as_ref()
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zone {
    type Error = ZoneErrors<RecordError>;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?.try_into()
    }
}

//--- TryFrom<ZoneBuilder>

impl From<ZoneBuilder> for Zone {
    fn from(builder: ZoneBuilder) -> Self {
        builder.build()
    }
}

//--- TryFrom<parsed::Zonefile>

impl TryFrom<parsed::Zonefile> for Zone {
    type Error = ZoneErrors<RecordError>;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        Ok(Zone::from(ZoneBuilder::try_from(source).map_err(
            |errors| {
                let mut new_errors = Self::Error::default();
                for (name, err) in errors {
                    new_errors
                        .add_error(name, RecordError::InvalidRecord(err))
                }
                new_errors
            },
        )?))
    }
}
