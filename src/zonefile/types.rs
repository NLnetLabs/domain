use bytes::Bytes;

use crate::base::{Dname, Record};
use crate::rdata::ZoneRecordData;

//------------ Type Aliases --------------------------------------------------

/// A [`Bytes`] backed [`Dname`].
pub type StoredDname = Dname<Bytes>;

/// A [`Bytes`] backed [`ZoneRecordData`].
pub type StoredRecordData = ZoneRecordData<Bytes, StoredDname>;

/// A [`Bytes`] backed [`Record`].`
pub type StoredRecord = Record<StoredDname, StoredRecordData>;
