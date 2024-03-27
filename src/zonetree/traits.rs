use bytes::Bytes;
use core::future::ready;
use core::pin::Pin;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::base::name::Label;
use crate::base::{Dname, Rtype};
use crate::zonefile::error::OutOfZone;

use super::answer::Answer;
use super::types::ZoneCut;
use super::{SharedRr, SharedRrset, StoredDname, WalkOp};

//------------ ZoneStore -----------------------------------------------------

pub trait ZoneStore: Debug + Sync + Send {
    /// Returns the class of the zone.
    fn class(&self) -> Class;

    /// Returns the apex name of the zone.
    fn apex_name(&self) -> &StoredDname;

    fn read(self: Arc<Self>) -> Box<dyn ReadableZone>;

    fn write(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>>>>;
}

//------------ ReadableZone --------------------------------------------------

pub trait ReadableZone: Send {
    fn is_async(&self) -> bool {
        true
    }

    //--- Sync variants

    fn query(
        &self,
        _qname: Dname<Bytes>,
        _qtype: Rtype,
    ) -> Result<Answer, OutOfZone>;

    fn walk(&self, _op: WalkOp);

    //--- Async variants

    fn query_async(
        &self,
        qname: Dname<Bytes>,
        qtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Result<Answer, OutOfZone>> + Send>> {
        Box::pin(ready(self.query(qname, qtype)))
    }

    fn walk_async(
        &self,
        op: WalkOp,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        self.walk(op);
        Box::pin(ready(()))
    }
}

//------------ WritableZone --------------------------------------------------

pub trait WritableZone {
    #[allow(clippy::type_complexity)]
    fn open(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>,
        >,
    >;

    fn commit(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;
}

//------------ WritableZoneNode ----------------------------------------------

pub trait WritableZoneNode {
    #[allow(clippy::type_complexity)]
    fn update_child(
        &self,
        label: &Label,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>,
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
