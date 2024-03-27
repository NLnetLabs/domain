use bytes::Bytes;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::base::{Dname, Rtype};
use crate::zonefile::error::OutOfZone;

use super::answer::Answer;
use super::{Rrset, StoredDname};
use futures::stream::Stream;

//------------ ZoneStore -----------------------------------------------------

pub trait ZoneStore: Debug + Sync + Send {
    type QueryFut: Future<Output = Result<Answer, OutOfZone>>;
    type IterFut: Stream<Item = (Dname<Bytes>, Arc<Rrset>)>;

    /// Returns the class of the zone.
    fn class(&self) -> Class;

    /// Returns the apex name of the zone.
    fn apex_name(&self) -> &StoredDname;

    fn query(&self, qname: Dname<Bytes>, qtype: Rtype) -> Self::QueryFut;

    fn iter(&self) -> Self::IterFut;

    // fn write(&self) -> Self::WriteFut;
}

//------------ ReadableZone --------------------------------------------------

// pub trait ReadableZone: Send {
//     type QueryFut: Future<Output = Result<Answer, OutOfZone>>;
//     type Iter: Stream<Item = SharedRrset>;

//     fn query(
//         &self,
//         qname: Dname<Bytes>,
//         qtype: Rtype,
//     ) -> Result<Answer, OutOfZone>;

//     fn iter(&self) -> Self::Iter;
// }

//------------ WritableZone --------------------------------------------------

// pub trait WritableZone {
//     #[allow(clippy::type_complexity)]
//     fn open(
//         &self,
//     ) -> Pin<
//         Box<
//             dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>,
//         >,
//     >;

//     fn commit(
//         &mut self,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;
// }

//------------ WritableZoneNode ----------------------------------------------

// pub trait WritableZoneNode {
//     #[allow(clippy::type_complexity)]
//     fn update_child(
//         &self,
//         label: &Label,
//     ) -> Pin<
//         Box<
//             dyn Future<Output = Result<Box<dyn WritableZoneNode>, io::Error>>,
//         >,
//     >;

//     fn update_rrset(
//         &self,
//         rrset: SharedRrset,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

//     fn remove_rrset(
//         &self,
//         rtype: Rtype,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

//     fn make_regular(
//         &self,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

//     fn make_zone_cut(
//         &self,
//         cut: ZoneCut,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;

//     fn make_cname(
//         &self,
//         cname: SharedRr,
//     ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>>>>;
// }
