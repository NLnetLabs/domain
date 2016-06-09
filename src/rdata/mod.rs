//! Resource data implementations.
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are grouped by the RFCs they are defined in. All types are also
//! reimported into the top level here. Ie., for the A record type, you can
//! simple `use domain::rdata::AAAA` instead of
//! `use domain::rdata::rfc3596::AAAA` which nobody could possibly remember.
//!
//! Since rustdoc doesn’t list the types for a glob re-import, here is a list
//! of all the record data types defined somewhere in this module in
//! alphabetic order.
//!
//! * [rfc1035](rfc1035/index.html)::[A](rfc1035/struct.A.html)
//!   (a host address),
//! * [rfc3596](rfc3596/index.html)::[AAAA](rfc3596/struct.AAAA.html)
//!   (IPv6 address),
//! * [rfc1035](rfc1035/index.html)::[CName](rfc1035/struct.CName.html)
//!   (the canonical name for an alias),
//! * [rfc1035](rfc1035/index.html)::[HInfo](rfc1035/struct.HInfo.html)
//!   (host information),
//! * [rfc1035](rfc1035/index.html)::[MB](rfc1035/struct.MB.html)
//!   (a mailbox domain name; experimental),
//! * [rfc1035](rfc1035/index.html)::[MD](rfc1035/struct.MD.html)
//!   (a mail destination; obsolete – use MX),
//! * [rfc1035](rfc1035/index.html)::[MF](rfc1035/struct.MF.html)
//!   (a mail forwarder; obsolete – use MX),
//! * [rfc1035](rfc1035/index.html)::[MG](rfc1035/struct.MG.html)
//!   (a mail group member; experimental),
//! * [rfc1035](rfc1035/index.html)::[MInfo](rfc1035/struct.MInfo.html)
//!   (mailbox or mail list information),
//! * [rfc1035](rfc1035/index.html)::[MR](rfc1035/struct.MR.html)
//!   (a mail rename domain name; experimental),
//! * [rfc1035](rfc1035/index.html)::[MX](rfc1035/struct.MX.html)
//!   (mail exchange),
//! * [rfc1035](rfc1035/index.html)::[NS](rfc1035/struct.NS.html)
//!   (an authoritative name server),
//! * [rfc1035](rfc1035/index.html)::[Null](rfc1035/struct.Null.html)
//!   (a null RR; experimental),
//! * [rfc1035](rfc1035/index.html)::[Ptr](rfc1035/struct.Ptr.html)
//!   (a domain name pointer),
//! * [rfc1035](rfc1035/index.html)::[Soa](rfc1035/struct.Soa.html)
//!   (marks the start of a zone of authority),
//! * [rfc1035](rfc1035/index.html)::[Txt](rfc1035/struct.Txt.html)
//!   (text strings),
//! * [rfc1035](rfc1035/index.html)::[Wks](rfc1035/struct.Wks.html)
//!   (a well known service description).
//!   
//! See the [RRType](../bits/iana/enum.RRType.html) type for the complete set
//! of record types and, consequently, those types that are still missing.

pub use self::rfc1035::*;
pub use self::rfc3596::*;

pub mod rfc1035;
pub mod rfc3596;
