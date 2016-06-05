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
//! * <tt>[rfc1035](rfc1035/index.html)::[A](rfc1035/struct.A.html)</tt>
//!   (a host address),
//! * <tt>[rfc3596](rfc3596/index.html)::[AAAA](rfc3596/struct.AAAA.html)</tt>
//!   (IPv6 address),
//! * <tt>[rfc1035](rfc1035/index.html)::[CName](rfc1035/struct.CName.html)</tt>
//!   (the canonical name for an alias),
//! * <tt>[rfc1035](rfc1035/index.html)::[HInfo](rfc1035/struct.HInfo.html)</tt>
//!   (host information),
//! * <tt>[rfc1035](rfc1035/index.html)::[MB](rfc1035/struct.MB.html)</tt>
//!   (a mailbox domain name; experimental),
//! * <tt>[rfc1035](rfc1035/index.html)::[MD](rfc1035/struct.MD.html)</tt>
//!   (a mail destination; obsolete – use MX),
//! * <tt>[rfc1035](rfc1035/index.html)::[MF](rfc1035/struct.MF.html)</tt>
//!   (a mail forwarder; obsolete – use MX),
//! * <tt>[rfc1035](rfc1035/index.html)::[MG](rfc1035/struct.MG.html)</tt>
//!   (a mail group member; experimental),
//! * <tt>[rfc1035](rfc1035/index.html)::[MInfo](rfc1035/struct.MInfo.html)</tt>
//!   (mailbox or mail list information),
//! * <tt>[rfc1035](rfc1035/index.html)::[MR](rfc1035/struct.MR.html)</tt>
//!   (a mail rename domain name; experimental),
//! * <tt>[rfc1035](rfc1035/index.html)::[MX](rfc1035/struct.MX.html)</tt>
//!   (mail exchange),
//! * <tt>[rfc1035](rfc1035/index.html)::[NS](rfc1035/struct.NS.html)</tt>
//!   (an authoritative name server),
//! * <tt>[rfc1035](rfc1035/index.html)::[Null](rfc1035/struct.Null.html)</tt>
//!   (a null RR; experimental),
//! * <tt>[rfc1035](rfc1035/index.html)::[Ptr](rfc1035/struct.Ptr.html)</tt>
//!   (a domain name pointer),
//! * <tt>[rfc1035](rfc1035/index.html)::[Soa](rfc1035/struct.Soa.html)</tt>
//!   (marks the start of a zone of authority),
//! * <tt>[rfc1035](rfc1035/index.html)::[Txt](rfc1035/struct.Txt.html)</tt>
//!   (text strings),
//! * <tt>[rfc1035](rfc1035/index.html)::[Wks](rfc1035/struct.Wks.html)</tt>
//!   (a well known service description).
//!   

pub use self::rfc1035::*;
pub use self::rfc3596::*;

pub mod rfc1035;
pub mod rfc3596;
