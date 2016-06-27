//! Record data from RFC 6891.
//!
//! This RFC contains the currently valid definition of the OPT resouce
//! record type originally defined in RFC 2671.
//!
//! OPT records actually requisition some of the fields of a DNS record for
//! their own purpose. Because of this, this module does not only define
//! the `Opt` type for the OPT resource data but also `OptRecord` for an
//! entire OPT record.


//------------ Opt ----------------------------------------------------------


