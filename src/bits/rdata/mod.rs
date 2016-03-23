//! Resource data handling.

pub use self::traits::{FlatRecordData, RecordData};
pub use self::generic::GenericRecordData;

pub mod traits;
pub mod generic;

pub mod rfc1035;
pub mod rfc3596;
