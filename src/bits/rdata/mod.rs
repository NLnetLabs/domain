//! Resource data handling.

pub use self::traits::{FlatRecordData, RecordData};
pub use self::generic::GenericRecordData;
pub use self::rfc1035::*;
pub use self::rfc3596::*;

pub mod traits;
pub mod generic;

pub mod rfc1035;
pub mod rfc3596;
