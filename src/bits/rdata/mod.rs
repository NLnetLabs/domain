//! Resource data handling.

pub use self::traits::RecordData;
pub use self::generic::GenericRecordData;

pub mod traits;
pub mod generic;

pub mod rfc1035;
