//! Domain names.

mod absolute;
pub use absolute::Name;

mod relative;
pub use relative::RelName;

mod parsed;
pub use parsed::ParsedName;

mod label;
pub use label::Label;
