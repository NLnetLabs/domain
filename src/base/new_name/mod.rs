//! Domain names.
//!
//! A _domain name_ is a sequence of _labels_ that names an entity within a
//! hierarchy.  In the domain name `www.example.org.`, the hierarchy is: `.`
//! (the root) -> `org.` -> `example.org.` -> `www.example.org.`.  Labels are
//! stored in reverse order, from innermost to outermost.

mod absolute;
pub use absolute::{Name, NameError};

mod relative;
pub use relative::{RelName, RelNameError};

mod label;
pub use label::{Label, LabelError};

mod builder;
pub use builder::NameBuilder;
