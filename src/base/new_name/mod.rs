//! Domain names.
//!
//! A _domain name_ is a sequence of _labels_ that names an entity within a
//! hierarchy.  In the domain name `www.example.org.`, the hierarchy is: `.`
//! (the root) -> `org.` -> `example.org.` -> `www.example.org.`.  Labels are
//! stored in reverse order, from innermost to outermost.

mod absolute;
pub use absolute::{Name, NameError, OwnedName};

mod relative;
pub use relative::{OwnedRelName, RelName, RelNameError};

mod uncertain;
pub use uncertain::{OwnedUncertainName, UncertainName, UncertainNameError};

mod label;
pub use label::{Label, LabelError, OwnedLabel};

mod idna;

mod labels;
pub use labels::Labels;

mod builder;
pub use builder::NameBuilder;

mod octets;
pub use octets::{Octets, Owned, SmallOctets};
