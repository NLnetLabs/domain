use domain_macros::*;

use crate::new_base::CharStr;

//----------- HInfo ----------------------------------------------------------

/// Information about the host computer.
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes, SplitBytes)]
pub struct HInfo<'a> {
    /// The CPU type.
    pub cpu: &'a CharStr,

    /// The OS type.
    pub os: &'a CharStr,
}
