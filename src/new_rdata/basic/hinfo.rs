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

//--- Interaction

impl HInfo<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> HInfo<'r> {
        use crate::utils::clone_to_bump;

        HInfo {
            cpu: clone_to_bump(self.cpu, bump),
            os: clone_to_bump(self.os, bump),
        }
    }
}
