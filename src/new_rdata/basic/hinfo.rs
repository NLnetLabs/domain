//! The HINFO record data type.

use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{CanonicalRecordData, CharStr};

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
        use crate::utils::dst::copy_to_bump;

        HInfo {
            cpu: copy_to_bump(self.cpu, bump),
            os: copy_to_bump(self.os, bump),
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for HInfo<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this = (
            self.cpu.len(),
            &self.cpu.octets,
            self.os.len(),
            &self.os.octets,
        );
        let that = (
            that.cpu.len(),
            &that.cpu.octets,
            that.os.len(),
            &that.os.octets,
        );
        this.cmp(&that)
    }
}
