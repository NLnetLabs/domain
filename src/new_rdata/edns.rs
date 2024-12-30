//! Record data types for Extended DNS.
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use zerocopy_derive::*;

use crate::new_base::build::{
    self, BuildInto, BuildIntoMessage, TruncationError,
};

//----------- Opt ------------------------------------------------------------

/// Extended DNS options.
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)] // 'derive(KnownLayout)' doesn't work with 'repr(transparent)'.
pub struct Opt {
    /// The raw serialized options.
    contents: [u8],
}

// TODO: Parsing the EDNS options.
// TODO: Formatting.

//--- Building into DNS messages

impl BuildIntoMessage for Opt {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.contents.build_into_message(builder)
    }
}

//--- Building into byte strings

impl BuildInto for Opt {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.contents.build_into(bytes)
    }
}
