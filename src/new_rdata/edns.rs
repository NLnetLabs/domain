//! Record data types for Extended DNS.
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use domain_macros::*;

use crate::new_base::build::{self, BuildIntoMessage, TruncationError};

//----------- Opt ------------------------------------------------------------

/// Extended DNS options.
#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, AsBytes, BuildBytes, ParseBytesByRef,
)]
#[repr(transparent)]
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
