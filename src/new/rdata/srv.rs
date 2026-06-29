//! The SRV record data type.
//!
//! See [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782).

use core::cmp::Ordering;

use crate::new::base::build::{
    AsBytes, BuildBytes, BuildInMessage, NameCompressor,
};
use crate::new::base::name::{CanonicalName, Name};
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- Srv ------------------------------------------------------------

/// The locations of services associated with this domain.
//
// TODO: Documentation.
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytesZC,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(C)]
pub struct Srv {
    /// The priority of this host.
    pub priority: U16,

    /// The relative weight for selection of this host.
    pub weight: U16,

    /// The port number on which the service is provided.
    pub port: U16,

    /// The domain name of the target host.
    pub name: Name,
}

//--- Canonical operations

impl CanonicalRecordData for Srv {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.priority.build_bytes(bytes)?;
        let bytes = self.weight.build_bytes(bytes)?;
        let bytes = self.port.build_bytes(bytes)?;
        let bytes = self.name.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        // `Srv` uses canonical comparisons by default.
        self.cmp(other)
    }
}

//--- Building into DNS messages

impl BuildInMessage for Srv {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = self.as_bytes();
        let end = start + bytes.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(bytes);
        Ok(end)
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Srv> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a Srv {}

impl<'a> ParseRecordDataBytes<'a> for &'a Srv {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SRV => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
