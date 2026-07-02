//! The SRV record data type.
//!
//! See [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782).

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};

use crate::new::base::build::{
    AsBytes, BuildBytes, BuildInMessage, NameCompressor,
};
use crate::new::base::name::Name;
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
    Debug, AsBytes, BuildBytes, ParseBytesZC, SplitBytesZC, UnsizedCopy,
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
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
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

//--- Equality

impl PartialEq for Srv {
    fn eq(&self, other: &Self) -> bool {
        // All elements are compared bytewise.
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Srv {}

//--- Hashing

impl Hash for Srv {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes())
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
