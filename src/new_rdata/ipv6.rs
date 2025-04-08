//! IPv6 record data types.
//!
//! See [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596).

use core::cmp::Ordering;
use core::fmt;
use core::net::Ipv6Addr;
use core::str::FromStr;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    wire::AsBytes,
    CanonicalRecordData,
};

//----------- Aaaa -----------------------------------------------------------

/// The IPv6 address of a host responsible for this domain.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct Aaaa {
    /// The IPv6 address octets.
    pub octets: [u8; 16],
}

//--- Converting to and from 'Ipv6Addr'

impl From<Ipv6Addr> for Aaaa {
    fn from(value: Ipv6Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<Aaaa> for Ipv6Addr {
    fn from(value: Aaaa) -> Self {
        Self::from(value.octets)
    }
}

//--- Canonical operations

impl CanonicalRecordData for Aaaa {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.octets.cmp(&other.octets)
    }
}

//--- Parsing from a string

impl FromStr for Aaaa {
    type Err = <Ipv6Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::from)
    }
}

//--- Formatting

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv6Addr::from(*self).fmt(f)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Aaaa {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.as_bytes().build_into_message(builder)
    }
}
