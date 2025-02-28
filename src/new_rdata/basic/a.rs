use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    wire::AsBytes,
};

//----------- A --------------------------------------------------------------

/// The IPv4 address of a host responsible for this domain.
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
pub struct A {
    /// The IPv4 address octets.
    pub octets: [u8; 4],
}

//--- Converting to and from 'Ipv4Addr'

impl From<Ipv4Addr> for A {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<A> for Ipv4Addr {
    fn from(value: A) -> Self {
        Self::from(value.octets)
    }
}

//--- Parsing from a string

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::from)
    }
}

//--- Formatting

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv4Addr::from(*self).fmt(f)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for A {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.as_bytes().build_into_message(builder)
    }
}
