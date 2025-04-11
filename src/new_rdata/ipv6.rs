//! IPv6 record data types.
//!
//! See [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596).

use core::cmp::Ordering;

use core::fmt;
use core::net::Ipv6Addr;
use core::str::FromStr;

use domain_macros::*;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

use crate::new_base::{wire::AsBytes, CanonicalRecordData};

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

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl Scan<'_> for Aaaa {
    /// Scan the data for an AAAA record.
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'_ bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let addr = scanner
            .scan_plain_token()?
            .parse::<Ipv6Addr>()
            .map_err(|_| ScanError::Custom("invalid IPv6 address"))?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self::from(addr))
        } else {
            Err(ScanError::Custom("unexpected data at end of AAAA record"))
        }
    }
}
