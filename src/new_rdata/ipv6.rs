//! IPv6 record data types.
//!
//! See [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596).

#[cfg(feature = "std")]
use core::{fmt, str::FromStr};

#[cfg(feature = "std")]
use std::net::Ipv6Addr;

use domain_macros::*;

use crate::new_base::wire::AsBytes;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

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

#[cfg(feature = "std")]
impl From<Ipv6Addr> for Aaaa {
    fn from(value: Ipv6Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

#[cfg(feature = "std")]
impl From<Aaaa> for Ipv6Addr {
    fn from(value: Aaaa) -> Self {
        Self::from(value.octets)
    }
}

//--- Parsing from a string

#[cfg(feature = "std")]
impl FromStr for Aaaa {
    type Err = <Ipv6Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::from)
    }
}

//--- Formatting

#[cfg(feature = "std")]
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
