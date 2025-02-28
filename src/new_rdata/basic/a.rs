use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;

use domain_macros::*;

use crate::new_base::wire::AsBytes;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

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

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl Scan<'_> for A {
    /// Scan the data for an A record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-a = ipv4-addr ws*
    ///   ipv4-addr = ipv4-octet "." ipv4-octet "." ipv4-octet "." ipv4-octet
    ///   # A decimal number between 0 and 255, inclusive.
    ///   ipv4-octet = [0-9]+
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'_ bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        buffer.clear();
        let token = scanner
            .scan_token(buffer)?
            .ok_or(ScanError::Custom("Missing IPv4 address"))?;
        let addr = core::str::from_utf8(token)
            .map_err(|_| ScanError::Custom("Invalid UTF-8 in IPv4 address"))?
            .parse::<Ipv4Addr>()
            .map_err(|_| ScanError::Custom("Invalid IPv4 address"))?;
        buffer.clear();

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self::from(addr))
        } else {
            Err(ScanError::Custom("Unexpected data at end of A record"))
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use super::A;

    #[cfg(feature = "zonefile")]
    #[test]
    fn scan_a() {
        use core::net::Ipv4Addr;

        use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

        let cases = [
            (
                b"127.0.0.1" as &[u8],
                Ok(A::from(Ipv4Addr::new(127, 0, 0, 1))),
            ),
            (
                b"a" as &[u8],
                Err(ScanError::Custom("Invalid IPv4 address")),
            ),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            assert_eq!(A::scan(&mut scanner, &alloc, &mut buffer), expected);
        }
    }
}
