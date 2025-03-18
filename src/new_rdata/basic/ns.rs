use core::fmt;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::ParseMessageBytes,
    wire::ParseError,
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Ns -------------------------------------------------------------

/// The authoritative name server for this domain.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BuildBytes,
    ParseBytes,
    SplitBytes,
    ParseBytesByRef,
    SplitBytesByRef,
    UnsizedClone,
)]
#[repr(transparent)]
pub struct Ns<N: ?Sized> {
    /// The name of the authoritative server.
    pub name: N,
}

//--- Interaction

impl<N> Ns<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Ns<R> {
        Ns {
            name: (f)(self.name),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Ns<R> {
        Ns {
            name: (f)(&self.name),
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Ns<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Ns<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}

//--- Formatting

impl<N: ?Sized + fmt::Display> fmt::Display for Ns<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N: Scan<'a>> Scan<'a> for Ns<N> {
    /// Scan the data for an NS record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-ns = name ws*
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let name = N::scan(scanner, alloc, buffer)?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self { name })
        } else {
            Err(ScanError::Custom("unexpected data at end of NS record"))
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new_base::name::RevNameBuf;
        use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

        use super::Ns;

        let cases = [
            (
                b"example.org." as &[u8],
                Ok(b"\x00\x03org\x07example" as &[u8]),
            ),
            (b"", Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let mut tmp = None;
            assert_eq!(
                <Ns<RevNameBuf>>::scan(&mut scanner, &alloc, &mut buffer)
                    .map(|s| tmp.insert(s.name).as_bytes()),
                expected
            );
        }
    }
}
