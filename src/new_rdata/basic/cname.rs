use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    name::CanonicalName,
    parse::ParseMessageBytes,
    wire::{ParseError, TruncationError},
    CanonicalRecordData,
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- CName ----------------------------------------------------------

/// The canonical name for this domain.
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
    UnsizedClone,
)]
#[repr(transparent)]
pub struct CName<N: ?Sized> {
    /// The canonical name.
    pub name: N,
}

//--- Interaction

impl<N> CName<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> CName<R> {
        CName {
            name: (f)(self.name),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> CName<R> {
        CName {
            name: (f)(&self.name),
        }
    }
}

//--- Canonical operations

impl<N: ?Sized + CanonicalName> CanonicalRecordData for CName<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.name.build_lowercased_bytes(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.name.cmp_lowercase_composed(&other.name)
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for CName<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for CName<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N: Scan<'a>> Scan<'a> for CName<N> {
    /// Scan the data for a CNAME record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-cname = name ws*
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
            Err(ScanError::Custom("unexpected data at end of CNAME record"))
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

        use super::CName;

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
                <CName<RevNameBuf>>::scan(&mut scanner, &alloc, &mut buffer)
                    .map(|s| tmp.insert(s.name).as_bytes()),
                expected
            );
        }
    }
}
