use domain_macros::*;

use crate::new_base::CharStr;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- HInfo ----------------------------------------------------------

/// Information about the host computer.
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes, SplitBytes)]
pub struct HInfo<'a> {
    /// The CPU type.
    pub cpu: &'a CharStr,

    /// The OS type.
    pub os: &'a CharStr,
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for HInfo<'a> {
    /// Scan the data for an HINFO record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-hinfo = char-str ws+ char-str ws*
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let cpu = <&CharStr>::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let os = <&CharStr>::scan(scanner, alloc, buffer)?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self { cpu, os })
        } else {
            Err(ScanError::Custom("Unexpected data at end of HINFO record"))
        }
    }
}
