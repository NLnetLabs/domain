use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseError, U16},
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Mx -------------------------------------------------------------

/// A host that can exchange mail for this domain.
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
#[repr(C)]
pub struct Mx<N: ?Sized> {
    /// The preference for this host over others.
    pub preference: U16,

    /// The domain name of the mail exchanger.
    pub exchange: N,
}

//--- Interaction

impl<N> Mx<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Mx<R> {
        Mx {
            preference: self.preference,
            exchange: (f)(self.exchange),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Mx<R> {
        Mx {
            preference: self.preference,
            exchange: (f)(&self.exchange),
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Mx<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (&preference, rest) =
            <&U16>::split_message_bytes(contents, start)?;
        let exchange = N::parse_message_bytes(contents, rest)?;
        Ok(Self {
            preference,
            exchange,
        })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Mx<N> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        builder.append_bytes(self.preference.as_bytes())?;
        self.exchange.build_into_message(builder.delegate())?;
        Ok(builder.commit())
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N: Scan<'a>> Scan<'a> for Mx<N> {
    /// Scan the data for an MX record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-mx = u16 ws+ name ws*
    /// # An unsigned 16-bit integer.
    /// u16 = [0-9]+
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let preference = u16::scan(scanner, alloc, buffer)?.into();
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let exchange = N::scan(scanner, alloc, buffer)?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self {
                preference,
                exchange,
            })
        } else {
            Err(ScanError::Custom("unexpected data at end of MX record"))
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

        use super::Mx;

        let cases = [
            (
                b"20 example.org." as &[u8],
                Ok((20, b"\x00\x03org\x07example" as &[u8])),
            ),
            (b"20" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let mut tmp = None;
            assert_eq!(
                <Mx<RevNameBuf>>::scan(&mut scanner, &alloc, &mut buffer)
                    .map(|s| (
                        s.preference.get(),
                        tmp.insert(s.exchange).as_bytes()
                    )),
                expected
            );
        }
    }
}
