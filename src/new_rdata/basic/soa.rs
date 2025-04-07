use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    name::CanonicalName,
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, BuildBytes, ParseError, TruncationError, U32},
    CanonicalRecordData, Serial,
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Soa ------------------------------------------------------------

/// The start of a zone of authority.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    BuildBytes,
    ParseBytes,
    SplitBytes,
)]
pub struct Soa<N> {
    /// The name server which provided this zone.
    pub mname: N,

    /// The mailbox of the maintainer of this zone.
    pub rname: N,

    /// The version number of the original copy of this zone.
    pub serial: Serial,

    /// The number of seconds to wait until refreshing the zone.
    pub refresh: U32,

    /// The number of seconds to wait until retrying a failed refresh.
    pub retry: U32,

    /// The number of seconds until the zone is considered expired.
    pub expire: U32,

    /// The minimum TTL for any record in this zone.
    pub minimum: U32,
}

//--- Interaction

impl<N> Soa<N> {
    /// Map the domain names within to another type.
    pub fn map_names<R, F: FnMut(N) -> R>(self, mut f: F) -> Soa<R> {
        Soa {
            mname: (f)(self.mname),
            rname: (f)(self.rname),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }

    /// Map references to the domain names within to another type.
    pub fn map_names_by_ref<'r, R, F: FnMut(&'r N) -> R>(
        &'r self,
        mut f: F,
    ) -> Soa<R> {
        Soa {
            mname: (f)(&self.mname),
            rname: (f)(&self.rname),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Soa<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.mname.build_lowercased_bytes(bytes)?;
        let bytes = self.rname.build_lowercased_bytes(bytes)?;
        let bytes = self.serial.build_bytes(bytes)?;
        let bytes = self.refresh.build_bytes(bytes)?;
        let bytes = self.retry.build_bytes(bytes)?;
        let bytes = self.expire.build_bytes(bytes)?;
        let bytes = self.minimum.build_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.mname
            .cmp_lowercase_composed(&other.mname)
            .then_with(|| self.rname.cmp_lowercase_composed(&other.rname))
            .then_with(|| self.serial.as_bytes().cmp(other.serial.as_bytes()))
            .then_with(|| self.refresh.cmp(&other.refresh))
            .then_with(|| self.retry.cmp(&other.retry))
            .then_with(|| self.expire.cmp(&other.expire))
            .then_with(|| self.minimum.cmp(&other.minimum))
    }
}

//--- Parsing from DNS messages

impl<'a, N: SplitMessageBytes<'a>> ParseMessageBytes<'a> for Soa<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (mname, rest) = N::split_message_bytes(contents, start)?;
        let (rname, rest) = N::split_message_bytes(contents, rest)?;
        let (&serial, rest) = <&Serial>::split_message_bytes(contents, rest)?;
        let (&refresh, rest) = <&U32>::split_message_bytes(contents, rest)?;
        let (&retry, rest) = <&U32>::split_message_bytes(contents, rest)?;
        let (&expire, rest) = <&U32>::split_message_bytes(contents, rest)?;
        let &minimum = <&U32>::parse_message_bytes(contents, rest)?;

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
}

//--- Building into DNS messages

impl<N: BuildIntoMessage> BuildIntoMessage for Soa<N> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        self.mname.build_into_message(builder.delegate())?;
        self.rname.build_into_message(builder.delegate())?;
        builder.append_bytes(self.serial.as_bytes())?;
        builder.append_bytes(self.refresh.as_bytes())?;
        builder.append_bytes(self.retry.as_bytes())?;
        builder.append_bytes(self.expire.as_bytes())?;
        builder.append_bytes(self.minimum.as_bytes())?;
        Ok(builder.commit())
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a, N: Scan<'a>> Scan<'a> for Soa<N> {
    /// Scan the data for a SOA record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-soa = name ws+ name ws+ u32 ws+ u32 ws+ u32 ws+ u32 ws+ u32 ws*
    /// # An unsigned 32-bit integer.
    /// u32 = [0-9]+
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let mname = N::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let rname = N::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let serial = Serial::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let refresh = u32::scan(scanner, alloc, buffer)?.into();
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let retry = u32::scan(scanner, alloc, buffer)?.into();
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let expire = u32::scan(scanner, alloc, buffer)?.into();
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let minimum = u32::scan(scanner, alloc, buffer)?.into();

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self {
                rname,
                mname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })
        } else {
            Err(ScanError::Custom("unexpected data at end of SOA record"))
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new_base::{name::RevNameBuf, wire::U32, Serial};
        use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

        use super::Soa;

        let cases = [
            (
                b"VENERA Action.domains 20 7200 600 3600000 60" as &[u8],
                Ok((
                    "VENERA.com",
                    "Action.domains.com",
                    20,
                    7200,
                    600,
                    3600000,
                    60,
                )),
            ),
            (b"VENERA" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let origin = "com".parse::<RevNameBuf>().unwrap();
            let mut scanner = Scanner::new(input, Some(&origin));
            let expected = expected.map(|expected| Soa::<RevNameBuf> {
                mname: expected.0.parse().unwrap(),
                rname: expected.1.parse().unwrap(),
                serial: Serial::from(expected.2),
                refresh: U32::new(expected.3),
                retry: U32::new(expected.4),
                expire: U32::new(expected.5),
                minimum: U32::new(expected.6),
            });
            assert_eq!(
                <Soa<RevNameBuf>>::scan(&mut scanner, &alloc, &mut buffer),
                expected
            );
        }
    }
}
