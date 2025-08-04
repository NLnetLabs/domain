//! The RRSIG record data type.

use core::cmp::Ordering;

use domain_macros::*;

#[cfg(feature = "zonefile")]
use time::{Date, Month, PrimitiveDateTime, Time};

use crate::new::base::build::BuildInMessage;
use crate::new::base::name::{CanonicalName, Name, NameCompressor};
use crate::new::base::wire::{AsBytes, BuildBytes, TruncationError, U16};
use crate::new::base::{CanonicalRecordData, RType, Serial, TTL};

#[cfg(feature = "zonefile")]
use crate::{
    new::zonefile::scanner::{Scan, ScanError, Scanner},
    utils::decoding::Base64Dec,
};

use super::SecAlg;

//----------- RRSig ----------------------------------------------------------

/// A cryptographic signature on a DNS record set.
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes)]
pub struct RRSig<'a> {
    /// The type of the RRset being signed.
    pub rtype: RType,

    /// The cryptographic algorithm used to construct the signature.
    pub algorithm: SecAlg,

    /// The number of labels in the signed RRset's owner name.
    pub labels: u8,

    /// The (original) TTL of the signed RRset.
    pub ttl: TTL,

    /// The point in time when the signature expires.
    pub expiration: Serial,

    /// The point in time when the signature was created.
    pub inception: Serial,

    /// The key tag of the key used to make the signature.
    pub keytag: U16,

    /// The name identifying the signer.
    pub signer: &'a Name,

    /// The serialized cryptographic signature.
    pub signature: &'a [u8],
}

//--- Interaction

impl RRSig<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> RRSig<'r> {
        use crate::utils::dst::copy_to_bump;

        RRSig {
            signer: copy_to_bump(self.signer, bump),
            signature: bump.alloc_slice_copy(self.signature),
            ..self.clone()
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for RRSig<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this_initial = (
            self.rtype,
            self.algorithm,
            self.labels,
            self.ttl,
            self.expiration.as_bytes(),
            self.inception.as_bytes(),
            self.keytag,
        );
        let that_initial = (
            that.rtype,
            that.algorithm,
            that.labels,
            that.ttl,
            that.expiration.as_bytes(),
            that.inception.as_bytes(),
            that.keytag,
        );
        this_initial
            .cmp(&that_initial)
            .then_with(|| self.signer.cmp_lowercase_composed(that.signer))
            .then_with(|| self.signature.cmp(that.signature))
    }
}

//--- Building in DNS messages

impl BuildInMessage for RRSig<'_> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = contents.get_mut(start..).ok_or(TruncationError)?;
        let rest = self.build_bytes(bytes)?.len();
        Ok(contents.len() - rest)
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for RRSig<'a> {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        fn parse_timestamp(text: &str) -> Result<Serial, ScanError> {
            use core::num::IntErrorKind;

            if !text.chars().all(|c| c.is_ascii_digit()) {
                return Err(ScanError::Custom(
                    "invalid characters in RRSIG timestamp",
                ));
            }

            if text.len() != 14 {
                return text.parse::<u32>().map(Into::into).map_err(|err| {
                    ScanError::Custom(match err.kind() {
                        IntErrorKind::PosOverflow => {
                            "overly large UNIX timestamp"
                        }
                        // We have already checked for other kinds of errors.
                        _ => unreachable!(),
                    })
                });
            }

            // Format: YYYYMMDDHHmmSS
            let year = text[0..4].parse().unwrap();
            let month: u8 = text[4..6].parse().unwrap();
            let day = text[6..8].parse().unwrap();
            let hour = text[8..10].parse().unwrap();
            let minute = text[10..12].parse().unwrap();
            let second = text[12..14].parse().unwrap();

            let time = PrimitiveDateTime::new(
                Month::try_from(month)
                    .and_then(|month| {
                        Date::from_calendar_date(year, month, day)
                    })
                    .map_err(|_| {
                        ScanError::Custom(
                            "invalid calendar date in RRSIG timestamp",
                        )
                    })?,
                Time::from_hms(hour, minute, second).map_err(|_| {
                    ScanError::Custom(
                        "invalid calendar time in RRSIG timestamp",
                    )
                })?,
            )
            .assume_utc()
            .unix_timestamp() as u32;

            Ok(Serial::from(time))
        }

        let rtype = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let algorithm = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let labels = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let ttl = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let expiration = parse_timestamp(scanner.scan_plain_token()?)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let inception = parse_timestamp(scanner.scan_plain_token()?)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let keytag = Scan::scan(scanner, alloc, buffer).map(U16::new)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let signer = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let start = buffer.len();
        let mut decoder = Base64Dec::new();
        while !scanner.is_empty() {
            let token = scanner.scan_plain_token()?;
            scanner.skip_ws();

            decoder.decode_to_vec(token.as_bytes(), buffer).map_err(
                |_| ScanError::Custom("invalid Base64 in RRSIG signature"),
            )?;
        }
        decoder.finish(&mut [], false).map_err(|_| {
            ScanError::Custom(
                "partial block in Base64-encoded RRSIG signature",
            )
        })?;
        let signature = alloc.alloc_slice_copy(&buffer[start..]);
        buffer.truncate(start);

        Ok(Self {
            rtype,
            algorithm,
            labels,
            ttl,
            expiration,
            inception,
            keytag,
            signer,
            signature,
        })
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new::base::{name::NameBuf, RType};
        use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

        use super::RRSig;

        let name = "example.com".parse::<NameBuf>().unwrap();
        let cases = [
            (
                b"A 5 3 86400 20030322173103 20030220173103 2642 example.com. oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr" as &[u8],
                Ok((
                    RType::A,
                    5,
                    3,
                    86400,
                    1048354263,
                    1045762263,
                    2642,
                    &*name,
                    b"\xA0\x90\x75\x5B\xA5\x8D\x1A\xFF\xA5\x76\xF4\x37\x58\x31\xB4\x31\x09\x20\xE4\x81\x21\x8D\x18\xA9\xF1\x64\xEB" as &[u8],
                )),
            ),
            (b"A" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            assert_eq!(
                RRSig::scan(&mut scanner, &alloc, &mut buffer).map(|r| (
                    r.rtype,
                    r.algorithm.into(),
                    r.labels,
                    r.ttl.into(),
                    r.expiration.into(),
                    r.inception.into(),
                    r.keytag.get(),
                    r.signer,
                    r.signature
                )),
                expected
            );
        }
    }
}
