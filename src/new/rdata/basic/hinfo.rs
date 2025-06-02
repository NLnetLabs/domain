//! The HINFO record data type.

use core::cmp::Ordering;

use crate::new::base::build::{
    BuildInMessage, NameCompressor, TruncationError,
};
use crate::new::base::parse::ParseMessageBytes;
use crate::new::base::wire::{
    BuildBytes, ParseBytes, ParseError, SplitBytes,
};
use crate::new::base::{
    CanonicalRecordData, CharStr, ParseRecordData, ParseRecordDataBytes,
    RType,
};

//----------- HInfo ----------------------------------------------------------

/// Information about the host computer.
///
/// [`HInfo`] describes the hardware and software of the server associated
/// with the domain name.  It is not commonly used for its original purpose,
/// given several issues:
///
/// 1. A domain name can be associated with multiple servers (due to having
///    multiple IP addresses or using IP anycast), but [`HInfo`] does not
///    provide a way to associate the information it provides with a specific
///    server (or at least IP address).
///
/// 2. The CPU and OS name are expected to be standardized, but given the
///    massive (and growing) number of both, it would be impossible to cover
///    every possibility.  [RFC 1010] listed the initial set of names, and it
///    has evolved into the online lists of [operating system names] (last
///    updated in 2010) and [machine names] (last updated in 2001).
///
/// 3. As documented by [RFC 1035], the "main use" for [`HInfo`] records was
///    "for protocols such as FTP that can use special procedures when talking
///    between machines or operating systems of the same type".  But given the
///    portabilitiy of most protocols across machines and operating systems,
///    [`HInfo`] is not very informative.  Protocols typically provide
///    extension mechanisms in-band instead of relying on out-of-band DNS
///    information.
///
/// 4. [RFC 8482, section 6] states that "the HINFO RRTYPE is believed to be
///    rarely used in the DNS at the time of writing, based on observations
///    made in passive DNS and at recursive and authoritative DNS servers".
///
/// [RFC 1010]: https://datatracker.ietf.org/doc/html/rfc1010
/// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [RFC 8482, section 6]: https://datatracker.ietf.org/doc/html/rfc8482#section-6
/// [operating system names]: https://www.iana.org/assignments/operating-system-names/operating-system-names.xhtml
/// [machine names]: https://www.iana.org/assignments/machine-names/machine-names.xhtml
///
/// Recently, [`HInfo`] has gained new use, as a potential fallback response
/// for [`QType::ANY`] queries.  [RFC 8482] specifies that name servers
/// wishing to avoid answering [`QType::ANY`] queries (which are expensive
/// to look up, have an amplifying network effect, and can be abused for DoS
/// attacks) can respond with a synthesized [`HInfo`] record instead.
///
/// [`QType::ANY`]: crate::new::base::QType::ANY
/// [RFC 8482]: https://datatracker.ietf.org/doc/html/rfc8482
///
/// [`HInfo`] is specified by [RFC 1035, section 3.3.2].  Its use as an
/// alternative response to [`QType::ANY`] queries is documented by [RFC 8482,
/// section 4.2].
///
/// [RFC 1035, section 3.3.2]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.2
/// [RFC 8482, section 4.2]: https://datatracker.ietf.org/doc/html/rfc8482#section-4.2
///
/// ## Wire Format
///
/// The wire format of an [`HInfo`] record is the concatenation of two
/// "character strings" (see [`CharStr`]).  The first specifies the "machine
/// name" of the host computer, and the second specifies the name of the
/// operating system it is running.
///
/// ## Usage
///
/// Because [`HInfo`] is a record data type, it is usually handled within an
/// enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new::rdata::RecordData
///
/// There's a few ways to build an [`HInfo`]:
///
/// ```
/// # use domain::new::base::wire::{BuildBytes, ParseBytes};
/// # use domain::new::rdata::HInfo;
/// #
/// use domain::new::base::CharStrBuf;
///
/// // Build an 'HInfo' manually.
/// let cpu: CharStrBuf = "DEC-2060".parse().unwrap();
/// let os: CharStrBuf = "TOPS20".parse().unwrap();
/// let manual: HInfo<'_> = HInfo { cpu: &*cpu, os: &*os };
///
/// let bytes = b"\x08DEC-2060\x06TOPS20";
/// # let mut buffer = [0u8; 16];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse an 'HInfo' from the DNS wire format.
/// let from_wire: HInfo<'_> = HInfo::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
/// ```
///
/// Since [`HInfo`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, it is bound by
/// the lifetime of the borrowed character strings.  At the moment, there is
/// no perfect way to own an [`HInfo`] without a lifetime restriction (largely
/// because it is not commonly used), however:
///
#[cfg_attr(feature = "alloc", doc = " - [`BoxedRecordData`] ")]
#[cfg_attr(not(feature = "alloc"), doc = " - `BoxedRecordData` ")]
///   is capable of doing so, but it does not guarantee that it holds an
///   [`HInfo`] (it can hold any record data type).
///
/// - If [`bumpalo`] is being used,
#[cfg_attr(feature = "bumpalo", doc = "   [`HInfo::clone_to_bump()`]")]
#[cfg_attr(not(feature = "bumpalo"), doc = "   `HInfo::clone_to_bump()`")]
///   can clone an [`HInfo`] over to a bump allocator.  This may extend its
///   lifetime sufficiently for some use cases.
///
#[cfg_attr(
    not(feature = "bumpalo"),
    doc = "[`bumpalo`]: https://docs.rs/bumpalo/latest/bumpalo/"
)]
#[cfg_attr(
    feature = "alloc",
    doc = "[`BoxedRecordData`]: crate::new::rdata::BoxedRecordData"
)]
///
/// For debugging [`HInfo`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize an [`HInfo`] in the wire format, use [`BuildBytes`].  It also
/// supports [`BuildInMessage`].
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes, SplitBytes,
)]
pub struct HInfo<'a> {
    /// The type of the machine hosting the domain name.
    pub cpu: &'a CharStr,

    /// The type of the operating system hosting the domain name.
    pub os: &'a CharStr,
}

//--- Interaction

impl HInfo<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> HInfo<'r> {
        use crate::utils::dst::copy_to_bump;

        HInfo {
            cpu: copy_to_bump(self.cpu, bump),
            os: copy_to_bump(self.os, bump),
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for HInfo<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this = (
            self.cpu.len(),
            &self.cpu.octets,
            self.os.len(),
            &self.os.octets,
        );
        let that = (
            that.cpu.len(),
            &that.cpu.octets,
            that.os.len(),
            &that.os.octets,
        );
        this.cmp(&that)
    }
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for HInfo<'a> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        contents
            .get(start..)
            .ok_or(ParseError)
            .and_then(Self::parse_bytes)
    }
}

//--- Building into DNS messages

impl BuildInMessage for HInfo<'_> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self.cpu.build_in_message(contents, start, compressor)?;
        start = self.os.build_in_message(contents, start, compressor)?;
        Ok(start)
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for HInfo<'a> {}

impl<'a> ParseRecordDataBytes<'a> for HInfo<'a> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::HINFO => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
