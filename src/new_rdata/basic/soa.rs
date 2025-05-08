//! The SOA record data type.

use core::cmp::Ordering;

use crate::new_base::build::{BuildInMessage, NameCompressor};
use crate::new_base::name::CanonicalName;
use crate::new_base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new_base::{
    wire::*, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::new_base::{CanonicalRecordData, Serial};

//----------- Soa ------------------------------------------------------------

/// The start of a zone of authority.
///
/// A [`Soa`] record indicates that a domain name is the apex of a DNS zone.
/// It provides several parameters to describe how the zone should be used,
/// e.g. how often it should be refreshed.
///
/// [`Soa`]'s most important use is to detect changes to the zone.  Whenever
/// the zone is changed, [`Soa::serial`] is incremented; secondary DNS servers
/// (which cache and redistribute the contents of the zone) can thus detect
/// whether they need to update their cache.
///
// TODO: Is there a strict definition to "whenever the zone is changed"?
//
/// Every zone has exactly one [`Soa`] record, and it is located at the apex.
/// The zone (along with its authoritative name servers) is authoritative for
/// the record.
///
/// [`Soa`] is specified by [RFC 1035, section 3.3.13].  The behaviour of
/// secondary name servers using [`Soa`] to check for updates to a zone is
/// specified by [RFC 1034, section 4.3.5].
///
/// [RFC 1034, section 4.3.5]: https://datatracker.ietf.org/doc/html/rfc1034#section-4.3.5
/// [RFC 1035, section 3.3.13]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13
///
/// ## Wire format
///
/// The wire format of a [`Soa`] record is the concatenation of its fields, in
/// the same order as the `struct` definition.  The domain names within a
/// [`Soa`] may be compressed in DNS messages.  Every other field is an
/// unsigned 32-bit big-endian integer.
///
/// ## Usage
///
/// Because [`Soa`] is a record data type, it is usually handled within
/// an enum like [`RecordData`].  This section describes how to use it
/// independently (or when building new record data from scratch).
///
/// [`RecordData`]: crate::new_rdata::RecordData
///
/// In order to build a [`Soa`], it's first important to choose a domain name
/// type.  For short-term usage (where the [`Soa`] is a local variable), it is
/// common to pick [`RevNameBuf`].  If the [`Soa`] will be placed on the heap,
/// <code>Box&lt;[`RevName`]&gt;</code> will be more efficient.
///
/// [`RevName`]: crate::new_base::name::RevName
/// [`RevNameBuf`]: crate::new_base::name::RevNameBuf
///
/// The primary way to build a new [`Soa`] is to construct each
/// field manually. To parse a [`Soa`] from a DNS message, use
/// [`ParseMessageBytes`].  In case the input bytes don't use name
/// compression, [`ParseBytes`] can be used.
///
/// ```
/// # use domain::new_base::name::{Name, RevNameBuf};
/// # use domain::new_base::wire::{BuildBytes, ParseBytes, ParseBytesZC};
/// # use domain::new_rdata::Soa;
/// #
/// // Build a 'Soa' manually:
/// let manual: Soa<RevNameBuf> = Soa {
///     mname: "ns.example.org".parse().unwrap(),
///     rname: "admin.example.org".parse().unwrap(),
///     serial: 42.into(),
///     refresh: 3600.into(),
///     retry: 600.into(),
///     expire: 18000.into(),
///     minimum: 150.into(),
/// };
///
/// // Its wire format serialization looks like:
/// let bytes = b"\
///     \x02ns\x07example\x03org\x00\
///     \x05admin\x07example\x03org\x00\
///     \x00\x00\x00\x2A\
///     \x00\x00\x0E\x10\
///     \x00\x00\x02\x58\
///     \x00\x00\x46\x50\
///     \x00\x00\x00\x96";
/// # let mut buffer = [0u8; 55];
/// # manual.build_bytes(&mut buffer).unwrap();
/// # assert_eq!(*bytes, buffer);
///
/// // Parse a 'Soa' from the wire format, without name decompression:
/// let from_wire: Soa<RevNameBuf> = Soa::parse_bytes(bytes).unwrap();
/// # assert_eq!(manual, from_wire);
///
/// // See 'ParseMessageBytes' for parsing with name decompression.
/// ```
///
/// Since [`Soa`] is a sized type, and it implements [`Copy`] and [`Clone`],
/// it's straightforward to handle and move around.  However, this depends on
/// the domain name type.  It can be changed using [`Soa::map_names()`] and
/// [`Soa::map_names_by_ref()`].
///
/// For debugging, [`Soa`] can be formatted using [`fmt::Debug`].
///
/// [`fmt::Debug`]: core::fmt::Debug
///
/// To serialize a [`Soa`] in the wire format, use [`BuildInMessage`]
/// (which supports name compression).  If name compression is not desired,
/// use [`BuildBytes`].
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
    /// The original/primary name server for this zone.
    ///
    /// This domain name should point to a name server that is authoritative
    /// for this zone -- more specifically, that is the original source of
    /// information that all other name servers are (directly or indirectly)
    /// loading this zone from.  This need not be listed in the [`Ns`] records
    /// for this zone, if it is not intended for public querying.
    ///
    /// [`Ns`]: crate::new_rdata::Ns
    pub mname: N,

    /// The mailbox of the maintainer of this zone.
    ///
    /// The first label here is the username (i.e. local part) of the e-mail
    /// address, and the remaining labels make up the mail domain name.  For
    /// example, <hostmaster@sri-nic.arpa> would be represented as
    /// `hostmaster.sri-nic.arpa`.  This convention is specified in [RFC 1034,
    /// section 3.3].
    ///
    /// [RFC 1034, section 3.3]: https://datatracker.ietf.org/doc/html/rfc1034#section-3.3
    pub rname: N,

    /// The version number of the original copy of this zone.
    ///
    /// This value is increased when the contents of the zone change.  If a
    /// secondary name server wishes to cache the contents of this zone, it
    /// can periodically check the version number from the primary name server
    /// to determine whether it needs to update its cache.
    ///
    /// There are multiple conventions for versioning strategies.  Some zones
    /// will increase this value by 1 when a change occurs; some set it to the
    /// Unix timestamp of the latest change; others set it so that the decimal
    /// representation includes the current date.  As long as the version
    /// number increases (by a relatively small value) upon every change, any
    /// strategy is valid.
    ///
    /// This field is represented using [`Serial`], which provides special
    /// "sequence space arithmetic".  This ensures that ordering comparisons
    /// are well-defined even if the number overflows modulo `2^32`.  See its
    /// documentation for more information.
    pub serial: Serial,

    /// The number of seconds to wait until refreshing the zone.
    ///
    /// If a secondary name server is caching and serving a zone, it is
    /// expected to periodically check the zone's serial number in the
    /// primary name server for changes to the zone contents.  The server is
    /// expected to wait this long (in seconds) after the last successful
    /// check, before checking again.
    ///
    /// If checking fails, however, the server uses a different periodicity;
    /// see [`Soa::retry`].
    ///
    /// Note that there are alternative means for keeping up to date with a
    /// primary name server -- see DNS NOTIFY ([RFC 1996]).
    ///
    /// [RFC 1996]: https://datatracker.ietf.org/doc/html/rfc1996
    pub refresh: U32,

    /// The number of seconds to wait until retrying a failed refresh.
    ///
    /// If a secondary name server is caching and serving a zone, it is
    /// expected to periodically check the zone's serial number in the
    /// primary name server for changes to the zone contents.  The server is
    /// expected to wait this long (in seconds) after the last _failing_ check
    /// before trying again.
    ///
    /// Once a check is successful, the server should resume using the
    /// [`Soa::refresh`] time.
    pub retry: U32,

    /// The number of seconds until the zone is considered expired.
    ///
    /// If a secondary name server is caching and serving a zone, it is
    /// expected to periodically check the zone's serial number in the
    /// primary name server for changes to the zone contents.  If the server
    /// fails to check for or retrieve updates to the zone for this period of
    /// time (in seconds), it should consider its copy of the zone obsolete
    /// and should discard it.
    pub expire: U32,

    /// The minimum TTL for any record in this zone.
    ///
    /// The meaning of this field has changed over time.  According to [RFC
    /// 2308, section 4], it is the time for which a negative response (i.e.
    /// that a certain record does not exist) should be cached.  [RFC 4035,
    /// section 2.3] likewise states that the [`NSec`] records for a zone
    /// should have a TTL of this value.
    ///
    /// [`NSec`]: crate::new_rdata::NSec
    /// [RFC 2308, section 4]: https://datatracker.ietf.org/doc/html/rfc2308#section-4
    /// [RFC 4035, section 2.3]: https://datatracker.ietf.org/doc/html/rfc4035#section-2.3
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

impl<N: BuildInMessage> BuildInMessage for Soa<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self.mname.build_in_message(contents, start, name)?;
        start = self.rname.build_in_message(contents, start, name)?;
        // Build the remaining bytes manually.
        let end = start + 20;
        let bytes = contents.get_mut(start..end).ok_or(TruncationError)?;
        bytes[0..4].copy_from_slice(self.serial.as_bytes());
        bytes[4..8].copy_from_slice(self.refresh.as_bytes());
        bytes[8..12].copy_from_slice(self.retry.as_bytes());
        bytes[12..16].copy_from_slice(self.expire.as_bytes());
        bytes[16..20].copy_from_slice(self.minimum.as_bytes());
        Ok(end)
    }
}

//--- Parsing record data

impl<'a, N: SplitMessageBytes<'a>> ParseRecordData<'a> for Soa<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SOA => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: SplitBytes<'a>> ParseRecordDataBytes<'a> for Soa<N> {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SOA => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
