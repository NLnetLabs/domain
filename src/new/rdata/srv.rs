//! The SRV record data type.
//!
//! See [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782).

use core::cmp::Ordering;

use crate::new::base::build::{
    AsBytes, BuildBytes, BuildInMessage, NameCompressor,
};
use crate::new::base::name::{CanonicalName, Name};
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};
use crate::utils::dst::UnsizedCopy;

//----------- Srv ------------------------------------------------------------

/// The locations of services associated with this domain.
///
/// The purpose of the [`Srv`] record is to direct clients to the correct
/// endpoint when they request a specific service from a domain.
///
/// The client queries the following name.
///
/// `_ldap._tcp.example.com.`
///
/// In this case, the client is seeking to contact the LDAP service via TCP at
/// `example.com`.
///
/// The server responds with zero or more [`Srv`] records. In presentation
/// format, they contain the following information.
///
/// `_Service._Proto.Name TTL Class SRV Priority Weight Port Target`
///
/// - `Service` is a name listed in the [Service Name and Transport Protocol
///   Port Number Registry][iana-srv-names] by IANA.
///   In the above example, the `Service` is `ldap`.
/// - `Proto` is a protocol listed in the [Protocol Numbers][iana-proto]
///   registry by IANA, but could be any other value, usually `udp` or `tcp`.
///   In the above example, the `Proto` is `tcp`.
/// - `Name` is the domain name that the record refers to.
///   In the above example, the `Name` is `example.com.`.
/// - The remaining values make up the record data, and are described in their
///   respective fields ([Priority](Srv::priority), [Weight](Srv::weight),
///   [Port](Srv::port), [Target](Srv::name)). [`Srv`] models only these four
///   fields. The owner name, TTL and class belong to the enclosing record.
///
/// [`Srv`] is specified by [RFC 2782].
///
/// ## Server selection
///
/// The [`Srv`] record enables simple load balancing rules to be created for
/// target selection based on two values: `Priority` and `Weight`.
///
/// Server selection works as follows:
///
/// - First, collect the targets with the numerically lowest `Priority` value.
///   Continue with this list.
/// - If all targets have a `Weight` of `0`, no special selection needs to be
///   applied.
/// - Otherwise, a target should be selected at random with a probability
///   proportional to its `Weight`. A greater value therefore has a
///   proportionally greater chance of selection. Targets with a `Weight` of
///   `0` have a very low chance of being selected in the presence of other,
///   higher values.
/// - If a target is unreachable, continue with other targets of the same
///   priority and move to the next priority if necessary.
///
/// ## Wire format
///
/// The wire format of an [`Srv`] record is the concatenation of its fields,
/// in the same order as the `struct` definition. The target name cannot be
/// compressed in DNS messages. Every other field is an unsigned 16-bit
/// big-endian integer.
///
/// The memory layout of the [`Srv`] type is identical to the wire format, so
/// it can be parsed in a zero-copy fashion, avoiding a copy of the data.
///
/// ## Usage
///
/// Because [`Srv`] is a record data type, it is usually handled within an
/// enum like [`RecordData`]. This section describes how to use it
/// independently.
///
/// [`Srv`] is an unsized type, it cannot be constructed directly. It has to
/// be parsed from its wire format.
///
/// ```
/// # use core::ops::Deref;
/// # use domain::new::base::name::NameBuf;
/// # use domain::new::base::wire::ParseBytesZC;
/// # use domain::new::rdata::Srv;
/// #
/// // The SRV record data includes a target with a priority of `1` and a
/// // weight of `0`. The service is reachable at `example.com:389`.
/// let bytes = b"\
///     \x00\x01\
///     \x00\x00\
///     \x01\x85\
///     \x07example\x03com\x00";
///
/// // Parse the record data from the wire format.
/// let srv = Srv::parse_bytes_by_ref(bytes).unwrap();
///
/// assert_eq!(1, srv.priority.get());
/// assert_eq!(0, srv.weight.get());
/// assert_eq!(389, srv.port.get());
/// assert_eq!(
///     &srv.name,
///     "example.com.".parse::<NameBuf>().unwrap().deref(),
/// );
/// ```
///
/// To serialize an [`Srv`] back into the wire format, use [`BuildInMessage`]
/// (which writes into a DNS message) or [`BuildBytes`].
///
/// [RFC 2782]: https://datatracker.ietf.org/doc/html/rfc2782
/// [`RecordData`]: crate::new::rdata::RecordData
/// [iana-proto]: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
/// [iana-srv-names]: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytesZC,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(C)]
pub struct Srv {
    /// The priority of this host.
    pub priority: U16,

    /// The relative weight for selection of this host.
    pub weight: U16,

    /// The port number on which the service is provided.
    pub port: U16,

    /// The domain name of the target host.
    ///
    /// A target name of `.` (the root name) means that the service is
    /// decidedly not available at this domain.
    ///
    /// the target must be a domain name with one or more address records, it
    /// must not be an alias.
    pub name: Name,
}

//--- Canonical operations

impl CanonicalRecordData for Srv {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.priority.build_bytes(bytes)?;
        let bytes = self.weight.build_bytes(bytes)?;
        let bytes = self.port.build_bytes(bytes)?;
        let bytes = self.name.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        // `Srv` uses canonical comparisons by default.
        self.cmp(other)
    }
}

//--- Building into DNS messages

impl BuildInMessage for Srv {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = self.as_bytes();
        let end = start + bytes.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(bytes);
        Ok(end)
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Srv> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a Srv {}

impl<'a> ParseRecordDataBytes<'a> for &'a Srv {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SRV => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}
