//! The Service Locator record data type.
//!
//! See [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782).

use core::cmp::Ordering;

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::name::CanonicalName;
use crate::new::base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new::base::wire::*;
use crate::new::base::{
    CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
};

//----------- Srv ------------------------------------------------------------

/// The location of a service.
///
/// TODO
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
)]
pub struct Srv<N> {
    /// The priority of this target host.
    pub priority: U16,

    /// The relative weight for selection among targets of equal priority.
    pub weight: U16,

    /// The TCP/UDP port on which the service is offered.
    pub port: U16,

    /// The domain name of the target host.
    pub target: N,
}

//--- Interaction

impl<N> Srv<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Srv<R> {
        Srv {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: (f)(self.target),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Srv<R> {
        Srv {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: (f)(&self.target),
        }
    }
}

//--- Canonical operations

impl<N: CanonicalName> CanonicalRecordData for Srv<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.priority.build_bytes(bytes)?;
        let bytes = self.weight.build_bytes(bytes)?;
        let bytes = self.port.build_bytes(bytes)?;
        let bytes = self.target.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| self.weight.cmp(&other.weight))
            .then_with(|| self.port.cmp(&other.port))
            .then_with(|| self.target.cmp_lowercase_composed(&other.target))
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Srv<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        let (&priority, rest) = <&U16>::split_message_bytes(contents, start)?;
        let (&weight, rest) = <&U16>::split_message_bytes(contents, rest)?;
        let (&port, rest) = <&U16>::split_message_bytes(contents, rest)?;
        let target = N::parse_message_bytes(contents, rest)?;
        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }
}

//--- Building into DNS messages

impl<N: BuildInMessage> BuildInMessage for Srv<N> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        start = self
            .priority
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self
            .weight
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self
            .port
            .as_bytes()
            .build_in_message(contents, start, compressor)?;
        start = self.target.build_in_message(contents, start, compressor)?;
        Ok(start)
    }
}

//--- Parsing record data

impl<'a, N: ParseMessageBytes<'a>> ParseRecordData<'a> for Srv<N> {
    fn parse_record_data(
        contents: &'a [u8],
        start: usize,
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::SRV => Self::parse_message_bytes(contents, start),
            _ => Err(ParseError),
        }
    }
}

impl<'a, N: ParseBytes<'a>> ParseRecordDataBytes<'a> for Srv<N> {
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
