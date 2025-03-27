use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    name::CanonicalName,
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, BuildBytes, ParseError, TruncationError, U32},
    CanonicalRecordData, Serial,
};

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
