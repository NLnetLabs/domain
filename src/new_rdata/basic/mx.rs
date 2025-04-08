//! The MX record data type.

use core::cmp::Ordering;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    name::CanonicalName,
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, BuildBytes, ParseError, TruncationError, U16},
    CanonicalRecordData,
};

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

//--- Canonical operations

impl<N: ?Sized + CanonicalName> CanonicalRecordData for Mx<N> {
    fn build_canonical_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let bytes = self.preference.build_bytes(bytes)?;
        let bytes = self.exchange.build_lowercased_bytes(bytes)?;
        Ok(bytes)
    }

    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.preference.cmp(&other.preference).then_with(|| {
            self.exchange.cmp_lowercase_composed(&other.exchange)
        })
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
