use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::ParseMessageBytes,
    wire::ParseError,
};

//----------- Ns -------------------------------------------------------------

/// The authoritative name server for this domain.
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
#[repr(transparent)]
pub struct Ns<N: ?Sized> {
    /// The name of the authoritative server.
    pub name: N,
}

//--- Interaction

impl<N> Ns<N> {
    /// Map the domain name within to another type.
    pub fn map_name<R, F: FnOnce(N) -> R>(self, f: F) -> Ns<R> {
        Ns {
            name: (f)(self.name),
        }
    }

    /// Map a reference to the domain name within to another type.
    pub fn map_name_by_ref<'r, R, F: FnOnce(&'r N) -> R>(
        &'r self,
        f: F,
    ) -> Ns<R> {
        Ns {
            name: (f)(&self.name),
        }
    }
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Ns<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Ns<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}
