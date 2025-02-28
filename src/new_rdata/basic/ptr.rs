use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::ParseMessageBytes,
    wire::ParseError,
};

//----------- Ptr ------------------------------------------------------------

/// A pointer to another domain name.
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
pub struct Ptr<N: ?Sized> {
    /// The referenced domain name.
    pub name: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for Ptr<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Ptr<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}
