use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::ParseMessageBytes,
    wire::{ParseBytes, ParseError},
    CharStr,
};

//----------- HInfo ----------------------------------------------------------

/// Information about the host computer.
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes, SplitBytes)]
pub struct HInfo<'a> {
    /// The CPU type.
    pub cpu: &'a CharStr,

    /// The OS type.
    pub os: &'a CharStr,
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for HInfo<'a> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for HInfo<'_> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        self.cpu.build_into_message(builder.delegate())?;
        self.os.build_into_message(builder.delegate())?;
        Ok(builder.commit())
    }
}
