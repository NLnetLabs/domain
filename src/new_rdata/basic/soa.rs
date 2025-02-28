use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseError, U32},
    Serial,
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
