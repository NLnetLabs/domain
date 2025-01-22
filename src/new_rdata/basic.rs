//! Core record data types.
//!
//! See [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).

use core::fmt;

#[cfg(feature = "std")]
use core::str::FromStr;

#[cfg(feature = "std")]
use std::net::Ipv4Addr;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseBytes, ParseError, SplitBytes, U16, U32},
    CharStr, Serial,
};

//----------- A --------------------------------------------------------------

/// The IPv4 address of a host responsible for this domain.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct A {
    /// The IPv4 address octets.
    pub octets: [u8; 4],
}

//--- Converting to and from 'Ipv4Addr'

#[cfg(feature = "std")]
impl From<Ipv4Addr> for A {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

#[cfg(feature = "std")]
impl From<A> for Ipv4Addr {
    fn from(value: A) -> Self {
        Self::from(value.octets)
    }
}

//--- Parsing from a string

#[cfg(feature = "std")]
impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::from)
    }
}

//--- Formatting

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for A {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.as_bytes().build_into_message(builder)
    }
}

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

//----------- Cname ----------------------------------------------------------

/// The canonical name for this domain.
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
pub struct CName<N: ?Sized> {
    /// The canonical name.
    pub name: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseMessageBytes<'a>> ParseMessageBytes<'a> for CName<N> {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        N::parse_message_bytes(contents, start).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for CName<N> {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.name.build_into_message(builder)
    }
}

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

//----------- Wks ------------------------------------------------------------

/// Well-known services supported on this domain.
#[derive(AsBytes, BuildBytes, ParseBytesByRef)]
#[repr(C, packed)]
pub struct Wks {
    /// The address of the host providing these services.
    pub address: A,

    /// The IP protocol number for the services (e.g. TCP).
    pub protocol: u8,

    /// A bitset of supported well-known ports.
    pub ports: [u8],
}

//--- Formatting

impl fmt::Debug for Wks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Ports<'a>(&'a [u8]);

        impl fmt::Debug for Ports<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let entries = self
                    .0
                    .iter()
                    .enumerate()
                    .flat_map(|(i, &b)| (0..8).map(move |j| (i, j, b)))
                    .filter(|(_, j, b)| b & (1 << j) != 0)
                    .map(|(i, j, _)| i * 8 + j);

                f.debug_set().entries(entries).finish()
            }
        }

        f.debug_struct("Wks")
            .field("address", &format_args!("{}", self.address))
            .field("protocol", &self.protocol)
            .field("ports", &Ports(&self.ports))
            .finish()
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Wks {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.as_bytes().build_into_message(builder)
    }
}

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
)]
#[repr(C)]
pub struct Mx<N: ?Sized> {
    /// The preference for this host over others.
    pub preference: U16,

    /// The domain name of the mail exchanger.
    pub exchange: N,
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

//----------- Txt ------------------------------------------------------------

/// Free-form text strings about this domain.
#[derive(AsBytes, BuildBytes)]
#[repr(transparent)]
pub struct Txt {
    /// The text strings, as concatenated [`CharStr`]s.
    content: [u8],
}

//--- Interaction

impl Txt {
    /// Iterate over the [`CharStr`]s in this record.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<&CharStr, ParseError>> + '_ {
        // NOTE: A TXT record always has at least one 'CharStr' within.
        let first = <&CharStr>::split_bytes(&self.content);
        core::iter::successors(Some(first), |prev| {
            prev.as_ref()
                .ok()
                .map(|(_elem, rest)| <&CharStr>::split_bytes(rest))
        })
        .map(|result| result.map(|(elem, _rest)| elem))
    }
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for &'a Txt {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Txt {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.content.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a> ParseBytes<'a> for &'a Txt {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // NOTE: The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_bytes(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_bytes(rest)?;
        }

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&'a [u8], Self>(bytes) })
    }
}

//--- Formatting

impl fmt::Debug for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Content<'a>(&'a Txt);
        impl fmt::Debug for Content<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();
                for elem in self.0.iter() {
                    if let Ok(elem) = elem {
                        list.entry(&elem);
                    } else {
                        list.entry(&ParseError);
                    }
                }
                list.finish()
            }
        }

        f.debug_tuple("Txt").field(&Content(self)).finish()
    }
}
