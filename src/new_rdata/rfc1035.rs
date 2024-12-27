//! Core record data types.

use core::{fmt, ops::Range, str::FromStr};

#[cfg(feature = "std")]
use std::net::Ipv4Addr;

use zerocopy::{
    network_endian::{U16, U32},
    IntoBytes,
};
use zerocopy_derive::*;

use crate::new_base::{
    build::{self, BuildInto, BuildIntoMessage, TruncationError},
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    CharStr, Message, Serial,
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
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

#[cfg(feature = "std")]
impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv4Addr::from(*self).fmt(f)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for A {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.as_bytes().build_into_message(builder)
    }
}

//--- Building into byte strings

impl BuildInto for A {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_into(bytes)
    }
}

//----------- Ns -------------------------------------------------------------

/// The authoritative name server for this domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ns<N: ?Sized> {
    /// The name of the authoritative server.
    pub name: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseFromMessage<'a>> ParseFromMessage<'a> for Ns<N> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        N::parse_from_message(message, range).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Ns<N> {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.name.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Ns<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
    }
}

//--- Building into bytes

impl<N: ?Sized + BuildInto> BuildInto for Ns<N> {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.name.build_into(bytes)
    }
}

//----------- Cname ----------------------------------------------------------

/// The canonical name for this domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Cname<N: ?Sized> {
    /// The canonical name.
    pub name: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseFromMessage<'a>> ParseFromMessage<'a> for Cname<N> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        N::parse_from_message(message, range).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Cname<N> {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.name.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Cname<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
    }
}

//--- Building into bytes

impl<N: ?Sized + BuildInto> BuildInto for Cname<N> {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.name.build_into(bytes)
    }
}

//----------- Soa ------------------------------------------------------------

/// The start of a zone of authority.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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

impl<'a, N: SplitFromMessage<'a>> ParseFromMessage<'a> for Soa<N> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let (mname, rest) = N::split_from_message(message, range.start)?;
        let (rname, rest) = N::split_from_message(message, rest)?;
        let (&serial, rest) = <&Serial>::split_from_message(message, rest)?;
        let (&refresh, rest) = <&U32>::split_from_message(message, rest)?;
        let (&retry, rest) = <&U32>::split_from_message(message, rest)?;
        let (&expire, rest) = <&U32>::split_from_message(message, rest)?;
        let &minimum = <&U32>::parse_from_message(message, rest..range.end)?;

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
    ) -> Result<(), TruncationError> {
        self.mname.build_into_message(builder.delegate())?;
        self.rname.build_into_message(builder.delegate())?;
        builder.append_bytes(self.serial.as_bytes())?;
        builder.append_bytes(self.refresh.as_bytes())?;
        builder.append_bytes(self.retry.as_bytes())?;
        builder.append_bytes(self.expire.as_bytes())?;
        builder.append_bytes(self.minimum.as_bytes())?;
        builder.commit();
        Ok(())
    }
}

//--- Parsing from bytes

impl<'a, N: SplitFrom<'a>> ParseFrom<'a> for Soa<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (mname, rest) = N::split_from(bytes)?;
        let (rname, rest) = N::split_from(rest)?;
        let (&serial, rest) = <&Serial>::split_from(rest)?;
        let (&refresh, rest) = <&U32>::split_from(rest)?;
        let (&retry, rest) = <&U32>::split_from(rest)?;
        let (&expire, rest) = <&U32>::split_from(rest)?;
        let &minimum = <&U32>::parse_from(rest)?;

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

//--- Building into byte strings

impl<N: BuildInto> BuildInto for Soa<N> {
    fn build_into<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.mname.build_into(bytes)?;
        bytes = self.rname.build_into(bytes)?;
        bytes = self.serial.as_bytes().build_into(bytes)?;
        bytes = self.refresh.as_bytes().build_into(bytes)?;
        bytes = self.retry.as_bytes().build_into(bytes)?;
        bytes = self.expire.as_bytes().build_into(bytes)?;
        bytes = self.minimum.as_bytes().build_into(bytes)?;
        Ok(bytes)
    }
}

//----------- Wks ------------------------------------------------------------

/// Well-known services supported on this domain.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
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
            .field("address", &Ipv4Addr::from(self.address))
            .field("protocol", &self.protocol)
            .field("ports", &Ports(&self.ports))
            .finish()
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Wks {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.as_bytes().build_into_message(builder)
    }
}

//--- Building into byte strings

impl BuildInto for Wks {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_into(bytes)
    }
}

//----------- Ptr ------------------------------------------------------------

/// A pointer to another domain name.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Ptr<N: ?Sized> {
    /// The referenced domain name.
    pub name: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseFromMessage<'a>> ParseFromMessage<'a> for Ptr<N> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        N::parse_from_message(message, range).map(|name| Self { name })
    }
}

//--- Building into DNS messages

impl<N: ?Sized + BuildIntoMessage> BuildIntoMessage for Ptr<N> {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.name.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Ptr<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
    }
}

//--- Building into bytes

impl<N: ?Sized + BuildInto> BuildInto for Ptr<N> {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.name.build_into(bytes)
    }
}

//----------- Hinfo ----------------------------------------------------------

/// Information about the host computer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hinfo<'a> {
    /// The CPU type.
    pub cpu: &'a CharStr,

    /// The OS type.
    pub os: &'a CharStr,
}

//--- Parsing from DNS messages

impl<'a> ParseFromMessage<'a> for Hinfo<'a> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        message
            .as_bytes()
            .get(range)
            .ok_or(ParseError)
            .and_then(Self::parse_from)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Hinfo<'_> {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.cpu.build_into_message(builder.delegate())?;
        self.os.build_into_message(builder.delegate())?;
        builder.commit();
        Ok(())
    }
}

//--- Parsing from bytes

impl<'a> ParseFrom<'a> for Hinfo<'a> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (cpu, rest) = <&CharStr>::split_from(bytes)?;
        let os = <&CharStr>::parse_from(rest)?;
        Ok(Self { cpu, os })
    }
}

//--- Building into bytes

impl BuildInto for Hinfo<'_> {
    fn build_into<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.cpu.build_into(bytes)?;
        bytes = self.os.build_into(bytes)?;
        Ok(bytes)
    }
}

//----------- Mx -------------------------------------------------------------

/// A host that can exchange mail for this domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct Mx<N: ?Sized> {
    /// The preference for this host over others.
    pub preference: U16,

    /// The domain name of the mail exchanger.
    pub exchange: N,
}

//--- Parsing from DNS messages

impl<'a, N: ParseFromMessage<'a>> ParseFromMessage<'a> for Mx<N> {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let (&preference, rest) =
            <&U16>::split_from_message(message, range.start)?;
        let exchange = N::parse_from_message(message, rest..range.end)?;
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
    ) -> Result<(), TruncationError> {
        builder.append_bytes(self.preference.as_bytes())?;
        self.exchange.build_into_message(builder.delegate())?;
        builder.commit();
        Ok(())
    }
}

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Mx<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (&preference, rest) = <&U16>::split_from(bytes)?;
        let exchange = N::parse_from(rest)?;
        Ok(Self {
            preference,
            exchange,
        })
    }
}

//--- Building into byte strings

impl<N: ?Sized + BuildInto> BuildInto for Mx<N> {
    fn build_into<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        bytes = self.preference.as_bytes().build_into(bytes)?;
        bytes = self.exchange.build_into(bytes)?;
        Ok(bytes)
    }
}

//----------- Txt ------------------------------------------------------------

/// Free-form text strings about this domain.
#[derive(IntoBytes, Immutable, Unaligned)]
#[repr(transparent)]
pub struct Txt {
    /// The text strings, as concatenated [`CharStr`]s.
    content: [u8],
}

// TODO: Support for iterating over the contained 'CharStr's.

//--- Parsing from DNS messages

impl<'a> ParseFromMessage<'a> for &'a Txt {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        message
            .as_bytes()
            .get(range)
            .ok_or(ParseError)
            .and_then(Self::parse_from)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Txt {
    fn build_into_message(
        &self,
        builder: build::Builder<'_>,
    ) -> Result<(), TruncationError> {
        self.content.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a> ParseFrom<'a> for &'a Txt {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // NOTE: The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_from(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_from(rest)?;
        }

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&'a [u8], Self>(bytes) })
    }
}

//--- Building into byte strings

impl BuildInto for Txt {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.content.build_into(bytes)
    }
}
