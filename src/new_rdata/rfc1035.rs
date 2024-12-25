//! Core record data types.

use core::{fmt, net::Ipv4Addr, ops::Range, str::FromStr};

use zerocopy::{
    network_endian::{U16, U32},
    IntoBytes,
};
use zerocopy_derive::*;

use crate::new_base::{
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    CharStr, Message,
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

impl From<Ipv4Addr> for A {
    fn from(value: Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<A> for Ipv4Addr {
    fn from(value: A) -> Self {
        Self::from(value.octets)
    }
}

//--- Parsing from a string

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::from)
    }
}

//--- Formatting

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ipv4Addr::from(*self).fmt(f)
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
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

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Ns<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
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

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Cname<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
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
    // TODO: Define a dedicated serial number type.
    pub serial: U32,

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
        let (&serial, rest) = <&U32>::split_from_message(message, rest)?;
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

//--- Parsing from bytes

impl<'a, N: SplitFrom<'a>> ParseFrom<'a> for Soa<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (mname, rest) = N::split_from(bytes)?;
        let (rname, rest) = N::split_from(rest)?;
        let (&serial, rest) = <&U32>::split_from(rest)?;
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
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

//--- Parsing from bytes

impl<'a, N: ParseFrom<'a>> ParseFrom<'a> for Ptr<N> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        N::parse_from(bytes).map(|name| Self { name })
    }
}

//----------- Hinfo ----------------------------------------------------------

/// Information about the host computer.
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

//--- Parsing from bytes

impl<'a> ParseFrom<'a> for Hinfo<'a> {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (cpu, rest) = <&CharStr>::split_from(bytes)?;
        let os = <&CharStr>::parse_from(rest)?;
        Ok(Self { cpu, os })
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
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
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
