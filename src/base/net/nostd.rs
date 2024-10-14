//! Re-implementation of libstd network address types.
#![cfg(not(feature = "std"))]

pub use super::parser::AddrParseError;

use core::fmt;

//------------ Ipv4Addr ------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Addr([u8; 4]);

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self([a, b, c, d])
    }

    pub fn octets(&self) -> [u8; 4] {
        self.0
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from(src: [u8; 4]) -> Self {
        Self(src)
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ipv4Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.octets().serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv4Addr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Ipv4Addr;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an IPv4 address")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                use core::str::FromStr;

                Ipv4Addr::from_str(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor)
        } else {
            <[u8; 4]>::deserialize(deserializer).map(Ipv4Addr::from)
        }
    }
}

//------------ Ipv6Addr ------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv6Addr([u8; 16]);

impl Ipv6Addr {
    pub fn octets(&self) -> [u8; 16] {
        self.0
    }

    pub fn segments(&self) -> [u16; 8] {
        let arr = self.0;
        [
            u16::from_be_bytes([arr[0], arr[1]]),
            u16::from_be_bytes([arr[2], arr[3]]),
            u16::from_be_bytes([arr[4], arr[5]]),
            u16::from_be_bytes([arr[6], arr[7]]),
            u16::from_be_bytes([arr[8], arr[9]]),
            u16::from_be_bytes([arr[10], arr[11]]),
            u16::from_be_bytes([arr[12], arr[13]]),
            u16::from_be_bytes([arr[14], arr[15]]),
        ]
    }
}

impl From<[u8; 16]> for Ipv6Addr {
    fn from(src: [u8; 16]) -> Self {
        Self(src)
    }
}

impl From<[u16; 8]> for Ipv6Addr {
    fn from(src: [u16; 8]) -> Self {
        let mut res = [0; 16];
        res[0] = src[0].to_be_bytes()[0];
        res[1] = src[0].to_be_bytes()[1];
        res[2] = src[1].to_be_bytes()[0];
        res[3] = src[1].to_be_bytes()[1];
        res[4] = src[2].to_be_bytes()[0];
        res[5] = src[2].to_be_bytes()[1];
        res[6] = src[3].to_be_bytes()[0];
        res[7] = src[3].to_be_bytes()[1];
        res[8] = src[4].to_be_bytes()[0];
        res[9] = src[4].to_be_bytes()[1];
        res[10] = src[5].to_be_bytes()[0];
        res[11] = src[5].to_be_bytes()[1];
        res[12] = src[6].to_be_bytes()[0];
        res[13] = src[6].to_be_bytes()[1];
        res[14] = src[7].to_be_bytes()[0];
        res[15] = src[7].to_be_bytes()[1];
        Self(res)
    }
}

#[allow(clippy::many_single_char_names)]
#[allow(clippy::needless_range_loop)]
impl fmt::Display for Ipv6Addr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.segments() {
            // We need special cases for :: and ::1, otherwise they're
            // formatted as ::0.0.0.[01]
            [0, 0, 0, 0, 0, 0, 0, 0] => write!(fmt, "::"),
            [0, 0, 0, 0, 0, 0, 0, 1] => write!(fmt, "::1"),
            // Ipv4 Compatible address
            [0, 0, 0, 0, 0, 0, g, h] => {
                write!(
                    fmt,
                    "::{}.{}.{}.{}",
                    (g >> 8) as u8,
                    g as u8,
                    (h >> 8) as u8,
                    h as u8
                )
            }
            // Ipv4-Mapped address
            [0, 0, 0, 0, 0, 0xffff, g, h] => {
                write!(
                    fmt,
                    "::ffff:{}.{}.{}.{}",
                    (g >> 8) as u8,
                    g as u8,
                    (h >> 8) as u8,
                    h as u8
                )
            }
            _ => {
                fn find_zero_slice(segments: &[u16; 8]) -> (usize, usize) {
                    let mut longest_span_len = 0;
                    let mut longest_span_at = 0;
                    let mut cur_span_len = 0;
                    let mut cur_span_at = 0;

                    for i in 0..8 {
                        if segments[i] == 0 {
                            if cur_span_len == 0 {
                                cur_span_at = i;
                            }

                            cur_span_len += 1;

                            if cur_span_len > longest_span_len {
                                longest_span_len = cur_span_len;
                                longest_span_at = cur_span_at;
                            }
                        } else {
                            cur_span_len = 0;
                            cur_span_at = 0;
                        }
                    }

                    (longest_span_at, longest_span_len)
                }

                let (zeros_at, zeros_len) = find_zero_slice(&self.segments());

                if zeros_len > 1 {
                    fn fmt_subslice(
                        segments: &[u16],
                        fmt: &mut fmt::Formatter<'_>,
                    ) -> fmt::Result {
                        if !segments.is_empty() {
                            write!(fmt, "{:x}", segments[0])?;
                            for &seg in &segments[1..] {
                                write!(fmt, ":{:x}", seg)?;
                            }
                        }
                        Ok(())
                    }

                    fmt_subslice(&self.segments()[..zeros_at], fmt)?;
                    fmt.write_str("::")?;
                    fmt_subslice(
                        &self.segments()[zeros_at + zeros_len..],
                        fmt,
                    )
                } else {
                    let &[a, b, c, d, e, f, g, h] = &self.segments();
                    write!(
                        fmt,
                        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                        a, b, c, d, e, f, g, h
                    )
                }
            }
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ipv6Addr {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.octets().serialize(serializer)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv6Addr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Ipv6Addr;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an IPv6 address")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                use core::str::FromStr;

                Ipv6Addr::from_str(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(Visitor)
        } else {
            <[u8; 16]>::deserialize(deserializer).map(Ipv6Addr::from)
        }
    }
}

//------------ IpAddr --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<[u8; 4]> for IpAddr {
    fn from(src: [u8; 4]) -> Self {
        IpAddr::V4(src.into())
    }
}

impl From<[u8; 16]> for IpAddr {
    fn from(src: [u8; 16]) -> Self {
        IpAddr::V6(src.into())
    }
}

impl From<[u16; 8]> for IpAddr {
    fn from(src: [u16; 8]) -> Self {
        IpAddr::V6(src.into())
    }
}

impl From<Ipv4Addr> for IpAddr {
    fn from(addr: Ipv4Addr) -> Self {
        IpAddr::V4(addr)
    }
}

impl From<Ipv6Addr> for IpAddr {
    fn from(addr: Ipv6Addr) -> Self {
        IpAddr::V6(addr)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for IpAddr {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            match *self {
                IpAddr::V4(ref a) => a.serialize(serializer),
                IpAddr::V6(ref a) => a.serialize(serializer),
            }
        } else {
            match *self {
                IpAddr::V4(ref a) => {
                    serializer.serialize_newtype_variant("IpAddr", 0, "V4", a)
                }
                IpAddr::V6(ref a) => {
                    serializer.serialize_newtype_variant("IpAddr", 1, "V6", a)
                }
            }
        }
    }
}
