//! Networking-related types not available in core.
//!
//! This module either re-exports or re-defines a number of types related to
//! networking that are not available in a `no_std` environment but are used
//! in DNS data. Currently, these are types for IP addresses.
//!
//! The `no_std` version currently is only the bare minimum implementation
//! and doesn’t provide all the features the `std` version has.

#[cfg(feature = "std")]
pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, AddrParseError};

#[cfg(not(feature = "std"))]
pub use self::nostd::*;


#[cfg(not(feature = "std"))]
mod nostd {
    use core::fmt;

    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Ipv4Addr([u8; 4]);

    impl Ipv4Addr {
        pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
            Self([a, b, c, d])
        }

        #[allow(clippy::trivially_copy_pass_by_ref)]
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
            write!(
                f, "{}.{}.{}.{}",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }

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
                    write!(fmt, "::{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                           (h >> 8) as u8, h as u8)
                }
                // Ipv4-Mapped address
                [0, 0, 0, 0, 0, 0xffff, g, h] => {
                    write!(fmt, "::ffff:{}.{}.{}.{}", (g >> 8) as u8, g as u8,
                           (h >> 8) as u8, h as u8)
                },
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

                    let (zeros_at, zeros_len) = find_zero_slice(
                        &self.segments()
                    );

                    if zeros_len > 1 {
                        fn fmt_subslice(
                            segments: &[u16], fmt: &mut fmt::Formatter<'_>
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
                            &self.segments()[zeros_at + zeros_len..], fmt
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


    #[derive(Clone, Copy, Debug)]
    pub struct AddrParseError;
}

