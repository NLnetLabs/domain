//! EDNS options to signal a variable TCP connection timeout.
//!
//! The option in this module – [`TcpKeepalive`] – allows a server to signal
//! to a client how long it should hold on to a TCP connection after having
//! received an answer.
//!
//! Note that his has nothing to do with the keepalive feature of TCP itself.
//!
//! This option is defined in [RFC 7829](https://tools.ietf.org/html/rfc7828).

use core::fmt;
use core::time::Duration;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, Parse, ParseError};
use super::{Opt, OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;


//------------ TcpKeepalive --------------------------------------------------

/// Option data for the edns-tcp-keepalive option.
///
/// The edns-tcp-keepalive option can be used to determine a time a server
/// would like a client to keep a TCP connection open after receiving an
/// answer. The client includes the option without a value in its query to
/// indicate support for the option. The server then includes the option in
/// its response, including a 16-bit value that provides the idle time in
/// units of 100 milliseconds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(Option<IdleTimeout>);

impl TcpKeepalive {
    /// The option code for this option.
    pub(super) const CODE: OptionCode = OptionCode::TCP_KEEPALIVE;
    
    /// Creates a new value from an optional idle timeout.
    #[must_use]
    pub fn new(timeout: Option<IdleTimeout>) -> Self {
        TcpKeepalive(timeout)
    }

    /// Returns the idle timeout.
    #[must_use]
    pub fn timeout(self) -> Option<IdleTimeout> {
        self.0
    }

    /// Parses an option data value from its wire format.
    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        if parser.remaining() == 0 {
            Ok(Self::new(None))
        } else {
            IdleTimeout::parse(parser).map(|v| Self::new(Some(v)))
        }
    }

    /// Placeholder for unnecessary octets conversion.
    ///
    /// This method only exists for the `AllOptData` macro.
    pub(super) fn try_octets_from<E>(src: Self) -> Result<Self, E> {
        Ok(src)
    }
}

//--- OptData

impl OptData for TcpKeepalive {
    fn code(&self) -> OptionCode {
        OptionCode::TCP_KEEPALIVE
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for TcpKeepalive {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::TCP_KEEPALIVE {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for TcpKeepalive {
    fn compose_len(&self) -> u16 {
        match self.0 {
            Some(_) => IdleTimeout::COMPOSE_LEN,
            None => 0,
        }
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        match self.0 {
            Some(v) => v.compose(target),
            None => Ok(()),
        }
    }
}

//--- Display

impl fmt::Display for TcpKeepalive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Some(v) => write!(f, "{}", v),
            None => write!(f, ""),
        }
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first edns-tcp-keepalive option if present.
    ///
    /// This option is used to signal a timeout to keep a TCP connection
    /// open.
    pub fn tcp_keepalive(&self) -> Option<TcpKeepalive> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn tcp_keepalive(
        &mut self, timeout: Option<IdleTimeout>
    ) -> Result<(), Target::AppendError> {
        self.push(&TcpKeepalive::new(timeout))
    }
}


//------------ IdleTimeout ---------------------------------------------------

/// The idle timeout value of a [`TcpKeepalive`] option.
///
/// This value is a `u16` carrying a time in units of 100 milliseconds. The
/// type provides means to conver the value into its raw `u16` value or into
/// a [`Duration`] value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdleTimeout(u16);

impl IdleTimeout {
    /// The length in octets of the wire format.
    const COMPOSE_LEN: u16 = 2;

    /// Parses a value from its wire format.
    fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        u16::parse(parser).map(Self)
    }

    /// Appends a value in wire format to a target.
    fn compose<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}

//--- From and TryFrom

impl From<u16> for IdleTimeout {
    fn from(src: u16) -> Self {
        Self(src)
    }
}

impl From<IdleTimeout> for u16 {
    fn from(src: IdleTimeout) -> u16 {
        src.0
    }
}

impl TryFrom<Duration> for IdleTimeout {
    type Error = FromDurationError;

    fn try_from(duration: Duration) -> Result<Self, Self::Error> {
        Ok(Self(
            u16::try_from(
                duration.as_secs().checked_mul(10).ok_or(
                    FromDurationError(())
                )?
                + u64::from(duration.subsec_millis() / 100)
            ).map_err(|_| FromDurationError(()))?
        ))
    }
}

impl From<IdleTimeout> for Duration {
    fn from(src: IdleTimeout) -> Self {
        Duration::from_millis(u64::from(src.0) * 100)
    }
}

//--- Display

impl fmt::Display for IdleTimeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


//------------ FromDurationError ---------------------------------------------

/// A duration value was too large to convert into a idle timeout.
#[derive(Clone, Copy, Debug)]
pub struct FromDurationError(());

impl fmt::Display for FromDurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("duration too large")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromDurationError { }


//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn tcp_keepalive_compose_parse_none() {
        test_option_compose_parse(
            &TcpKeepalive::new(None),
            |parser| TcpKeepalive::parse(parser)
        );
    }

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn tcp_keepalive_compose_parse_some() {
        test_option_compose_parse(
            &TcpKeepalive::new(Some(12.into())),
            |parser| TcpKeepalive::parse(parser)
        );
    }
}

