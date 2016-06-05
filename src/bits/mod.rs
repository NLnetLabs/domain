//! DNS data.

pub use self::charstr::{CharStr, CharStrError};
pub use self::compose::{ComposeBytes, ComposeBuf};
pub use self::error::{ComposeError, ComposeResult, ParseError, ParseResult,
                      FromStrError, FromStrResult};
pub use self::iana::{Class, Opcode, Rcode, RRType};
pub use self::message::{Message, MessageBuf, MessageBuilder};
pub use self::name::{DName, DNameSlice, DNameBuf, PackedDName};
pub use self::nest::Nest;
pub use self::octets::Octets;
pub use self::parse::{ParseBytes};
pub use self::question::Question;

pub mod charstr;
pub mod compose;
pub mod error;
pub mod header;
pub mod iana;
pub mod message;
pub mod name;
pub mod nest;
pub mod octets;
pub mod parse;
pub mod question;
pub mod rdata;
pub mod record;
mod u8;

