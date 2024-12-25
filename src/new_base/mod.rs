//! Basic DNS.
//!
//! This module provides the essential types and functionality for working
//! with DNS.  Most importantly, it provides functionality for parsing and
//! building DNS messages on the wire.

mod message;
pub use message::{Header, HeaderFlags, Message, SectionCounts};

pub mod name;

mod charstr;
pub use charstr::CharStr;

mod question;
pub use question::{QClass, QType, Question, UnparsedQuestion};

mod record;
pub use record::{
    RClass, RType, Record, UnparsedRecord, UnparsedRecordData, TTL,
};

pub mod parse;

mod serial;
pub use serial::Serial;
