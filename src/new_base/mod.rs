//! Basic DNS.
//!
//! This module provides the essential types and functionality for working
//! with DNS.  Most importantly, it provides functionality for parsing and
//! building DNS messages on the wire.

//--- DNS messages

mod message;
pub use message::{Header, HeaderFlags, Message, SectionCounts};

mod question;
pub use question::{QClass, QType, Question, UnparsedQuestion};

mod record;
pub use record::{
    RClass, RType, Record, UnparsedRecord, UnparsedRecordData, TTL,
};

//--- Elements of DNS messages

pub mod name;

mod charstr;
pub use charstr::CharStr;

mod serial;
pub use serial::Serial;

//--- Wire format

pub mod build;
pub mod parse;
