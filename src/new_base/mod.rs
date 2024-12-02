//! Basic DNS.

pub mod message;
pub use message::Message;

pub mod question;
pub use question::Question;

pub mod record;
pub use record::Record;

pub mod name;
pub use name::{Name, ParsedName};

pub mod build;
pub mod parse;
