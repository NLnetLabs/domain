//! Basic DNS.

pub mod message;
pub use message::Message;

pub mod question;
pub use question::Question;

pub mod name;

pub mod parse;
