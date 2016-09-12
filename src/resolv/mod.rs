/// An asnychronous stub resolver using futures and tokio.

pub use self::conf::ResolvConf;
pub use self::error::{Error, Result};
pub use self::resolver::{Resolver, Query};

pub mod conf;
pub mod error;
pub mod lookup;

mod dgram;
mod pending;
mod request;
mod resolver;
mod stream;
mod tcp;
mod udp;
