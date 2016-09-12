/// An asnychronous stub resolver using futures and tokio.

pub use self::conf::ResolvConf;
pub use self::resolver::{Resolver, Query};

pub mod conf;
mod dgram;
pub mod lookup;
mod pending;
mod request;
mod resolver;
mod stream;
mod tcp;
mod udp;
