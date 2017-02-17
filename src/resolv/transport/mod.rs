/// DNS Transports.
///
/// While the actual sending and receiving of messages is done
/// implementations of the `Channel` trait, there needs to be some logic
/// governing in which order multiple parallel requests are sent to a server.
/// This is what transports do.
///
/// There are (at least) three ways how servers expect their requests: The
/// most obvious one is *multiplexed,* that is, we send all requests right
/// away, each with a different ID, and then match received responses using
/// their ID. Alternatively, we can operate *sequentially* by sending a
/// request and waiting for its response before sending a new request.
/// Finally, in *single request* mode each request is sent, its response
/// received and then the socket is closed.
///
/// Consequently, this module contains three different transport
/// implementations in the `multiplex`, `sequential`, and `single` submodules.
///
/// Towards the outside world, only the `spawn_transport()` function is
/// really relevant which spawns a transport into a reactor core. Which
/// particular strategy the transport will be using is defined by the
/// `TransportMode` enum

pub use self::spawn::{TransportMode, spawn_transport};

mod multiplex;
mod pending;
mod sequential;
mod single;
mod spawn;

