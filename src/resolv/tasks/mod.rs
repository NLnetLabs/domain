//! Resolver tasks.
//!
//! Since using the resolver may mean that several DNS queries have to be
//! made, all such operations are encoded in types called *tasks*. The only
//! way a user interfaces with tasks is by creating task values, usually by
//! way of a `new()` associated function. The created value is passed into
//! the resolver through the `task()` or `sync_task()` functions. In either
//! case there will eventually be successful completion of the task or an
//! error. Errors are always of type `domain::resolv::Error`, the type of
//! a successful result depends on the task in question.
//!
//! This module defines a number of common tasks. You can also implement your
//! own task by implementing the task-related traits for your own types. See
//! the documentation of the [traits](traits/index.html) module for more
//! details.

pub use self::host::{LookupHost, HostSuccess, SearchHost};
pub use self::query::Query;

pub mod host;
pub mod query;
pub mod traits;
