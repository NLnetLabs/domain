//! Sending and receiving DNS messages.
//!
//! This module provides types, traits, and functions for sending and receiving
//! DNS messages.
//!
//! Currently, the module only provides the unstable
#![cfg_attr(feature = "unstable-client-transport", doc = " [`client`]")]
#![cfg_attr(not(feature = "unstable-client-transport"), doc = " `client`")]
//! sub-module intended for sending requests and receiving responses to them,
//! the unstable
#![cfg_attr(feature = "unstable-server-transport", doc = " [`server`]")]
#![cfg_attr(not(feature = "unstable-server-transport"), doc = " `server`")]
//! sub-module intended for receiving requests and sending responses to them.
//! and the unstable
#![cfg_attr(feature = "unstable-xfr", doc = " [`xfr`]")]
#![cfg_attr(not(feature = "unstable-xfr"), doc = " `xfr`")]
//! sub-module for zone transfer related functionality.
//!
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

pub mod client;
pub mod server;
pub mod xfr;
