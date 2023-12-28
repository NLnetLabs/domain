//! Sending and receiving DNS messages.
//!
//! This module provides types, traits, and function for sending and receiving
//! DNS messages.
//!
//! Currently, the module only provides the unstable
#![cfg_attr(feature = "unstable-client-transport", doc = " [`client`]")]
#![cfg_attr(not(feature = "unstable-client-transport"), doc = " `client`")]
//! sub-module intended for sending requests and receiving responses to them.
#![cfg_attr(not(feature = "unstable-client-transport"), doc = " The `unstable-client-transport` feature is necessary to enable this module.")]
//!
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

pub mod client;
