//! Looking up raw records.

use futures::{BoxFuture, Future};
use ::bits::{DNameSlice, MessageBuf};
use ::iana::{RRType, Class};
use super::super::error::Error;
use super::super::ResolverTask;
use super::search::search;


//------------ lookup_records ------------------------------------------------

/// Creates a future that looks up DNS records.
///
/// The future will use resolver represented by `resolv` to perform a DNS
/// query for the records of type `rtype` associated with `name` in `class`.
/// This differs from calling `resolv.query()` directly in that can treat
/// relative names. In this case, the resolver configuration is considered
/// to translate the name into a series of absolute names. If you want to
/// find out the name that resulted in a successful answer, you can look at
/// the query in the resulting message.
pub fn lookup_records<N>(resolv: ResolverTask, name: N, rtype: RRType,
                         class: Class) -> BoxFuture<MessageBuf, Error>
                      where N: AsRef<DNameSlice> {
    search(resolv, name, move |resolv, name| resolv.query(name, rtype, class))
        .boxed()
}

