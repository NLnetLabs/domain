//! Looking up raw records.

use futures::{BoxFuture, Future};
use ::bits::{DNameSlice, MessageBuf};
use ::iana::{RRType, Class};
use super::super::error::Error;
use super::super::resolver::ResolverTask;
use super::search::search;

pub fn lookup_records<N>(resolv: ResolverTask, name: N, rtype: RRType,
                         class: Class) -> BoxFuture<MessageBuf, Error>
                      where N: AsRef<DNameSlice> {
    search(resolv, name, move |resolv, name| resolv.query(&name, rtype, class))
        .boxed()
}

