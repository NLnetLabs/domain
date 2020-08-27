//! Looking up raw records.

use std::vec::Vec;
use domain_core::bits::name::ToDname;
use domain_core::bits::Question;
use tokio::prelude::Future;
use crate::resolver::{Answer, QueryError, Resolver};


//------------ lookup_records ------------------------------------------------

/// Creates a future that looks up DNS records.
///
/// The future will use the given resolver to perform a DNS query for the
/// records of type `rtype` associated with `name` in `class`.
/// This differs from calling `resolv.query()` directly in that it can treat
/// relative names. In this case, the resolver configuration is considered
/// to translate the name into a series of absolute names. If you want to
/// find out the name that resulted in a successful answer, you can look at
/// the query in the resulting message.
pub fn lookup_records<'a, N, Q>(
    resolver: &'a Resolver,
    question: Q
) -> impl Future<Output = Result<Answer, QueryError>> + 'a
where N: ToDname + 'a, Q: Into<Question<N>>+ 'a {
    resolver.query(question)
}


