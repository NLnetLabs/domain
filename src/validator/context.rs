// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use crate::base::ParsedDname;
use super::anchor::TrustAnchor;

pub struct ValidationContext {
    ta: TrustAnchor,
}

impl ValidationContext {
    pub fn new(ta: TrustAnchor) -> Self {
	Self { ta }
    }

    pub fn get_node<Octs>(&self, name: &ParsedDname<Octs>) {
	// Check the cache first
	if let Some(node) = self.cache_lookup(name) {
	    return node;
	}

	// Find a trust anchor. 
	let Some(ta) = self.ta.find() else {
	    // Try to get an indeterminate node for the root
	    todo!();
	};
	todo!();
    }

    fn cache_lookup<Octs>(&self, name: &ParsedDname<Octs>) -> Option<()> {
	None
    }
}
