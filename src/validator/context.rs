// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use crate::base::ParsedDname;
use super::anchor::TrustAnchors;
use super::types::ValidationState;

pub struct ValidationContext {
    ta: TrustAnchors,
}

impl ValidationContext {
    pub fn new(ta: TrustAnchors) -> Self {
	Self { ta }
    }

    pub fn get_node<Octs>(&self, name: &ParsedDname<Octs>) -> Node {
	// Check the cache first
	if let Some(node) = self.cache_lookup(name) {
	    return node;
	}

	// Find a trust anchor. 
	let Some(ta) = self.ta.find() else {
	    // Try to get an indeterminate node for the root
	    return Node::new(ValidationState::Indeterminate);
	};
	todo!();
    }

    fn cache_lookup<Octs>(&self, name: &ParsedDname<Octs>) -> Option<Node> {
	None
    }
}

pub struct Node {
	state: ValidationState
}

impl Node {
    fn new(state: ValidationState) -> Self {
	Self { state }
    }

    pub fn validation_state(&self) -> ValidationState {
	self.state
    }
}
