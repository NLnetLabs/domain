// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use super::anchor::TrustAnchors;
use super::types::ValidationState;
use crate::base::Dname;
use crate::base::ParsedDname;

pub struct ValidationContext {
    ta: TrustAnchors,
}

impl ValidationContext {
    pub fn new(ta: TrustAnchors) -> Self {
        Self { ta }
    }

    pub fn get_node<Octs>(&self, name: &Dname<Octs>) -> Node {
        // Check the cache first
        if let Some(node) = self.cache_lookup(name) {
            return node;
        }

        // Find a trust anchor.
        let Some(_ta) = self.ta.find() else {
            // Try to get an indeterminate node for the root
            return Node::new(ValidationState::Indeterminate);
        };
        todo!();
    }

    fn cache_lookup<Octs>(&self, _name: &Dname<Octs>) -> Option<Node> {
        None
    }
}

pub struct Node {
    state: ValidationState,
}

impl Node {
    fn new(state: ValidationState) -> Self {
        Self { state }
    }

    pub fn validation_state(&self) -> ValidationState {
        self.state
    }
}
