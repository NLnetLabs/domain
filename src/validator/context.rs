// Validation context. The validation contains trust anchors, a transport
// connection for issuing queries, and caches to store previously fetched
// or evaluated results.

use super::anchor::TrustAnchor;
use super::anchor::TrustAnchors;
use super::types::ValidationState;
use crate::base::Dname;
use crate::base::MessageBuilder;
use crate::base::Rtype;
use crate::base::ToDname;
use bytes::Bytes;
//use crate::dep::octseq::Octets;
//use crate::base::ParsedDname;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::RequestMessage;
use crate::net::client::request::SendRequest;
//use std::vec::Vec;

pub struct ValidationContext<Upstream> {
    ta: TrustAnchors,
    upstream: Upstream,
}

impl<Upstream> ValidationContext<Upstream> {
    pub fn new(ta: TrustAnchors, upstream: Upstream) -> Self {
        Self { ta, upstream }
    }

    pub async fn get_node(&self, name: &Dname<Bytes>) -> Node
    where
        Upstream: Clone + SendRequest<RequestMessage<Bytes>>,
    {
        // Check the cache first
        if let Some(node) = self.cache_lookup(name) {
            return node;
        }

        // Find a trust anchor.
        let Some(ta) = self.ta.find(name) else {
            // Try to get an indeterminate node for the root
            return Node::indeterminate();
        };

        let ta_owner = ta.owner();
        if ta_owner.name_eq(name) {
            // The trust anchor is the same node we are looking for. Create
            // a node for the trust anchor.
            todo!();
        }

        let mut curr = name.parent().unwrap();
        loop {
            if ta_owner.name_eq(&curr) {
                // We ended up at the trust anchor.
                let node =
                    Node::trust_anchor(ta, self.upstream.clone()).await;
                break;
            }

            // Try to find the node in the cache.
            if let Some(node) = self.cache_lookup(&curr) {
                todo!();
            }

            curr = curr.parent().unwrap();
        }

        // Walk from the parent of name back to trust anchor.
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
    fn indeterminate() -> Self {
        Self {
            state: ValidationState::Indeterminate,
        }
    }

    async fn trust_anchor<Upstream>(
        ta: &TrustAnchor,
        upstream: Upstream,
    ) -> Self
    where
        Upstream: SendRequest<RequestMessage<Bytes>>,
    {
        // Get the DNSKEY RRset for the trust anchor.
        let ta_owner = ta.owner();

        let mut msg = MessageBuilder::new_bytes();
        msg.header_mut().set_rd(true);
        let mut msg = msg.question();
        msg.push((ta_owner, Rtype::Dnskey)).unwrap();
        let mut req = RequestMessage::new(msg);
        req.set_dnssec_ok(true);

        let mut request = upstream.send_request(req);
        let reply = request.get_response().await;

        println!("got reply {reply:?}");
        todo!();
    }

    pub fn validation_state(&self) -> ValidationState {
        self.state
    }
}
