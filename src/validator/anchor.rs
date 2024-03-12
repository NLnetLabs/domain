// Trust anchor

pub struct TrustAnchors {
}

impl TrustAnchors {
    pub fn new() -> Self {
	Self {}
    }

    pub fn find(&self) -> Option<TrustAnchor> {
	None
    }
}

pub struct TrustAnchor {
}
