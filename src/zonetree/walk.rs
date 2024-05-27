use std::boxed::Box;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use tracing::trace;

use super::{SharedRrset, StoredName};
use crate::base::name::OwnedLabel;
use crate::base::NameBuilder;

/// A callback function invoked for each leaf node visited while walking a
/// [`Zone`].
///
/// [`Zone`]: super::Zone
pub type WalkOp = Box<dyn Fn(StoredName, &SharedRrset) + Send + Sync>;

struct WalkStateInner {
    op: WalkOp,
    label_stack: Mutex<Vec<OwnedLabel>>,
    apex_name: StoredName,
}

impl WalkStateInner {
    fn new(op: WalkOp, apex_name: StoredName) -> Self {
        Self {
            op,
            label_stack: Default::default(),
            apex_name,
        }
    }
}

#[derive(Clone)]
pub(super) struct WalkState {
    inner: Option<Arc<WalkStateInner>>,
}

impl WalkState {
    pub(super) const DISABLED: WalkState = WalkState { inner: None };

    pub(super) fn new(op: WalkOp, apex_name: StoredName) -> Self {
        Self {
            inner: Some(Arc::new(WalkStateInner::new(op, apex_name))),
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub(super) fn op(&self, rrset: &SharedRrset) {
        if let Some(inner) = &self.inner {
            let labels = inner.label_stack.lock().unwrap();
            let mut dname = NameBuilder::new_bytes();
            for label in labels.iter().rev() {
                trace!("Walk: op append label '{label}'");
                dname.append_label(label.as_slice()).unwrap();
            }
            let owner = dname.append_origin(&inner.apex_name).unwrap();
            // let owner = dname.into_name().unwrap();
            trace!("Walk: op owner '{owner}'");
            (inner.op)(owner, rrset);
        }
    }

    pub(super) fn push(&self, label: OwnedLabel) {
        trace!("Walk: push label '{label}'");
        if let Some(inner) = &self.inner {
            inner.label_stack.lock().unwrap().push(label);
        }
    }

    pub(super) fn pop(&self) {
        trace!("Walk: pop label");
        if let Some(inner) = &self.inner {
            inner.label_stack.lock().unwrap().pop();
        }
    }
}
