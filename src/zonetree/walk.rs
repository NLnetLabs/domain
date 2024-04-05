use std::boxed::Box;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use bytes::Bytes;

use super::SharedRrset;
use crate::base::name::OwnedLabel;
use crate::base::{Dname, DnameBuilder};
use std::future::Future;
use std::pin::Pin;

/// A callback function invoked for each leaf node visited while walking a
/// [`Zone`].
pub type WalkOp<T> = Pin<
    Box<
        dyn (Fn(
                Dname<Bytes>,
                SharedRrset,
                Option<T>,
            ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>>)
            + Send
            + Sync,
    >,
>;

struct WalkStateInner<T> {
    op: WalkOp<T>,
    label_stack: Mutex<Vec<OwnedLabel>>,
}

impl<T> WalkStateInner<T> {
    fn new(op: WalkOp<T>) -> Self {
        Self {
            op,
            label_stack: Default::default(),
        }
    }
}

#[derive(Clone)]
pub(super) struct WalkState<T> {
    inner: Option<Arc<WalkStateInner<T>>>,
    meta: Option<T>,
}

impl<T: Clone> WalkState<T> {
    pub(super) const DISABLED: WalkState<T> = WalkState {
        inner: None,
        meta: None,
    };

    pub(super) fn new(op: WalkOp<T>, meta: T) -> Self {
        Self {
            inner: Some(Arc::new(WalkStateInner::new(op))),
            meta: Some(meta),
        }
    }

    pub(super) fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    pub(super) fn op(&self, rrset: &SharedRrset) {
        if let Some(inner) = &self.inner {
            let labels = inner.label_stack.lock().unwrap();
            let mut dname = DnameBuilder::new_bytes();
            for label in labels.iter().rev() {
                dname.append_label(label.as_slice()).unwrap();
            }
            let owner = dname.into_dname().unwrap();
            tokio::spawn((inner.op)(owner, rrset.clone(), self.meta.clone()));
        }
    }

    pub(super) fn push(&self, label: OwnedLabel) {
        if let Some(inner) = &self.inner {
            inner.label_stack.lock().unwrap().push(label);
        }
    }

    pub(super) fn pop(&self) {
        if let Some(inner) = &self.inner {
            inner.label_stack.lock().unwrap().pop();
        }
    }
}
