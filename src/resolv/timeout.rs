//! Timeouts and a queue for them.

use std::cmp;
use std::collections::BinaryHeap;
use rotor::Time;

//------------ Timeout ------------------------------------------------------

struct Timeout<T>(Time, T);

impl<T> Timeout<T> {
    fn new(timeout: Time, t: T) -> Self {
        Timeout(timeout, t)
    }
}

impl<T> PartialOrd for Timeout<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        other.0.partial_cmp(&self.0)
    }
}

impl<T> Ord for Timeout<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        other.0.cmp(&self.0)
    }
}

impl<T> PartialEq for Timeout<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T> Eq for Timeout<T> { }


//------------ TimeoutQueue -------------------------------------------------

/// A queue for values that time out.
pub struct TimeoutQueue<T>(BinaryHeap<Timeout<T>>);

impl<T> TimeoutQueue<T> {
    /// Creates a new timeout queue.
    pub fn new() -> Self {
        TimeoutQueue(BinaryHeap::new())
    }

    /// Returns whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Adds a new value and its timeout to the queue.
    pub fn push(&mut self, timeout: Time, t: T) {
        self.0.push(Timeout::new(timeout, t))
    }

    /// Returns the first item whose timeout has elapsed by `now`.
    pub fn pop_expired(&mut self, now: Time) -> Option<T> {
        let timeout = match self.0.peek().map(|x| x.0) {
            Some(top) => top,
            None => return None,
        };
        if timeout < now { Some(self.0.pop().unwrap().1) }
        else { None }
    }

    /// Returns the first item.
    pub fn pop(&mut self) -> Option<T> {
        self.0.pop().map(|x| x.1)
    }

    /// Removes invalid items from the head of the queue.
    ///
    /// Keeps looking at the first item in the queue. Hands a reference for
    /// the first item to `invalid()`. If that returns `true`, the item is
    /// dropped.
    /// 
    /// Call this before asking `self.next_timeout()` for the timeout if
    /// your items may actually have disappeared before timing out.
    pub fn clean_head<F: Fn(&T) -> bool>(&mut self, invalid: F) {
        loop {
            match self.0.peek() {
                None => return,
                Some(t) => {
                    if !invalid(&t.1) { return }
                }
            }
            self.pop();
        }
    }

    /// Returns the time of the next timeout or `None` if empty.
    ///
    pub fn next_timeout(&self) -> Option<Time> {
        self.0.peek().map(|x| x.0)
    }
}

