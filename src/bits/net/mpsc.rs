//! An MPSC with futures.

use std::{error, fmt};
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::atomic::Ordering::SeqCst;
use crossbeam::sync::{AtomicOption, MsQueue};
use futures::Async;
use futures::stream::Stream;
use futures::task::{Task, park};
use void::Void;

//------------ channel ------------------------------------------------------

pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    Inner::new()
}


//------------ Inner --------------------------------------------------------

struct Inner<T> {
    queue: MsQueue<T>,
    tx_count: AtomicUsize,
    rx_dropped: AtomicBool,
    rx_task: AtomicOption<Task>,
}

impl<T> Inner<T> {
    fn new() -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(Inner {
            queue: MsQueue::new(),
            tx_count: AtomicUsize::new(1),
            rx_dropped: AtomicBool::new(false),
            rx_task: AtomicOption::new()
        });
        (Sender{inner: inner.clone()}, Receiver{inner: inner})
    }
}


//------------ Sender -------------------------------------------------------

pub struct Sender<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Sender<T> {
    pub fn send(&self, t: T) -> Result<(), T> {
        if self.inner.rx_dropped.load(SeqCst) {
            Err(t)
        }
        else {
            self.inner.queue.push(t);
            if let Some(task) = self.inner.rx_task.take(SeqCst) {
                task.unpark()
            }
            Ok(())
        }
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        let inner = self.inner.clone();
        let _ = inner.tx_count.fetch_add(1, SeqCst);
        Sender{inner: inner}
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let _ = self.inner.tx_count.fetch_sub(1, SeqCst);
    }
}


//------------ Receiver ------------------------------------------------------

pub struct Receiver<T> {
    inner: Arc<Inner<T>>,
}


impl<T> Stream for Receiver<T> {
    type Item = T;
    type Error = Void;

    fn poll(&mut self) -> Result<Async<Option<T>>, Void> {
        if self.inner.tx_count.load(SeqCst) == 0 {
            Ok(Async::Ready(None))
        }
        else if let Some(t) = self.inner.queue.try_pop() {
            Ok(Async::Ready(Some(t)))
        }
        else {
            self.inner.rx_task.swap(park(), SeqCst);
            Ok(Async::NotReady)
        }
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        self.inner.rx_dropped.store(true, SeqCst)
    }
}


//------------ SendError ----------------------------------------------------

pub struct SendError<T>(T);

impl<T> fmt::Debug for SendError<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_tuple("SendError")
            .field(&"...")
            .finish()
    }
}

impl<T> fmt::Display for SendError<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "send failed because receiver is gone")
    }
}

impl<T: Any> error::Error for SendError<T> {
    fn description(&self) -> &str {
        "send failed because receiver is gone"
    }
}

