//! Helper types for the rotor-based DNS transport.

use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use rotor::{Notifier, WakeupError};


//------------ SharedNotifier -----------------------------------------------

/// A notifer shared between state machine and user.
///
/// This type exists because it is not possible to extract a notifier to a
/// state machine created by some other state machine before it first ran.
#[derive(Clone)]
pub struct SharedNotifier(Arc<Mutex<Option<Notifier>>>);

impl SharedNotifier {
    /// Creates a new, empty notifier.
    pub fn new() -> SharedNotifier {
        SharedNotifier(Arc::new(Mutex::new(None)))
    }

    /// Sets the notifier.
    pub fn set(&self, notifier: Notifier) {
        self.0.lock().as_mut().map(|x| **x = Some(notifier)).ok();
    }

    /// Wake up the state machine if there is a notifier.
    ///
    /// Panics on any wakeup error other than `WakeupError::Closed` which
    /// is ignored.
    pub fn wakeup(&self) {
        match self.0.lock().unwrap().deref() {
            &None => (),
            &Some(ref notifier) => {
                match notifier.wakeup() {
                    Ok(()) | Err(WakeupError::Closed) => (),
                    Err(err) => panic!("Wakeup failed: {}", err)
                }
            }
        }
    }
}


//------------ RotorReceiver ------------------------------------------------

/// An `mpsc::Receiver` that can produce a `RotorSender` if necessary.
pub struct RotorReceiver<T> {
    receiver: mpsc::Receiver<T>,
    sender: mpsc::Sender<T>,
    notifier: Notifier,
}

impl<T> RotorReceiver<T> {
    pub fn new(notifier: Notifier) -> RotorReceiver<T> {
        let (tx, rx) = mpsc::channel();
        RotorReceiver { receiver: rx, sender: tx, notifier: notifier }
    }

    pub fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn sender(&self) -> RotorSender<T> {
        RotorSender::new(self.sender.clone(), self.notifier.clone())
    }
}


//------------ RotorSender --------------------------------------------------

/// A sender to a mpsc channel waking up the receiver.
#[derive(Debug)]
pub struct RotorSender<T> {
    sender: mpsc::Sender<T>,
    notifier: Notifier
}

impl<T> RotorSender<T> {
    pub fn new(sender: mpsc::Sender<T>, notifier: Notifier) -> Self {
        RotorSender { sender: sender, notifier: notifier }
    }

    pub fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        try!(self.sender.send(t));
        let _ = self.notifier.wakeup();
        Ok(())
    }
}

impl<T> Clone for RotorSender<T> {
    fn clone(&self) -> Self {
        RotorSender::new(self.sender.clone(), self.notifier.clone())
    }
}

//------------ MaybeRotorSender ---------------------------------------------

/// A sender to an mpsc channel that may need to be woken up.
#[derive(Clone, Debug)]
pub struct MaybeRotorSender<T> {
    sender: mpsc::Sender<T>,
    notifier: Option<Notifier>
}

impl<T> MaybeRotorSender<T> {
    pub fn new(sender: mpsc::Sender<T>, notifier: Option<Notifier>) -> Self {
        MaybeRotorSender { sender: sender, notifier: notifier }
    }

    pub fn channel() -> (Self, mpsc::Receiver<T>) {
        let (tx, rx) = mpsc::channel();
        (MaybeRotorSender::new(tx, None), rx)
    }

    pub fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        try!(self.sender.send(t));
        if let Some(ref notifier) = self.notifier {
            let _ = notifier.wakeup();
        }
        Ok(())
    }
}

