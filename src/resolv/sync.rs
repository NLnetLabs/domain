//! Helper types for the rotor-based DNS transport.

use std::clone::Clone;
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
///
/// Note that because the receiver internally holds a sender for later
/// cloning, it will never disconnect.
pub struct RotorReceiver<T> {
    receiver: mpsc::Receiver<T>,
    sender: mpsc::Sender<T>,
    notifier: Option<Notifier>,
}

impl<T> RotorReceiver<T> {
    pub fn new(notifier: Option<Notifier>) -> RotorReceiver<T> {
        let (tx, rx) = mpsc::channel();
        RotorReceiver { receiver: rx, sender: tx, notifier: notifier }
    }

    pub fn try_recv(&self) -> Result<T, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }

    pub fn recv(&self) -> Result<T, mpsc::RecvError> {
        self.receiver.recv()
    }

    pub fn sender(&self) -> RotorSender<T> {
        RotorSender::new(self.sender.clone(), self.notifier.clone())
    }
}


//------------ RotorSender --------------------------------------------------

/// A sender to a mpsc channel waking up the receiver.
#[derive(Debug)]
pub struct RotorSender<T> {
    sender: Option<mpsc::Sender<T>>,
    notifier: Option<Notifier>
}

impl<T> RotorSender<T> {
    pub fn new(sender: mpsc::Sender<T>, notifier: Option<Notifier>) -> Self {
        RotorSender { sender: Some(sender), notifier: notifier }
    }

    pub fn send(&self, t: T) -> Result<(), mpsc::SendError<T>> {
        match self.sender {
            None => Err(mpsc::SendError(t)),
            Some(ref sender) => {
                try!(sender.send(t));
                if let Some(ref notifier) = self.notifier {
                    let _ = notifier.wakeup();
                }
                Ok(())
            }
        }
    }
}

impl<T> Clone for RotorSender<T> {
    fn clone(&self) -> Self {
        RotorSender {
            sender: self.sender.clone(),
            notifier: self.notifier.clone(),
        }
    }
}

impl<T> Drop for RotorSender<T> {
    fn drop(&mut self) {
        self.sender = None;
        match self.notifier {
            None => None,
            Some(ref notifier) => notifier.wakeup().ok()
        };
    }
}


//------------ Functions ----------------------------------------------------

pub fn channel<T>(notifier: Option<Notifier>)
                  -> (RotorSender<T>, mpsc::Receiver<T>)  {
    let (tx, rx) = mpsc::channel();
    (RotorSender::new(tx, notifier), rx)
}

