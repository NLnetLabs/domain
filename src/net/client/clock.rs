//! A time interface that can be replaced by a fake time implementation
//! during testing.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time;
use std::time::Duration;

//------------ Clock -----------------------------------------------------------

/// A trait for storing the current time in an object that implements the
/// [Elapsed] trait.
pub trait Clock: Clone {
    /// The type that implements the [Elapsed] trait.
    type Instant: Clone + Debug + Elapsed + Send + Sync;

    /// Create a new instance of the clock.
    fn new() -> Self;

    /// Record the current time in an [Self::Instant] object.
    fn now(&self) -> Self::Instant;
}

//------------ Elapsed --------------------------------------------------------

/// Trait for reporting the time that has elapsed since the creation of an
/// instance object.
pub trait Elapsed {
    /// Return the elapsed time.
    fn elapsed(&self) -> Duration;
}

//------------ SystemClock -----------------------------------------------------

/// Implementation of the [Clock] trait using the Instant type from
/// std::time.
#[derive(Clone, Debug)]
pub struct SystemClock {}

impl Clock for SystemClock {
    type Instant = time::Instant;

    fn new() -> Self {
        Self {}
    }

    fn now(&self) -> Self::Instant {
        Self::Instant::now()
    }
}

impl Elapsed for time::Instant {
    fn elapsed(&self) -> Duration {
        self.elapsed()
    }
}

//------------ FakeClock -----------------------------------------------------

/// Implementation of the [Clock] trait to fake the passing of time, for example
/// for testing.
#[derive(Clone, Debug)]
pub struct FakeClock {
    /// The current fake time.
    now: Arc<Mutex<Duration>>,
}

impl FakeClock {
    /// Adjust the current time by adding a [Duration]
    pub fn adjust_time(&self, adjust: Duration) {
        println!("adjust_time: adjust {:?}", adjust);
        let mut now = self.now.lock().unwrap();
        *now = (*now).checked_add(adjust).unwrap();
    }

    /// Return the current (fake) time.
    fn curr_time(&self) -> Duration {
        let now = self.now.lock().unwrap();
        *now
    }
}

impl Clock for FakeClock {
    type Instant = FakeInstant;

    fn new() -> Self {
        Self {
            now: Arc::new(Mutex::new(Duration::from_secs(0))),
        }
    }

    fn now(&self) -> Self::Instant {
        let now = self.now.lock().unwrap();
        Self::Instant::now(*now, self.clone())
    }
}

//------------ FakeInstant ----------------------------------------------------

/// An instant that provides fake time.
#[derive(Clone, Debug)]
pub struct FakeInstant {
    /// When the FakeInstant was created.
    start: Duration,

    /// The clock that was used to create it.
    clock: FakeClock,
}

impl FakeInstant {
    /// Create a new FakeInstant.
    fn now(now: Duration, clock: FakeClock) -> Self {
        Self { start: now, clock }
    }
}

impl Elapsed for FakeInstant {
    fn elapsed(&self) -> Duration {
        self.clock.curr_time().checked_sub(self.start).unwrap()
    }
}
