//! A time interface that can be replaced by a fake time implementation
//! during testing.

use std::fmt::Debug;
use std::sync::Mutex;
use std::time;
use std::time::Duration;

//------------ Time -----------------------------------------------------------

/// A trait for storing the current time in an object that implements the
/// [Elapsed] trait.
pub trait Time {
    /// The type that implements the [Elapsed] trait.
    type Instant: Copy + Debug + Elapsed + Send + Sync;

    /// Record the current time in an [Instant] object.
    fn now() -> Self::Instant;
}

//------------ Elapsed --------------------------------------------------------

/// Trait for reporting the time that has elapsed since the creation of an
/// instance object.
pub trait Elapsed {
    /// Return the elapsed time.
    fn elapsed(&self) -> Duration;
}

//------------ SimpleTime -----------------------------------------------------

/// Simple implementation of the [Time] trait using the Instant type from
/// std::time.
#[derive(Debug)]
pub struct SimpleTime {}

impl Time for SimpleTime {
    type Instant = time::Instant;

    fn now() -> Self::Instant {
        Self::Instant::now()
    }
}

impl Elapsed for time::Instant {
    fn elapsed(&self) -> Duration {
        self.elapsed()
    }
}

//------------ FakeTime -----------------------------------------------------

/// Implementation of the [Time] trait to fake the passing of time, for example
/// for testing.
#[derive(Debug)]
pub struct FakeTime {}

impl FakeTime {
    /// Adjust the current time by adding a [Duration]
    pub fn adjust_time(adjust: Duration) {
        println!("adjust_time: adjust {:?}", adjust);
        CURRENT_FAKE_TIME.with(|m_ft| {
            let mut ft = m_ft.lock().unwrap();
            *ft = (*ft).checked_add(adjust).unwrap();
        });
    }
}

impl Time for FakeTime {
    type Instant = FakeInstant;

    fn now() -> Self::Instant {
        Self::Instant::now()
    }
}

thread_local! {
    static CURRENT_FAKE_TIME: Mutex<Duration> = const { Mutex::new(Duration::from_secs(0)) };
}

//------------ FakeInstant ----------------------------------------------------

/// An instant that provides fake time.
#[derive(Clone, Copy, Debug)]
pub struct FakeInstant(Duration);

impl FakeInstant {
    fn now() -> Self {
        let current_fake_time =
            CURRENT_FAKE_TIME.with(|ft| *ft.lock().unwrap());
        Self(current_fake_time)
    }
}

impl Elapsed for FakeInstant {
    fn elapsed(&self) -> Duration {
        CURRENT_FAKE_TIME.with(|m_ft| {
            let ft = m_ft.lock().unwrap();
            let now = *ft;
            now.checked_sub(self.0).unwrap()
        })
    }
}
