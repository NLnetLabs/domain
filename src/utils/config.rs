use std::cmp;

//------------ DefMinMax -----------------------------------------------------

/// The default, minimum, and maximum values for a config variable.
#[derive(Clone, Copy)]
pub struct DefMinMax<T> {
    /// The default value,
    def: T,

    /// The minimum value,
    min: T,

    /// The maximum value,
    max: T,
}

impl<T> DefMinMax<T> {
    /// Creates a new value.
    pub const fn new(def: T, min: T, max: T) -> Self {
        Self { def, min, max }
    }

    /// Returns the default value.
    pub fn default(self) -> T {
        self.def
    }

    /// Trims the given value to fit into the minimum/maximum range.
    pub fn limit(self, value: T) -> T
    where
        T: Ord,
    {
        cmp::max(self.min, cmp::min(self.max, value))
    }
}
