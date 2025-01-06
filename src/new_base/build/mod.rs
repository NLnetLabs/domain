//! Building DNS messages in the wire format.

mod builder;
pub use builder::{Builder, BuilderContext};

pub use super::wire::TruncationError;

//----------- Message-aware building traits ----------------------------------

/// Building into a DNS message.
pub trait BuildIntoMessage {
    // Append this value to the DNS message.
    ///
    /// If the byte string is long enough to fit the message, it is appended
    /// using the given message builder and committed.   Otherwise, a
    /// [`TruncationError`] is returned.
    fn build_into_message(
        &self,
        builder: Builder<'_>,
    ) -> Result<(), TruncationError>;
}

impl<T: ?Sized + BuildIntoMessage> BuildIntoMessage for &T {
    fn build_into_message(
        &self,
        builder: Builder<'_>,
    ) -> Result<(), TruncationError> {
        (**self).build_into_message(builder)
    }
}

impl BuildIntoMessage for [u8] {
    fn build_into_message(
        &self,
        mut builder: Builder<'_>,
    ) -> Result<(), TruncationError> {
        builder.append_bytes(self)?;
        builder.commit();
        Ok(())
    }
}
