//! Building DNS messages in the wire format.

mod builder;
pub use builder::{Builder, BuilderContext};

mod message;
pub use message::MessageBuilder;

mod record;
pub use record::RecordBuilder;

use super::wire::TruncationError;

//----------- Message-aware building traits ----------------------------------

/// Building into a DNS message.
pub trait BuildIntoMessage {
    // Append this value to the DNS message.
    ///
    /// If the builder has enough capacity to fit the message, it is appended
    /// and committed.   Otherwise, a [`TruncationError`] is returned.
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult;
}

impl<T: ?Sized + BuildIntoMessage> BuildIntoMessage for &T {
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult {
        (**self).build_into_message(builder)
    }
}

impl BuildIntoMessage for [u8] {
    fn build_into_message(&self, mut builder: Builder<'_>) -> BuildResult {
        builder.append_bytes(self)?;
        Ok(builder.commit())
    }
}

//----------- BuildResult ----------------------------------------------------

/// The result of building into a DNS message.
pub type BuildResult = Result<BuildCommitted, TruncationError>;

//----------- BuildCommitted -------------------------------------------------

/// The output of [`Builder::commit()`].
///
/// This is a stub type to remind users to call [`Builder::commit()`] in all
/// success paths of building functions.
#[derive(Debug)]
pub struct BuildCommitted;
