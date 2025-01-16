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
///
/// This is used in [`BuildIntoMessage::build_into_message()`].
pub type BuildResult = Result<BuildCommitted, TruncationError>;

//----------- BuildCommitted -------------------------------------------------

/// The output of [`Builder::commit()`].
///
/// This is a simple marker type, produced by [`Builder::commit()`].  Certain
/// trait methods (e.g. [`BuildIntoMessage::build_into_message()`]) require it
/// in the return type, as a way to remind users to commit their builders.
///
/// # Examples
///
/// If `build_into_message()` simply returned a unit type, an example impl may
/// look like:
///
/// ```compile_fail
/// # use domain::new_base::name::RevName;
/// # use domain::new_base::build::{BuildIntoMessage, Builder, BuildResult};
/// # use domain::new_base::wire::AsBytes;
///
/// struct Foo<'a>(&'a RevName, u8);
///
/// impl BuildIntoMessage for Foo<'_> {
///     fn build_into_message(
///         &self,
///         mut builder: Builder<'_>,
///     ) -> BuildResult {
///         builder.append_name(self.0)?;
///         builder.append_bytes(self.1.as_bytes());
///         Ok(())
///     }
/// }
/// ```
///
/// This code is incorrect: since the appended content is not committed, the
/// builder will remove it when it is dropped (at the end of the function),
/// and so nothing gets written.  Instead, users have to write:
///
/// ```
/// # use domain::new_base::name::RevName;
/// # use domain::new_base::build::{BuildIntoMessage, Builder, BuildResult};
/// # use domain::new_base::wire::AsBytes;
///
/// struct Foo<'a>(&'a RevName, u8);
///
/// impl BuildIntoMessage for Foo<'_> {
///     fn build_into_message(
///         &self,
///         mut builder: Builder<'_>,
///     ) -> BuildResult {
///         builder.append_name(self.0)?;
///         builder.append_bytes(self.1.as_bytes());
///         Ok(builder.commit())
///     }
/// }
/// ```
#[derive(Debug)]
pub struct BuildCommitted;
