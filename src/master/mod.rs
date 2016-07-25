//! Reading and writing of master files.

pub use self::error::{Error, Result, SyntaxError, SyntaxResult};
pub use self::stream::{Pos, Stream};

pub mod entry;
pub mod error;
pub mod reader;
pub mod record;
pub mod stream;

