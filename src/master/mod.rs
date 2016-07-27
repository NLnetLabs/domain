//! Reading and writing of master files.

pub use self::error::{Pos, ScanError, ScanResult, SyntaxError, SyntaxResult};
pub use self::scanner::Scanner;

pub mod bufscanner;
pub mod entry;
pub mod error;
pub mod reader;
pub mod record;
pub mod scanner;

