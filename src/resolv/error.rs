//! Errors and results.

use std::error;
use std::io;
use std::fmt;
use std::result;
use bits::ComposeError;


//------------ Error --------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    /// The question was all broken.
    QuestionError(ComposeError),

    /// All responses for a query were negative.
    NoName,

    /// All queries timed out.
    Timeout,

    /// At least one response was received but none was secure.
    NoSecureAnswers,

    /// At least one response was received but all were bogus.
    AllBogusAnswers,

    /// An IO error stopped queries from succeeding at all.
    IoError(io::Error),
}

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            QuestionError(ref error) => error.description(),
            NoName => "all responses were negative",
            Timeout => "all queries timed out",
            NoSecureAnswers => "no received response was secure",
            AllBogusAnswers => "all received responses were bogus",
            IoError(ref error) => error.description()
        }
    }
}

impl From<ComposeError> for Error {
    fn from(error: ComposeError) -> Error {
        Error::QuestionError(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}


//------------ Result -------------------------------------------------------

pub type Result<T> = result::Result<T, Error>;
