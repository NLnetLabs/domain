//! Resolver errors and results.

use std::error;
use std::io;
use std::fmt;
use std::result;
use ::bits::ComposeError;


//------------ Error ---------------------------------------------------------

/// An error happened during a lookup.
#[derive(Debug)]
pub enum Error {
    /// The question was broken.
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


impl Error {
    /// Returns whether this error spells the end of a lookup.
    pub fn is_fatal(&self) -> bool {
        match *self {
            Error::QuestionError(_) => true,
            _ => false
        }
    }

    /// Finds the most appropriate error for two failed lookups.
    pub fn merge(self, other: Self) -> Self {
        use self::Error::*;

        match (self, other) {
            (QuestionError(err), _) => QuestionError(err),

            (NoName, NoSecureAnswers) => NoSecureAnswers,
            (NoName, AllBogusAnswers) => AllBogusAnswers,
            (NoName, _) => NoName,

            (Timeout, IoError(_)) => Timeout,
            (Timeout, other) => other,

            (NoSecureAnswers, _) => NoSecureAnswers,

            (AllBogusAnswers, NoSecureAnswers) => NoSecureAnswers,
            (AllBogusAnswers, _) => AllBogusAnswers,

            (IoError(_), other) => other
        }
    }
}


//--- Error

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


//--- From

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


//--- Display

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}


//------------ Result --------------------------------------------------------

/// The result type of a lookup.
pub type Result<T> = result::Result<T, Error>;

