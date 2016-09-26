//! Resolver errors and results.

use std::error;
use std::io;
use std::fmt;
use std::result;
use ::bits::ComposeError;


//------------ Error ---------------------------------------------------------

/// An error happened during a query.
#[derive(Debug)]
pub enum Error {
    /// The question was broken.
    Question(ComposeError),

    /// All queries timed out.
    Timeout,

    /// All responses for a query were negative.
    NoName,

    /// At least one response was received but none was secure.
    NoSecureAnswers,

    /// At least one response was received but all were bogus.
    AllBogusAnswers,

    /// An IO error stopped queries from succeeding at all.
    Io(io::Error),
}


impl Error {
    /// Finds the most appropriate error for two failed queries.
    #[allow(match_same_arms)]
    pub fn merge(self, other: Self) -> Self {
        use self::Error::*;

        match (self, other) {
            (Question(err), _) => Question(err),

            (Timeout, Io(_)) => Timeout,
            (Timeout, other) => other,

            (NoName, NoSecureAnswers) => NoSecureAnswers,
            (NoName, AllBogusAnswers) => AllBogusAnswers,
            (NoName, _) => NoName,

            (NoSecureAnswers, _) => NoSecureAnswers,

            (AllBogusAnswers, NoSecureAnswers) => NoSecureAnswers,
            (AllBogusAnswers, _) => AllBogusAnswers,

            (Io(_), other) => other
        }
    }
}


//--- Error

impl error::Error for Error {
    fn description(&self) -> &str {
        use self::Error::*;

        match *self {
            Question(ref error) => error.description(),
            NoName => "all responses were negative",
            Timeout => "all queries timed out",
            NoSecureAnswers => "no received response was secure",
            AllBogusAnswers => "all received responses were bogus",
            Io(ref error) => error.description()
        }
    }
}


//--- From

impl From<ComposeError> for Error {
    fn from(error: ComposeError) -> Error {
        Error::Question(error)
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::Io(error)
    }
}


//--- From for io::Error

impl From<Error> for io::Error {
    fn from(error: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, error)
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

/// The result type of a query.
pub type Result<T> = result::Result<T, Error>;

