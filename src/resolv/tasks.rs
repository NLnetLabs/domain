//! Resolver tasks.

use bits::message::MessageBuf;
use bits::name::DNameSlice;
use bits::iana::{RRType, Class};
use super::{Error, Result};


//------------ Progress -----------------------------------------------------

/// A type for a task indicating how to proceed.
pub enum Progress<T, S, E=Error> {
    Continue(T),
    Success(S),
    Error(E)
}


//------------ Task ---------------------------------------------------------

/// The interface of a task towards a resolver.
///
/// There’s two methods, one called at the beginning of the task and one
/// called once for each received response or when an error occurs. Both use
/// a closure to pass a number of questions to the resolver.
pub trait Task: Sized {
    /// The type returned by the task in case of a success.
    type Success;

    /// Process the start of the task.
    ///
    /// Implementations should call *f* once for each question they have
    /// and then return themselves.
    fn start<F>(self, f: F) -> Self
             where F: FnMut(&DNameSlice, RRType, Class);

    /// Process a response or error.
    ///
    /// Any response is being moved to the task. If processing the response
    /// results in further questions, these can be given to the resolver
    /// through calls of *f*. If it wants answers to these questions, it
    /// should return `Progress::Continue(Self)`. Returning anything else
    /// will end processing.
    fn progress<F>(self, response: Result<MessageBuf>, f: F)
                   -> Progress<Self, Self::Success>
                where F: FnMut(&DNameSlice, RRType, Class);
}


//------------ Query --------------------------------------------------------

/// A basic query.
pub enum Query<'a> {
    Early(&'a DNameSlice, RRType, Class),
    Started,
}

impl<'a> Query<'a> {
    pub fn new(name: &'a DNameSlice, rtype: RRType, class: Class) -> Self {
        Query::Early(name, rtype, class)
    }
}

impl<'a> Task for Query<'a> {
    type Success = MessageBuf;

    fn start<F>(self, mut f: F) -> Self
             where F: FnMut(&DNameSlice, RRType, Class) {
        match self {
            Query::Early(name, rtype, class) => {
                f(name, rtype, class);
                Query::Started
            }
            _ => unreachable!()
        }
    }

    fn progress<F>(self, response: Result<MessageBuf>, _f: F)
                   -> Progress<Self, Self::Success>
                where F: FnMut(&DNameSlice, RRType, Class) {
        match self {
            Query::Started => {
                match response {
                    Ok(msg) => Progress::Success(msg),
                    Err(err) => Progress::Error(err)
                }
            }
            _ => unreachable!()
        }
    }
}

