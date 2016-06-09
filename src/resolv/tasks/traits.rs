//! Task traits.
//!
//! The purpose of a task is to gather a certain kind of information using
//! the DNS. They do this by giving questions to a resolver and receiving
//! responses from it. If these responses contain the information in
//! question, the task succeeds. It may, however, have to ask further
//! questions and are free to do so, expecting further further responses.
//!
//! Because of the asynchronous nature of the implementation, tasks are
//! driven by the resolver. It will repeatedly call methods of the two
//! traits the task needs to implement. Each of these methods receives a
//! closure which the task can use to pass any number of questions to the
//! resolver. For each, it will later call again with a result or an
//! answer.
//!
//! There are two traits here for each of the two stages of processing. The
//! first one, `Task` is used to start a task. The resolver calls its
//! `start()` method when it is ready to start the task. It should create
//! an initial set of questions and return a value of the second trait,
//! `TaskRunner`. Whenever the resolver receives a response, it calls this
//! trait’s `progress()` method, passing in the response and the
//! aforementioned closure. The return value allows one of three options:
//! the implementation can declare success returning the task’s result,
//! it can declare failure, returning an error, or decide that it needs
//! more information. 
//!
//! When implementing a task, you can choose between implementing both
//! traits on one type or have two separate types. The `TaskRunner` trait
//! has an associated type `Success` that defines the type returned to the
//! task user upon success. If your task type is collecting information,
//! it may even be reasonable to use `Self` as the `Success` type.
//!
//! The split into two traits is mostly for the benefit `Query`, which can
//! let go of references as soon as the task has been started, avoiding
//! having to clone the domain name.

use bits::{Class, DName, MessageBuf, RRType};
use resolv::error::{Error, Result};

//------------ Progress -----------------------------------------------------

/// A type for a task indicating how to proceed.
///
/// The type is generic over three type parameters. `T` is the new state
/// when processing needs to continue, `S` is the type returned upon
/// successful completion, and `E` is the error type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Progress<T, S, E=Error> {
    /// Continue processing using the inner value as the new task state.
    Continue(T),

    /// The task has successfully completed, the result is included.
    Success(S),

    /// The task has failed with the included error.
    Error(E)
}


//------------ Task ---------------------------------------------------------

/// The interface of an unstarted task towards a resolver.
pub trait Task: Sized {
    /// The type representing the started task.
    type Runner: TaskRunner;

    /// Process the start of the task.
    ///
    /// Implementations should call `f` once for each question they have
    /// and then return their task runner.
    fn start<F>(self, f: F) -> Self::Runner 
             where F: FnMut(DName, RRType, Class);
}

/// The interface of a started task towards a resolver.
pub trait TaskRunner: Sized {
    /// The type returned by the task in case of a success.
    type Success;


    /// Process a response or error.
    ///
    /// Any response is being moved to the task. If processing the response
    /// results in further questions, these can be given to the resolver
    /// through calls of `f`. If it wants answers to these questions, it
    /// should return `Progress::Continue(Self)`. Returning anything else
    /// will end processing.
    fn progress<F>(self, response: Result<MessageBuf>, f: F)
                   -> Progress<Self, Self::Success>
                where F: FnMut(DName, RRType, Class);
}

