//! Parsing DNS questions.

use core::{convert::Infallible, ops::ControlFlow};

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::new_base::Question;

//----------- Trait definitions ----------------------------------------------

/// A type that can be constructed by parsing exactly one DNS question.
pub trait ParseQuestion<'a>: Sized {
    /// The type of parse errors.
    // TODO: Remove entirely?
    type Error;

    /// Parse the given DNS question.
    fn parse_question(
        question: Question<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error>;
}

/// A type that can be constructed by parsing zero or more DNS questions.
pub trait ParseQuestions<'a>: Sized {
    /// The type of visitors for incrementally building the output.
    type Visitor: Default + VisitQuestion<'a>;

    /// The type of errors from converting a visitor into [`Self`].
    // TODO: Just use 'Visitor::Error'?  Or remove entirely?
    type Error;

    /// Convert a visitor back to this type.
    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error>;
}

/// A type that can visit DNS questions.
pub trait VisitQuestion<'a> {
    /// The type of errors produced by visits.
    type Error;

    /// Visit a question.
    fn visit_question(
        &mut self,
        question: Question<'a>,
    ) -> Result<ControlFlow<()>, Self::Error>;
}

//----------- Trait implementations ------------------------------------------

impl<'a> ParseQuestion<'a> for Question<'a> {
    type Error = Infallible;

    fn parse_question(
        question: Question<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error> {
        Ok(ControlFlow::Break(question))
    }
}

//--- Impls for 'Option<T>'

impl<'a, T: ParseQuestion<'a>> ParseQuestion<'a> for Option<T> {
    type Error = T::Error;

    fn parse_question(
        question: Question<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error> {
        Ok(match T::parse_question(question)? {
            ControlFlow::Break(elem) => ControlFlow::Break(Some(elem)),
            ControlFlow::Continue(()) => ControlFlow::Continue(()),
        })
    }
}

impl<'a, T: ParseQuestion<'a>> ParseQuestions<'a> for Option<T> {
    type Visitor = Option<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor)
    }
}

impl<'a, T: ParseQuestion<'a>> VisitQuestion<'a> for Option<T> {
    type Error = T::Error;

    fn visit_question(
        &mut self,
        question: Question<'a>,
    ) -> Result<ControlFlow<()>, Self::Error> {
        if self.is_some() {
            return Ok(ControlFlow::Continue(()));
        }

        Ok(match T::parse_question(question)? {
            ControlFlow::Break(elem) => {
                *self = Some(elem);
                ControlFlow::Break(())
            }
            ControlFlow::Continue(()) => ControlFlow::Continue(()),
        })
    }
}

//--- Impls for 'Vec<T>'

#[cfg(feature = "std")]
impl<'a, T: ParseQuestion<'a>> ParseQuestions<'a> for Vec<T> {
    type Visitor = Vec<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor)
    }
}

#[cfg(feature = "std")]
impl<'a, T: ParseQuestion<'a>> VisitQuestion<'a> for Vec<T> {
    type Error = T::Error;

    fn visit_question(
        &mut self,
        question: Question<'a>,
    ) -> Result<ControlFlow<()>, Self::Error> {
        Ok(match T::parse_question(question)? {
            ControlFlow::Break(elem) => {
                self.push(elem);
                ControlFlow::Break(())
            }
            ControlFlow::Continue(()) => ControlFlow::Continue(()),
        })
    }
}

//--- Impls for 'Box<[T]>'

#[cfg(feature = "std")]
impl<'a, T: ParseQuestion<'a>> ParseQuestions<'a> for Box<[T]> {
    type Visitor = Vec<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor.into_boxed_slice())
    }
}
