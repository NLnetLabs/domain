//! Parsing DNS records.

use core::{convert::Infallible, ops::ControlFlow};

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::new_base::Record;

//----------- Trait definitions ----------------------------------------------

/// A type that can be constructed by parsing exactly one DNS record.
pub trait ParseRecord<'a>: Sized {
    /// The type of parse errors.
    // TODO: Remove entirely?
    type Error;

    /// Parse the given DNS record.
    fn parse_record(
        record: Record<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error>;
}

/// A type that can be constructed by parsing zero or more DNS records.
pub trait ParseRecords<'a>: Sized {
    /// The type of visitors for incrementally building the output.
    type Visitor: Default + VisitRecord<'a>;

    /// The type of errors from converting a visitor into [`Self`].
    // TODO: Just use 'Visitor::Error'?  Or remove entirely?
    type Error;

    /// Convert a visitor back to this type.
    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error>;
}

/// A type that can visit DNS records.
pub trait VisitRecord<'a> {
    /// The type of errors produced by visits.
    type Error;

    /// Visit a record.
    fn visit_record(
        &mut self,
        record: Record<'a>,
    ) -> Result<ControlFlow<()>, Self::Error>;
}

//----------- Trait implementations ------------------------------------------

impl<'a> ParseRecord<'a> for Record<'a> {
    type Error = Infallible;

    fn parse_record(
        record: Record<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error> {
        Ok(ControlFlow::Break(record))
    }
}

//--- Impls for 'Option<T>'

impl<'a, T: ParseRecord<'a>> ParseRecord<'a> for Option<T> {
    type Error = T::Error;

    fn parse_record(
        record: Record<'a>,
    ) -> Result<ControlFlow<Self>, Self::Error> {
        Ok(match T::parse_record(record)? {
            ControlFlow::Break(elem) => ControlFlow::Break(Some(elem)),
            ControlFlow::Continue(()) => ControlFlow::Continue(()),
        })
    }
}

impl<'a, T: ParseRecord<'a>> ParseRecords<'a> for Option<T> {
    type Visitor = Option<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor)
    }
}

impl<'a, T: ParseRecord<'a>> VisitRecord<'a> for Option<T> {
    type Error = T::Error;

    fn visit_record(
        &mut self,
        record: Record<'a>,
    ) -> Result<ControlFlow<()>, Self::Error> {
        if self.is_some() {
            return Ok(ControlFlow::Continue(()));
        }

        Ok(match T::parse_record(record)? {
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
impl<'a, T: ParseRecord<'a>> ParseRecords<'a> for Vec<T> {
    type Visitor = Vec<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor)
    }
}

#[cfg(feature = "std")]
impl<'a, T: ParseRecord<'a>> VisitRecord<'a> for Vec<T> {
    type Error = T::Error;

    fn visit_record(
        &mut self,
        record: Record<'a>,
    ) -> Result<ControlFlow<()>, Self::Error> {
        Ok(match T::parse_record(record)? {
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
impl<'a, T: ParseRecord<'a>> ParseRecords<'a> for Box<[T]> {
    type Visitor = Vec<T>;
    type Error = Infallible;

    fn from_visitor(visitor: Self::Visitor) -> Result<Self, Self::Error> {
        Ok(visitor.into_boxed_slice())
    }
}
