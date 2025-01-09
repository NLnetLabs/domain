//! Record data types for Extended DNS.
//!
//! See [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).

use core::{fmt, iter::FusedIterator};

use domain_macros::*;

use crate::{
    new_base::{
        build::{self, BuildIntoMessage, BuildResult},
        wire::{ParseError, SplitBytes},
    },
    new_edns::EdnsOption,
};

//----------- Opt ------------------------------------------------------------

/// Extended DNS options.
#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, AsBytes, BuildBytes, ParseBytesByRef,
)]
#[repr(transparent)]
pub struct Opt {
    /// The raw serialized options.
    contents: [u8],
}

//--- Inspection

impl Opt {
    /// Traverse the options in this record.
    pub fn options(&self) -> EdnsOptionsIter<'_> {
        EdnsOptionsIter::new(&self.contents)
    }
}

//--- Formatting

impl fmt::Debug for Opt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Opt").field(&self.options()).finish()
    }
}

// TODO: Formatting.

//--- Building into DNS messages

impl BuildIntoMessage for Opt {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.contents.build_into_message(builder)
    }
}

//----------- EdnsOptionsIter ------------------------------------------------

/// An iterator over EDNS options in an [`Opt`] record.
#[derive(Clone)]
pub struct EdnsOptionsIter<'a> {
    /// The serialized options to parse from.
    options: &'a [u8],
}

//--- Construction

impl<'a> EdnsOptionsIter<'a> {
    /// Construct a new [`EdnsOptionsIter`].
    pub const fn new(options: &'a [u8]) -> Self {
        Self { options }
    }
}

//--- Inspection

impl<'a> EdnsOptionsIter<'a> {
    /// The serialized options yet to be parsed.
    pub const fn remaining(&self) -> &'a [u8] {
        self.options
    }
}

//--- Formatting

impl fmt::Debug for EdnsOptionsIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut entries = f.debug_set();
        for option in self.clone() {
            match option {
                Ok(option) => entries.entry(&option),
                Err(_err) => entries.entry(&format_args!("<error>")),
            };
        }
        entries.finish()
    }
}

//--- Iteration

impl<'a> Iterator for EdnsOptionsIter<'a> {
    type Item = Result<EdnsOption<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.options.is_empty() {
            let options = core::mem::take(&mut self.options);
            match EdnsOption::split_bytes(options) {
                Ok((option, rest)) => {
                    self.options = rest;
                    Some(Ok(option))
                }
                Err(err) => Some(Err(err)),
            }
        } else {
            None
        }
    }
}

impl FusedIterator for EdnsOptionsIter<'_> {}
