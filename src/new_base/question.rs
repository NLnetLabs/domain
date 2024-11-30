//! DNS questions.

use core::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use zerocopy::{network_endian::U16, FromBytes};
use zerocopy_derive::*;

use super::{
    name::ParsedName,
    parse::{ParseError, SplitFrom},
};

//----------- Question -------------------------------------------------------

/// A DNS question.
///
/// # Memory Layout
///
/// A [`Question`] is laid out in memory as:
///
/// ```text
/// +- .. -+------+-------+
/// | name | type | class |
/// +- .. -+------+-------+
/// ```
///
/// The name field is dynamically sized.  The type and class are packaged in a
/// [`QuestionFields`] and can be accessed implicitly via [`Deref`].
///
/// [`Question`] is declared `repr(transparent)`, and can be transmuted to and
/// from a [`ParsedName`] directly.  A [`Question`] must only be constructed
/// when the name field is followed by a type and class.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct Question {
    /// The fields in the question.
    _fields: PhantomData<QuestionFields>,

    /// The domain name being requested.
    pub name: ParsedName,
}

//--- Construction

impl Question {
    /// Assume a [`ParsedName`] is the start of a [`Question`].
    ///
    /// # Safety
    ///
    /// The [`ParsedName`] must be followed in memory by a [`QuestionFields`].
    /// The fields will be borrowed by the returned [`Question`], so they must
    /// be immutably borrowed for the lifetime of the reference.
    pub const unsafe fn from_name_unchecked(name: &ParsedName) -> &Self {
        // SAFETY: The caller has verified that a 'QuestionFields' follows.
        unsafe { core::mem::transmute(name) }
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a Question {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (name, rest) = <&ParsedName>::split_from(bytes)?;
        let (_, rest) = QuestionFields::ref_from_prefix(rest)?;
        // SAFETY: The 'ParsedName' is followed by a 'QuestionFields', and
        // both are borrowed immutably for the lifetime of the reference.
        Ok((unsafe { Question::from_name_unchecked(name) }, rest))
    }
}

//--- Access to variable-length fields

impl Deref for Question {
    type Target = QuestionFields;

    fn deref(&self) -> &Self::Target {
        let name_end = self.name.as_bytes().as_ptr_range().end;
        // SAFETY: The 'ParsedName' is always followed by a 'QuestionFields'.
        unsafe { &*name_end.cast::<QuestionFields>() }
    }
}

impl DerefMut for Question {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let name_end = self.name.as_bytes().as_ptr_range().end;
        // SAFETY: The 'ParsedName' is always followed by a 'QuestionFields'.
        unsafe { &mut *name_end.cast_mut().cast::<QuestionFields>() }
    }
}

//----------- QuestionFields -------------------------------------------------

/// The fields in a DNS question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct QuestionFields {
    /// The type of the question.
    pub qtype: QType,

    /// The class of the question.
    pub qclass: QClass,
}

//----------- QType ----------------------------------------------------------

/// The type of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct QType {
    /// The type code.
    pub code: U16,
}

//----------- QClass ---------------------------------------------------------

/// The class of a question.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct QClass {
    /// The class code.
    pub code: U16,
}
