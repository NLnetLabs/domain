//! Building DNS records.

use crate::new_base::{
    name::RevName,
    wire::{AsBytes, TruncationError},
    Header, Message, RClass, RType, TTL,
};

use super::{BuildCommitted, BuildIntoMessage, Builder};

//----------- RecordBuilder --------------------------------------------------

/// A builder for a DNS record.
///
/// This is used to incrementally build the data for a DNS record.  It can be
/// constructed using [`MessageBuilder::build_answer()`] etc.
///
/// [`MessageBuilder::build_answer()`]: super::MessageBuilder::build_answer()
pub struct RecordBuilder<'b> {
    /// The underlying [`Builder`].
    ///
    /// Its commit point lies at the beginning of the record.
    inner: Builder<'b>,

    /// The position of the record data.
    ///
    /// This is an offset from the message contents.
    start: usize,

    /// The section the record is a part of.
    ///
    /// The appropriate section count will be incremented on completion.
    section: u8,
}

//--- Initialization

impl<'b> RecordBuilder<'b> {
    /// Construct a [`RecordBuilder`] from raw parts.
    ///
    /// # Safety
    ///
    /// - `builder`, `start`, and `section` are paired together.
    pub unsafe fn from_raw_parts(
        builder: Builder<'b>,
        start: usize,
        section: u8,
    ) -> Self {
        Self {
            inner: builder,
            start,
            section,
        }
    }

    /// Initialize a new [`RecordBuilder`].
    ///
    /// A new record with the given name, type, and class will be created.
    /// The returned builder can be used to add data for the record.
    ///
    /// The count for the specified section (1, 2, or 3, i.e. answers,
    /// authorities, and additional records respectively) will be incremented
    /// when the builder finishes successfully.
    pub fn new(
        mut builder: Builder<'b>,
        rname: impl BuildIntoMessage,
        rtype: RType,
        rclass: RClass,
        ttl: TTL,
        section: u8,
    ) -> Result<Self, TruncationError> {
        debug_assert_eq!(builder.appended(), &[] as &[u8]);
        debug_assert!((1..4).contains(&section));

        assert!(builder
            .header()
            .counts
            .as_array()
            .iter()
            .skip(1 + section as usize)
            .all(|&c| c == 0));

        // Build the record header.
        rname.build_into_message(builder.delegate())?;
        builder.append_bytes(rtype.as_bytes())?;
        builder.append_bytes(rclass.as_bytes())?;
        builder.append_bytes(ttl.as_bytes())?;
        let start = builder.appended().len();

        // Set up the builder.
        Ok(Self {
            inner: builder,
            start,
            section,
        })
    }
}

//--- Inspection

impl<'b> RecordBuilder<'b> {
    /// The message header.
    pub fn header(&self) -> &Header {
        self.inner.header()
    }

    /// The message without this record.
    pub fn message(&self) -> &Message {
        self.inner.message()
    }

    /// The record data appended thus far.
    pub fn data(&self) -> &[u8] {
        &self.inner.appended()[self.start..]
    }

    /// Decompose this builder into raw parts.
    ///
    /// This returns the underlying builder, the offset of the record data in
    /// the record, and the section number for this record (1, 2, or 3).  The
    /// builder can be recomposed with [`Self::from_raw_parts()`].
    pub fn into_raw_parts(self) -> (Builder<'b>, usize, u8) {
        (self.inner, self.start, self.section)
    }
}

//--- Interaction

impl RecordBuilder<'_> {
    /// Finish the record.
    ///
    /// The respective section count will be incremented.  The builder will be
    /// consumed and the record will be committed.
    pub fn finish(mut self) -> BuildCommitted {
        // Increment the appropriate section count.
        self.inner.header_mut().counts.as_array_mut()
            [self.section as usize] += 1;

        self.inner.commit()
    }

    /// Delegate to a new builder.
    ///
    /// Any content committed by the builder will be added as record data.
    pub fn delegate(&mut self) -> Builder<'_> {
        self.inner.delegate()
    }

    /// Append some bytes.
    ///
    /// No name compression will be performed.
    pub fn append_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), TruncationError> {
        self.inner.append_bytes(bytes)
    }

    /// Compress and append a domain name.
    pub fn append_name(
        &mut self,
        name: &RevName,
    ) -> Result<(), TruncationError> {
        self.inner.append_name(name)
    }
}
