//! Building DNS records.

use core::{mem::ManuallyDrop, ptr};

use crate::new_base::{
    name::UnparsedName,
    parse::ParseMessageBytes,
    wire::{AsBytes, ParseBytes, SizePrefixed, TruncationError},
    RClass, RType, Record, TTL,
};

use super::{
    BuildCommitted, BuildIntoMessage, Builder, MessageBuilder, MessageState,
};

//----------- RecordBuilder ------------------------------------------------

/// A DNS record builder.
///
/// A [`RecordBuilder`] provides access to a record that has been appended to
/// a DNS message (using a [`MessageBuilder`]).  It can be used to inspect the
/// record, to (re)write the record data, and to commit (finish building) or
/// cancel (remove) the record.
pub struct RecordBuilder<'b> {
    /// The underlying message builder.
    builder: MessageBuilder<'b>,

    /// The offset of the record name.
    name: u16,

    /// The offset of the record data.
    data: u16,
}

//--- Construction

impl<'b> RecordBuilder<'b> {
    /// Build a [`Record`].
    ///
    /// The provided builder must be empty (i.e. must not have uncommitted
    /// content).
    pub(super) fn build<N, D>(
        mut builder: MessageBuilder<'b>,
        record: &Record<N, D>,
    ) -> Result<Self, TruncationError>
    where
        N: BuildIntoMessage,
        D: BuildIntoMessage,
    {
        // Build the record and remember important positions.
        let start = builder.context.size;
        let (name, data) = {
            let name = start.try_into().expect("Messages are at most 64KiB");
            let mut b = builder.builder(start);
            record.rname.build_into_message(b.delegate())?;
            b.append_bytes(&record.rtype.as_bytes())?;
            b.append_bytes(&record.rclass.as_bytes())?;
            b.append_bytes(&record.ttl.as_bytes())?;
            let size = b.context().size;
            SizePrefixed::new(&record.rdata)
                .build_into_message(b.delegate())?;
            let data =
                (size + 2).try_into().expect("Messages are at most 64KiB");
            b.commit();
            (name, data)
        };

        // Update the message state.
        match builder.context.state {
            ref mut state @ MessageState::Answers => {
                *state = MessageState::MidAnswer { name, data };
            }

            ref mut state @ MessageState::Authorities => {
                *state = MessageState::MidAuthority { name, data };
            }

            ref mut state @ MessageState::Additionals => {
                *state = MessageState::MidAdditional { name, data };
            }

            _ => unreachable!(),
        }

        Ok(Self {
            builder,
            name,
            data,
        })
    }

    /// Reconstruct a [`RecordBuilder`] from raw parts.
    ///
    /// # Safety
    ///
    /// `builder.message().contents[name..]` must represent a valid
    /// [`Record`] in the wire format.  `contents[data..]` must represent the
    /// record data (i.e. immediately after the record data size field).
    pub unsafe fn from_raw_parts(
        builder: MessageBuilder<'b>,
        name: u16,
        data: u16,
    ) -> Self {
        Self {
            builder,
            name,
            data,
        }
    }
}

//--- Inspection

impl<'b> RecordBuilder<'b> {
    /// The (unparsed) record name.
    pub fn rname(&self) -> &UnparsedName {
        let contents = &self.builder.message().contents;
        let contents =
            &contents[usize::from(self.name)..usize::from(self.data) - 10];
        <&UnparsedName>::parse_message_bytes(contents, self.name.into())
            .expect("The record was serialized correctly")
    }

    /// The record type.
    pub fn rtype(&self) -> RType {
        let contents = &self.builder.message().contents;
        let contents = &contents[usize::from(self.data) - 10..];
        RType::parse_bytes(&contents[0..2])
            .expect("The record was serialized correctly")
    }

    /// The record class.
    pub fn rclass(&self) -> RClass {
        let contents = &self.builder.message().contents;
        let contents = &contents[usize::from(self.data) - 10..];
        RClass::parse_bytes(&contents[2..4])
            .expect("The record was serialized correctly")
    }

    /// The TTL.
    pub fn ttl(&self) -> TTL {
        let contents = &self.builder.message().contents;
        let contents = &contents[usize::from(self.data) - 10..];
        TTL::parse_bytes(&contents[4..8])
            .expect("The record was serialized correctly")
    }

    /// The record data built thus far.
    pub fn rdata(&self) -> &[u8] {
        &self.builder.message().contents[usize::from(self.data)..]
    }

    /// Deconstruct this [`RecordBuilder`] into its raw parts.
    pub fn into_raw_parts(self) -> (MessageBuilder<'b>, u16, u16) {
        let (name, data) = (self.name, self.data);
        let this = ManuallyDrop::new(self);
        let this = (&*this) as *const Self;
        // SAFETY: 'this' is a valid object that can be moved out of.
        let builder = unsafe { ptr::read(ptr::addr_of!((*this).builder)) };
        (builder, name, data)
    }
}

//--- Interaction

impl<'b> RecordBuilder<'b> {
    /// Commit this record.
    ///
    /// The builder will be consumed, and the record will be committed so that
    /// it can no longer be removed.
    pub fn commit(self) -> BuildCommitted {
        self.builder
            .context
            .state
            .commit(&mut self.builder.message.header.counts);

        // NOTE: The record data size will be fixed on drop.
        BuildCommitted
    }

    /// Stop building and remove this record.
    ///
    /// The builder will be consumed, and the record will be removed.
    pub fn cancel(self) {
        self.builder.context.size = self.name.into();
        self.builder.context.state.cancel();

        // NOTE: The drop glue is a no-op.
    }

    /// Delegate further building of the record data to a new [`Builder`].
    pub fn delegate(&mut self) -> Builder<'_> {
        let offset = self.builder.context.size;
        self.builder.builder(offset)
    }
}

//--- Drop

impl Drop for RecordBuilder<'_> {
    fn drop(&mut self) {
        // Fixup the record data size so the overall message builder is valid.
        let size = self.builder.context.size as u16;
        if self.data <= size {
            // SAFETY: Only the record data size field is being modified.
            let message = unsafe { self.builder.message_mut() };
            let data = usize::from(self.data);
            let size = size - self.data;
            message.contents[data - 2..data]
                .copy_from_slice(&size.to_be_bytes());
        }
    }
}
