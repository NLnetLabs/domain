//! DNS request messages.

use crate::new_base::{
    name::UnparsedName,
    parse::SplitMessageBytes,
    wire::{AsBytes, ParseError, SizePrefixed, U16},
    Message, Question, RType, Record, UnparsedRecordData,
};

/// A DNS request message.
pub struct RequestMessage<'b> {
    /// The underlying [`Message`].
    pub message: &'b Message,

    /// Cached indices of the initial questions and records.
    ///
    /// For questions, the indices span the whole question.
    ///
    /// For records, the indices span the record header (the record name,
    /// type, class, TTL, and data size).  The record data can be located
    /// using the header very easily.
    indices: [(u16, u16); 8],

    /// Cached offset of the EDNS record.
    edns_offset: u16,

    /// Cached indices of the EDNS options in the message.
    edns_indices: [(u16, u16); 8],

    /// The number of components before the end of every section.
    section_offsets: [u16; 4],
}

//--- Construction

impl<'b> RequestMessage<'b> {
    /// Wrap a raw [`Message`] into a [`RequestMessage`].
    ///
    /// This will iterate through the message, pre-filling some caches for
    /// efficient access in the future.
    pub fn new(message: &'b Message) -> Result<Self, ParseError> {
        let mut indices = [(0u16, 0u16); 8];
        let mut edns_indices = [(0u16, 0u16); 8];

        // DNS messages are 64KiB at the largest.
        let _ = u16::try_from(message.as_bytes().len())
            .map_err(|_| ParseError)?;

        // The offset (in bytes) into the message contents.
        let mut offset = 0;

        // The section counts from the message.
        let counts = &message.header.counts.as_array();

        // The offset of each section, in components.
        let mut section_offsets = [0u16; 4];

        // First, parse all questions.
        for i in 0..counts[0].get() {
            let (_question, rest) =
                Question::<&'b UnparsedName>::split_message_bytes(
                    &message.contents,
                    offset,
                )?;

            if let Some(indices) = indices.get_mut(i as usize) {
                *indices = (offset as u16, rest as u16);
            }

            offset = rest;
        }

        // The offset (in components) of this section in the message.
        let mut section_offset = counts[0].get();
        section_offsets[0] = section_offset;

        // The offset of the EDNS record, if any.
        let mut edns_offset = u16::MAX;

        // Parse all records.
        for section in 1..4 {
            for i in 0..counts[section].get() {
                let (record, rest) = Record::<
                    &'b UnparsedName,
                    &'b UnparsedRecordData,
                >::split_message_bytes(
                    &message.contents, offset
                )?;

                let component = (section_offset + i) as usize;
                if let Some(indices) = indices.get_mut(component) {
                    let data = offset + record.rname.len() + 10;
                    *indices = (offset as u16, data as u16);
                }

                if record.rtype == RType::OPT {
                    if edns_offset != u16::MAX {
                        // A DNS message can only contain one EDNS record.
                        return Err(ParseError);
                    } else {
                        edns_offset = offset as u16;
                    }
                }

                offset = rest;
            }

            section_offset += counts[section].get();
            section_offsets[section] = section_offset;
        }

        // Parse EDNS options.
        if edns_offset < u16::MAX {
            // Extract the EDNS record data.
            let offset = edns_offset as usize + 9;
            let (&size, mut offset) =
                <&U16>::split_message_bytes(&message.contents, offset)?;

            let contents = message
                .contents
                .get(..offset + size.get() as usize)
                .ok_or(ParseError)?;

            // Parse through it.
            let mut indices = edns_indices.iter_mut();
            while offset < contents.len() {
                let (_type, rest) =
                    <&U16>::split_message_bytes(contents, offset)?;
                let (_data, rest) =
                    <SizePrefixed<&[u8]>>::split_message_bytes(
                        contents, rest,
                    )?;

                if let Some(indices) = indices.next() {
                    *indices = (offset as u16, rest as u16);
                }

                offset = rest;
            }
        }

        Ok(Self {
            message,
            indices,
            edns_offset,
            edns_indices,
            section_offsets,
        })
    }
}
