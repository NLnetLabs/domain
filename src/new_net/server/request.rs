//! DNS request messages.

use core::ops::Range;

use crate::new_base::{
    name::UnparsedName,
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{AsBytes, ParseError, SizePrefixed, U16},
    Message, Question, RType, Record, UnparsedRecordData,
};

/// A DNS request message.
#[derive(Clone)]
pub struct RequestMessage<'b> {
    /// The underlying [`Message`].
    pub message: &'b Message,

    /// Cached offsets for the question section.
    questions: (Range<u16>, [Range<u16>; 1]),

    /// Cached offsets for the answer section.
    answers: (Range<u16>, [Range<u16>; 0]),

    /// Cached offsets for the authority section.
    authorities: (Range<u16>, [Range<u16>; 0]),

    /// Cached offsets for the additional section.
    additional: (Range<u16>, [Range<u16>; 2]),

    /// Cached offsets for the EDNS record.
    edns: (Range<u16>, u16, [Range<u16>; 4]),
}

//--- Construction

impl<'b> RequestMessage<'b> {
    /// Wrap a raw [`Message`] into a [`RequestMessage`].
    ///
    /// This will iterate through the message, pre-filling some caches for
    /// efficient access in the future.
    pub fn new(message: &'b Message) -> Result<Self, ParseError> {
        /// Parse the question section into cached offsets.
        fn parse_questions(
            contents: &[u8],
            range: &mut Range<u16>,
            number: u16,
            indices: &mut [Range<u16>],
        ) -> Result<(), ParseError> {
            let mut indices = indices.iter_mut();
            let mut offset = range.start as usize;

            for _ in 0..number {
                let (_question, rest) =
                    Question::<&UnparsedName>::split_message_bytes(
                        contents, offset,
                    )?;

                if let Some(indices) = indices.next() {
                    *indices = offset as u16..rest as u16;
                }

                offset = rest;
            }

            range.end = offset as u16;
            Ok(())
        }

        /// Parse a record section into cached offsets.
        fn parse_records(
            contents: &[u8],
            section: u8,
            range: &mut Range<u16>,
            number: u16,
            indices: &mut [Range<u16>],
            edns_range: &mut Option<Range<u16>>,
        ) -> Result<(), ParseError> {
            let mut indices = indices.iter_mut();
            let mut offset = range.start as usize;

            for _ in 0..number {
                let (record, rest) = Record::<
                    &UnparsedName,
                    &UnparsedRecordData,
                >::split_message_bytes(
                    contents, offset
                )?;
                let data = offset + record.rname.len() + 10;
                let range = offset as u16..data as u16;

                if let Some(indices) = indices.next() {
                    *indices = range.clone();
                }

                if section == 3 && record.rtype == RType::OPT {
                    if edns_range.is_some() {
                        // A DNS message can only contain one EDNS record.
                        return Err(ParseError);
                    }

                    *edns_range = Some(range);
                }

                offset = rest;
            }

            range.end = offset as u16;
            Ok(())
        }

        /// Parse the EDNS record into cached offsets.
        fn parse_edns(
            contents: &[u8],
            range: Range<u16>,
            number: &mut u16,
            indices: &mut [Range<u16>],
        ) -> Result<(), ParseError> {
            let mut indices = indices.iter_mut();
            let mut offset = range.start as usize;

            while offset < range.end as usize {
                let (_type, rest) =
                    <&U16>::split_message_bytes(contents, offset)?;
                let (_data, rest) =
                    <SizePrefixed<&[u8]>>::split_message_bytes(
                        contents, rest,
                    )?;

                *number += 1;

                if let Some(indices) = indices.next() {
                    *indices = offset as u16..rest as u16;
                }

                offset = rest;
            }

            Ok(())
        }

        // DNS messages are 64KiB at the largest.
        let _ = u16::try_from(message.as_bytes().len())
            .map_err(|_| ParseError)?;

        let mut this = Self {
            message,
            questions: Default::default(),
            answers: Default::default(),
            authorities: Default::default(),
            additional: Default::default(),
            edns: Default::default(),
        };

        let mut edns_range = None;

        parse_questions(
            &message.contents,
            &mut this.questions.0,
            message.header.counts.questions.get(),
            &mut this.questions.1,
        )?;

        this.answers.0 = this.questions.0.end..0;
        parse_records(
            &message.contents,
            1,
            &mut this.answers.0,
            message.header.counts.answers.get(),
            &mut this.answers.1,
            &mut edns_range,
        )?;

        this.authorities.0 = this.answers.0.end..0;
        parse_records(
            &message.contents,
            2,
            &mut this.authorities.0,
            message.header.counts.authorities.get(),
            &mut this.authorities.1,
            &mut edns_range,
        )?;

        this.additional.0 = this.authorities.0.end..0;
        parse_records(
            &message.contents,
            2,
            &mut this.additional.0,
            message.header.counts.additional.get(),
            &mut this.additional.1,
            &mut edns_range,
        )?;

        if let Some(edns_range) = edns_range {
            this.edns.0 = edns_range.clone();
            parse_edns(
                &message.contents,
                edns_range,
                &mut this.edns.1,
                &mut this.edns.2,
            )?;
        }

        Ok(this)
    }
}
