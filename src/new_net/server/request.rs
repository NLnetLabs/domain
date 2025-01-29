//! DNS request messages.

use core::{iter::FusedIterator, marker::PhantomData, ops::Range};

use crate::{
    new_base::{
        name::{Name, UnparsedName},
        parse::{ParseMessageBytes, SplitMessageBytes},
        wire::{AsBytes, ParseBytes, ParseError, SizePrefixed, U16},
        Message, ParseRecordData, QClass, QType, Question, RClass, RType,
        Record, SectionCounts, UnparsedRecordData, TTL,
    },
    new_edns::{EdnsOption, EdnsRecord},
    new_rdata::EdnsOptionsIter,
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
                let (question, rest) =
                    Question::<&UnparsedName>::split_message_bytes(
                        contents, offset,
                    )?;

                if let Some(indices) = indices.next() {
                    let fields = offset + question.qname.len();
                    *indices = offset as u16..fields as u16;
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

                if let Some(indices) = indices.next() {
                    let fields = offset + record.rname.len();
                    *indices = offset as u16..fields as u16;
                }

                if section == 3 && record.rtype == RType::OPT {
                    if edns_range.is_some() {
                        // A DNS message can only contain one EDNS record.
                        return Err(ParseError);
                    }

                    *edns_range = Some(offset as u16..rest as u16);
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
            let mut offset = range.start as usize + 11;

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

//--- Internals

impl<'b> RequestMessage<'b> {
    /// The section counts.
    fn counts(&self) -> &'b SectionCounts {
        &self.message.header.counts
    }
}

//--- Inspection

impl<'b> RequestMessage<'b> {
    /// The sole question in the message.
    ///
    /// # Name Compression
    ///
    /// Due to the restrictions around compressed domain names (in order to
    /// prevent attackers from crafting compression pointer loops), it is
    /// guaranteed that the first QNAME in the message is uncompressed.
    ///
    /// # Errors
    ///
    /// Fails if there are zero or more than one question in the message.
    pub fn sole_question(&self) -> Result<Question<&'b Name>, ParseError> {
        if self.message.header.counts.questions.get() != 1 {
            return Err(ParseError);
        }

        // SAFETY: 'RequestMessage' is pre-validated.
        let range = self.questions.1[0].clone();
        let range = range.start as usize..range.end as usize;
        let qname = &self.message.contents[range.clone()];
        let qname = unsafe { Name::from_bytes_unchecked(qname) };
        let fields = &self.message.contents[range.end..];
        let qtype = QType::parse_bytes(&fields[0..2]).unwrap();
        let qclass = QClass::parse_bytes(&fields[2..4]).unwrap();

        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    /// The EDNS record in the message, if any.
    pub fn edns_record(&self) -> Option<EdnsRecord<'b>> {
        if self.edns.0.is_empty() {
            return None;
        }

        let range = self.edns.0.clone();
        let contents = &self.message.contents[..range.end as usize];
        EdnsRecord::parse_message_bytes(contents, range.start as usize)
            .map(Some)
            .expect("'RequestMessage' only holds well-formed EDNS records")
    }

    /// The questions in the message.
    ///
    /// # Name Compression
    ///
    /// The returned questions use [`UnparsedName`] for the QNAMEs.  These can
    /// be resolved against the original message to determine the whole domain
    /// name, if necessary.  Note that decompression can fail.
    pub fn questions(&self) -> RequestQuestions<'_, 'b> {
        let contents = self.questions.0.clone();
        RequestQuestions {
            message: self,
            cache: self.questions.1.iter(),
            contents: contents.start as usize..contents.end as usize,
            indices: 0..self.counts().questions.get(),
        }
    }

    /// The answer records in the message.
    ///
    /// # Name Compression
    ///
    /// The returned records use [`UnparsedName`] for the RNAMEs.  These can
    /// be resolved against the original message to determine the whole domain
    /// name, if necessary.  Note that decompression can fail.
    ///
    /// # Record Data
    ///
    /// The caller can select an appropriate record data type to use.  In most
    /// cases, [`RecordData`](crate::new_rdata::RecordData) is appropriate; if
    /// many records will be skipped, however, [`UnparsedRecordData`] might be
    /// preferable.
    pub fn answers<D>(&self) -> RequestRecords<'_, 'b, D>
    where
        D: ParseRecordData<'b>,
    {
        let contents = self.answers.0.clone();
        RequestRecords {
            message: self,
            cache: self.answers.1.iter(),
            contents: contents.start as usize..contents.end as usize,
            indices: 0..self.counts().answers.get(),
            _rdata: PhantomData,
        }
    }

    /// The authority records in the message.
    ///
    /// # Name Compression
    ///
    /// The returned records use [`UnparsedName`] for the RNAMEs.  These can
    /// be resolved against the original message to determine the whole domain
    /// name, if necessary.  Note that decompression can fail.
    ///
    /// # Record Data
    ///
    /// The caller can select an appropriate record data type to use.  In most
    /// cases, [`RecordData`](crate::new_rdata::RecordData) is appropriate; if
    /// many records will be skipped, however, [`UnparsedRecordData`] might be
    /// preferable.
    pub fn authorities<D>(&self) -> RequestRecords<'_, 'b, D>
    where
        D: ParseRecordData<'b>,
    {
        let contents = self.authorities.0.clone();
        RequestRecords {
            message: self,
            cache: self.authorities.1.iter(),
            contents: contents.start as usize..contents.end as usize,
            indices: 0..self.counts().authorities.get(),
            _rdata: PhantomData,
        }
    }

    /// The additional records in the message.
    ///
    /// # Name Compression
    ///
    /// The returned records use [`UnparsedName`] for the RNAMEs.  These can
    /// be resolved against the original message to determine the whole domain
    /// name, if necessary.  Note that decompression can fail.
    ///
    /// # Record Data
    ///
    /// The caller can select an appropriate record data type to use.  In most
    /// cases, [`RecordData`](crate::new_rdata::RecordData) is appropriate; if
    /// many records will be skipped, however, [`UnparsedRecordData`] might be
    /// preferable.
    pub fn additional<D>(&self) -> RequestRecords<'_, 'b, D>
    where
        D: ParseRecordData<'b>,
    {
        let contents = self.additional.0.clone();
        RequestRecords {
            message: self,
            cache: self.additional.1.iter(),
            contents: contents.start as usize..contents.end as usize,
            indices: 0..self.counts().additional.get(),
            _rdata: PhantomData,
        }
    }

    /// The EDNS options in the message.
    pub fn edns_options(&self) -> RequestEdnsOptions<'b> {
        let start = self.edns.0.start as usize + 11;
        let end = self.edns.0.end as usize;
        let options = &self.message.contents[start..end];
        RequestEdnsOptions {
            inner: EdnsOptionsIter::new(options),
            indices: 0..self.edns.1,
        }
    }
}

//----------- RequestQuestions -----------------------------------------------

/// The questions in a [`RequestMessage`].
#[derive(Clone)]
pub struct RequestQuestions<'r, 'b> {
    /// The underlying request message.
    message: &'r RequestMessage<'b>,

    /// The cached question ranges.
    cache: core::slice::Iter<'r, Range<u16>>,

    /// The range of message contents to parse.
    contents: Range<usize>,

    /// The range of record indices left.
    indices: Range<u16>,
}

impl<'b> Iterator for RequestQuestions<'_, 'b> {
    type Item = Question<&'b UnparsedName>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try loading a cached question.
        if let Some(range) = self.cache.next().cloned() {
            if range.is_empty() {
                // There are no more questions, stop.
                self.cache = Default::default();
                self.contents.start = self.contents.end;
                return None;
            }

            // SAFETY: 'RequestMessage' is pre-validated.
            let range = range.start as usize..range.end as usize;
            let qname = &self.message.message.contents[range.clone()];
            let qname = unsafe { UnparsedName::from_bytes_unchecked(qname) };
            let fields = &self.message.message.contents[range.end..];
            let qtype = QType::parse_bytes(&fields[0..2]).unwrap();
            let qclass = QClass::parse_bytes(&fields[2..4]).unwrap();

            self.indices.start += 1;
            return Some(Question {
                qname,
                qtype,
                qclass,
            });
        }

        let _ = self.indices.next()?;
        let contents = &self.message.message.contents[..self.contents.end];
        let (question, rest) =
            Question::split_message_bytes(contents, self.contents.start)
                .expect("'RequestMessage' only contains valid questions");

        self.contents.start = rest;
        Some(question)
    }
}

impl ExactSizeIterator for RequestQuestions<'_, '_> {
    fn len(&self) -> usize {
        self.indices.len()
    }
}

impl FusedIterator for RequestQuestions<'_, '_> {}

//----------- RequestRecords -------------------------------------------------

/// The records in a section of a [`RequestMessage`].
#[derive(Clone)]
pub struct RequestRecords<'r, 'b, D> {
    /// The underlying request message.
    message: &'r RequestMessage<'b>,

    /// The cached record ranges.
    cache: core::slice::Iter<'r, Range<u16>>,

    /// The range of message contents to parse.
    contents: Range<usize>,

    /// The range of record indices left.
    indices: Range<u16>,

    /// A representation of the record data held.
    _rdata: PhantomData<&'r [D]>,
}

impl<'b, D> Iterator for RequestRecords<'_, 'b, D>
where
    D: ParseRecordData<'b>,
{
    type Item = Result<Record<&'b UnparsedName, D>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try loading a cached record.
        if let Some(range) = self.cache.next().cloned() {
            if range.is_empty() {
                // There are no more records, stop.
                self.cache = Default::default();
                self.contents.start = self.contents.end;
                return None;
            }

            // SAFETY: 'RequestMessage' is pre-validated.
            let range = range.start as usize..range.end as usize;
            let rname = &self.message.message.contents[range.clone()];
            let rname = unsafe { UnparsedName::from_bytes_unchecked(rname) };
            let fields = &self.message.message.contents[range.end..];
            let rtype = RType::parse_bytes(&fields[0..2]).unwrap();
            let rclass = RClass::parse_bytes(&fields[2..4]).unwrap();
            let ttl = TTL::parse_bytes(&fields[4..8]).unwrap();
            let size = U16::parse_bytes(&fields[8..10]).unwrap();
            let rdata_end = range.end + 10 + size.get() as usize;
            let rdata = &self.message.message.contents[..rdata_end];
            let rdata =
                match D::parse_record_data(rdata, range.end + 10, rtype) {
                    Ok(rdata) => rdata,
                    Err(err) => return Some(Err(err)),
                };

            self.indices.start += 1;
            return Some(Ok(Record {
                rname,
                rtype,
                rclass,
                ttl,
                rdata,
            }));
        }

        let _ = self.indices.next()?;
        let contents = &self.message.message.contents[..self.contents.end];
        let (record, rest) = match Record::split_message_bytes(
            contents,
            self.contents.start,
        ) {
            Ok((record, rest)) => (record, rest),
            Err(err) => return Some(Err(err)),
        };

        self.contents.start = rest;
        Some(Ok(record))
    }
}

impl<'b, D> ExactSizeIterator for RequestRecords<'_, 'b, D>
where
    D: ParseRecordData<'b>,
{
    fn len(&self) -> usize {
        self.indices.len()
    }
}

impl<'b, D> FusedIterator for RequestRecords<'_, 'b, D> where
    D: ParseRecordData<'b>
{
}

//----------- RequestEdnsOptions ---------------------------------------------

/// The EDNS options in a [`RequestMessage`].
#[derive(Clone)]
pub struct RequestEdnsOptions<'b> {
    /// The underlying iterator.
    inner: EdnsOptionsIter<'b>,

    /// The range of option indices left.
    indices: Range<u16>,
}

impl<'b> Iterator for RequestEdnsOptions<'b> {
    type Item = EdnsOption<'b>;

    fn next(&mut self) -> Option<Self::Item> {
        let _ = self.indices.next()?;
        self.inner.next().map(Result::unwrap)
    }
}

impl ExactSizeIterator for RequestEdnsOptions<'_> {
    fn len(&self) -> usize {
        self.indices.len()
    }
}

impl FusedIterator for RequestEdnsOptions<'_> {}
