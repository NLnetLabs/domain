
use core::mem;
use core::marker::PhantomData;
use unwrap::unwrap;
use super::header::{Header, HeaderCounts, HeaderSection};
use super::iana::{Rcode, Rtype};
use super::message_builder::{
    AdditionalBuilder, AnswerBuilder, RecordSectionBuilder
};
use super::name::{ParsedDname, ToDname};
use super::octets::{
    OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use super::opt::{Opt, OptRecord};
use super::question::Question;
use super::rdata::{ParseRecordData, RecordData};
use super::record::{ParsedRecord, Record};
use crate::rdata::rfc1035::Cname;


//------------ Message -------------------------------------------------------

#[derive(Clone, Copy)]
pub struct Message<Octets> {
    octets: Octets
}

/// # Creation and Conversion
///
impl<Octets> Message<Octets> {
    /// Creates a message from a bytes value.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns `Ok`, the message may still be broken with other
    /// methods returning `Err(_)`.
    pub fn from_octets(octets: Octets) -> Result<Self, ShortBuf>
    where Octets: AsRef<[u8]> {
        if octets.as_ref().len() < mem::size_of::<HeaderSection>() {
            Err(ShortBuf)
        }
        else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a message from a bytes value without checking.
    pub(super) unsafe fn from_octets_unchecked(octets: Octets) -> Self {
        Message { octets }
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_octets(&self) -> &Octets {
        &self.octets
    }

    /// Converts the message into the underlying octets sequence.
    pub fn into_octets(self) -> Octets {
        self.octets
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8]
    where Octets: AsRef<[u8]> {
        self.octets.as_ref()
    }

    /// Returns a mutable reference to the underlying octets.
    ///
    /// Because it is possible to utterly break the message using this slice,
    /// the method is private.
    fn as_slice_mut(&mut self) -> &mut [u8]
    where Octets: AsMut<[u8]> {
        self.octets.as_mut()
    }

    pub fn as_ref_message(&self) -> Message<&[u8]>
    where Octets: AsRef<[u8]> {
        unsafe { Message::from_octets_unchecked(self.octets.as_ref()) }
    }
}


/// # Header Section
///
impl<Octets: AsRef<[u8]>> Message<Octets> {
    /// Returns a the message header.
    pub fn header(&self) -> Header {
        *Header::for_message_slice(self.as_slice())
    }
    
    /// Returns a mutable reference to the message header.
    pub fn header_mut(&mut self) -> &mut Header
    where Octets: AsMut<[u8]> {
        Header::for_message_slice_mut(self.as_slice_mut())
    }

    /// Returns the header counts of the message.
    pub fn header_counts(&self) -> HeaderCounts {
        *HeaderCounts::for_message_slice(self.as_slice())
    }

    /// Returns the entire header section.
    pub fn header_section(&self) -> HeaderSection {
        *HeaderSection::for_message_slice(&self.as_slice())
    }

    /// Returns whether the rcode is NoError.
    pub fn no_error(&self) -> bool {
        self.header().rcode() == Rcode::NoError
    }

    /// Returns whether the rcode is one of the error values.
    pub fn is_error(&self) -> bool {
        self.header().rcode() != Rcode::NoError
    }
}

/// # Access to Sections
///
impl<Octets> Message<Octets>
where for<'a> &'a Octets: OctetsRef {
    /// Returns the question section.
    pub fn question(&self) -> QuestionSection<&Octets> {
        QuestionSection::new(&self.octets)
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection<&Octets> {
        self.question()
    }

    /// Returns the answer section.
    pub fn answer(&self) -> Result<RecordSection<&Octets>, ParseError> {
        Ok(self.question().next_section()?)
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(&self) -> Result<RecordSection<&Octets>, ParseError> {
        self.answer()
    }

    /// Returns the authority section.
    pub fn authority(&self) -> Result<RecordSection<&Octets>, ParseError> {
        Ok(self.answer()?.next_section()?.unwrap())
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> Result<RecordSection<&Octets>, ParseError> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(&self) -> Result<RecordSection<&Octets>, ParseError> {
        Ok(self.authority()?.next_section()?.unwrap())
    }

    /// Returns all four sections in one fell swoop.
    #[allow(clippy::type_complexity)]
    pub fn sections(
        &self
    ) -> Result<
        (
            QuestionSection<&Octets>, RecordSection<&Octets>,
            RecordSection<&Octets>, RecordSection<&Octets>
        ),
        ParseError
    > {
        let question = self.question();
        let answer = question.clone().next_section()?;
        let authority = answer.clone().next_section()?.unwrap();
        let additional = authority.clone().next_section()?.unwrap();
        Ok((question, answer, authority, additional))
    }

    pub fn iter(&self) -> MessageIter<&Octets> {
        self.into_iter()
    }
}


/// # Helpers for Common Tasks
impl<Octets> Message<Octets>
where
    Octets: AsRef<[u8]>,
    for<'a> &'a Octets: OctetsRef
{
    /// Returns whether this is the answer to some other message.
    ///
    /// The method checks whether the ID fields of the headers are the same,
    /// whether the QR flag is set in this message, and whether the questions
    /// are the same.
    pub fn is_answer<Other>(&self, query: &Message<Other>) -> bool
    where
        Other: AsRef<[u8]>,
        for <'o> &'o Other: OctetsRef
    {
        if !self.header().qr()
            || self.header().id() != query.header().id()
            || self.header_counts().qdcount()
                != query.header_counts().qdcount()
        {
            false
        }
        else { self.question() == query.question() }
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(&self) -> Option<Question<ParsedDname<&Octets>>> {
        match self.question().next() {
            None | Some(Err(..)) => None,
            Some(Ok(question)) => Some(question)
        }
    }

    /// Returns the query type of the first question, if any.
    pub fn qtype(&self) -> Option<Rtype> {
        self.first_question().map(|x| x.qtype())
    }

    /// Returns whether the message contains answers of a given type.
    pub fn contains_answer<'s, Data>(&'s self) -> bool
    where Data: ParseRecordData<&'s Octets> {
        let answer = match self.answer() {
            Ok(answer) => answer,
            Err(..) => return false
        };
        answer.limit_to::<Data>().next().is_some()
    }

    /// Resolves the canonical name of the answer.
    ///
    /// Returns `None` if either the message doesn’t have a question or there
    /// was a parse error. Otherwise starts with the question’s name,
    /// follows any CNAME trail and returns the name answers should be for.
    pub fn canonical_name(&self) -> Option<ParsedDname<&Octets>> {
        let question = match self.first_question() {
            None => return None,
            Some(question) => question
        };
        let mut name = question.into_qname();
        let answer = match self.answer() {
            Ok(answer) => answer.limit_to::<Cname<_>>(),
            Err(_) => return None,
        };

        loop {
            let mut found = false;
            for record in answer.clone() {
                let record = match record {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                if *record.owner() == name {
                    name = *record.data().cname();
                    found = true;
                    break;
                }
            }
            if !found {
                break
            }
        }
        
        Some(name)
    }

    /// Get the OPT record from the message, if there is one.
    pub fn opt(&self) -> Option<OptRecord<<&Octets as OctetsRef>::Range>> {
        match self.additional() {
            Ok(section) => match section.limit_to::<Opt<_>>().next() {
                Some(Ok(rr)) => Some(OptRecord::from(rr)),
                _ => None,
            }
            Err(_) => None,
        }
    }

    /// Returns the last additional record from the message.
    ///
    /// The method tries to parse the last record of the additional section
    /// as the provided record type. If that succeeds, it returns that
    /// parsed record and removes it from the message.
    ///
    /// If the last record is of the wrong type or parsing fails, returns
    /// `None` and leaves the message untouched.
    pub fn get_last_additional<'s, Data: ParseRecordData<&'s Octets>>(
        &'s self
    ) -> Option<Record<ParsedDname<&'s Octets>, Data>> {
        let mut section = match self.additional() {
            Ok(section) => section,
            Err(_) => return None
        };
        loop {
            match section.count {
                Err(_) => return None,
                Ok(0) => return None,
                Ok(1) => break,
                _ => { }
            }
            let _ = section.next();
        }
        let record = match ParsedRecord::parse(&mut section.parser) {
            Ok(record) => record,
            Err(_) => return None,
        };
        let record = match record.into_record() {
            Ok(Some(record)) => record,
            _ => return None
        };
        Some(record)
    }

    /// Drops the last additional record from the message.
    ///
    /// Does so by decreasing the ’arcount.’ Does, however, not change the
    /// underlying octet sequence.
    pub fn remove_last_additional(&mut self)
    where Octets: AsMut<[u8]> {
        HeaderCounts::for_message_slice_mut(self.octets.as_mut()).dec_arcount();
    }

    /// Copy records from message into the target message builder.
    ///
    /// The method uses `op` to process records from all record sections
    /// before inserting, caller can use this closure to filter or manipulate
    /// records before inserting.
    pub fn copy_records<'s, N, D, R, F, T, O>(
        &'s self,
        target: T,
        mut op: F
    ) -> Result<AdditionalBuilder<O>, ParseError>
    where
        for <'a> &'a Octets: OctetsRef,
        N: ToDname + 's,
        D: RecordData + 's,
        R: Into<Record<N, D>> + 's,
        F: FnMut(ParsedRecord<&'s Octets>) -> Option<R>,
        T: Into<AnswerBuilder<O>>,
        O: OctetsBuilder
    {
        let mut source = self.answer()?;
        let mut target = target.into();
        while let Some(rr) = source.next() {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr)?;
            }
        }

        let mut source = unwrap!(source.next_section()?);
        let mut target = target.authority();
        while let Some(rr) = source.next() {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr)?;
            }
        }

        let source = unwrap!(source.next_section()?);
        let mut target = target.additional();
        for rr in source {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr)?;
            }
        }

        Ok(target)
    }
}


//--- IntoIterator

impl<'a, Octets> IntoIterator for &'a Message<Octets>
where for<'s> &'s Octets: OctetsRef {
    type Item = Result<(ParsedRecord<&'a Octets>, Section), ParseError>;
    type IntoIter = MessageIter<&'a Octets>;

    fn into_iter(self) -> Self::IntoIter {
        MessageIter { inner: self.answer().ok() }
    }
}


//------------ QuestionSection ----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct QuestionSection<Ref> {
    /// The parser for generating the questions.
    parser: Parser<Ref>,

    /// The remaining number of questions.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParseError>
}

impl<Ref: OctetsRef> QuestionSection<Ref> {
    /// Creates a new question section from the message octets.
    fn new(octets: Ref) -> Self {
        let mut parser = Parser::from_ref(octets);
        unwrap!(parser.advance(mem::size_of::<HeaderSection>()));
        QuestionSection {
            count: Ok(HeaderCounts::for_message_slice(
                parser.as_slice()).qdcount()
            ),
            parser,
        }
    }

    /// Returns the current position relative to the beginning of the message.
    pub fn pos(&self) -> usize {
        self.parser.pos()
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into the
    /// first [`RecordSection`].
    ///
    /// [`RecordSection`]: struct.RecordSection.html
    pub fn answer(mut self) -> Result<RecordSection<Ref>, ParseError> {
        while self.next().is_some() { }
        let _ = self.count?;
        Ok(RecordSection::new(self.parser, Section::first()))
    }

    pub fn next_section(self) -> Result<RecordSection<Ref>, ParseError> {
        self.answer()
    }
}


//--- Iterator

impl<Ref: OctetsRef> Iterator for QuestionSection<Ref> {
    type Item = Result<Question<ParsedDname<Ref>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match Question::parse(&mut self.parser) {
                    Ok(question) => {
                        self.count = Ok(count - 1);
                        Some(Ok(question))
                    }
                    Err(err) => {
                        self.count = Err(err);
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//--- PartialEq

impl<Ref, Other> PartialEq<QuestionSection<Other>> for QuestionSection<Ref>
where Ref: OctetsRef, Other: OctetsRef {
    fn eq(&self, other: &QuestionSection<Other>) -> bool {
        let mut me = *self;
        let mut other = *other;
        loop {
            match (me.next(), other.next()) {
                (Some(Ok(left)), Some(Ok(right))) => {
                    if left != right {
                        return false
                    }
                }
                (None, None) => return true,
                _ => return false
            }
        }
    }
}


//------------ Section -------------------------------------------------------

/// A helper type enumerating which section a `RecordSection` is currently in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum Section {
    Answer,
    Authority,
    Additional
}


impl Section {
    /// Returns the first section.
    pub fn first() -> Self { Section::Answer }

    /// Returns the correct record count for this section.
    fn count(self, counts: HeaderCounts) -> u16 {
        match self {
            Section::Answer => counts.ancount(),
            Section::Authority => counts.nscount(),
            Section::Additional => counts.arcount()
        }
    }

    /// Returns the value for the following section or `None` if this is last.
    pub(crate) fn next_section(self) -> Option<Self> {
        match self {
            Section::Answer => Some(Section::Authority),
            Section::Authority => Some(Section::Additional),
            Section::Additional => None
        }
    }
}


//------------ RecordSection -----------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RecordSection<Ref> {
    /// The parser for generating the records.
    parser: Parser<Ref>,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of records.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParseError>
}

impl<Ref: OctetsRef> RecordSection<Ref> {
    /// Creates a new section from a parser.
    ///
    /// The parser must be positioned at the beginning of this section.
    fn new(parser: Parser<Ref>, section: Section) -> Self {
        RecordSection {
            count: Ok(section.count(
                *HeaderCounts::for_message_slice(parser.as_slice())
            )),
            section,
            parser,
        }
    }

    /// Returns the current position relative to the beginning of the message.
    pub fn pos(&self) -> usize {
        self.parser.pos()
    }

    /// Trades `self` in for an iterator limited to a concrete record type.
    ///
    /// The record type is given through its record data type. Since the data
    /// is being parsed, this type must implement [`ParseRecordData`]. For
    /// record data types that are generic over domain name types, this is
    /// normally achieved by giving them a [`ParsedDname`]. As a convenience,
    /// type aliases for all the fundamental record data types exist in the
    /// [domain::rdata::parsed] module.
    ///
    /// The returned limited iterator will continue at the current position
    /// of `self`. It will *not* start from the beginning of the section.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    /// [`ParsedDname`]: ../name/struct.ParsedDname.html
    /// [domain::rdata::parsed]: ../../rdata/parsed/index.html
    pub fn limit_to<Data: ParseRecordData<Ref>>(
        self
    ) -> RecordIter<Ref, Data> {
        RecordIter::new(self)
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unsable
    /// now.
    pub fn next_section(mut self) -> Result<Option<Self>, ParseError> {
        let section = match self.section.next_section() {
            Some(section) => section,
            None => return Ok(None)
        };
        while self.skip_next().is_some() { }
        let _ = self.count?;
        Ok(Some(RecordSection::new(self.parser, section)))
    }

    /// Skip the next record.
    fn skip_next(&mut self) -> Option<Result<(), ParseError>> {
        match self.count {
            Ok(count) if count > 0 => {
                match ParsedRecord::skip(&mut self.parser) {
                    Ok(_) => {
                        self.count = Ok(count - 1);
                        Some(Ok(()))
                    }
                    Err(err) => {
                        self.count = Err(err);
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//--- Iterator

impl<Ref: OctetsRef> Iterator for RecordSection<Ref> {
    type Item = Result<ParsedRecord<Ref>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match ParsedRecord::parse(&mut self.parser) {
                    Ok(record) => {
                        self.count = Ok(count - 1);
                        Some(Ok(record))
                    }
                    Err(err) => {
                        self.count = Err(err);
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//------------ MessageIter ---------------------------------------------------

pub struct MessageIter<Ref> {
    inner: Option<RecordSection<Ref>>,
}

impl<Ref: OctetsRef> Iterator for MessageIter<Ref> {
    type Item = Result<(ParsedRecord<Ref>, Section), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get next record from current section
        match self.inner {
            Some(ref mut inner) => {
                let item = inner.next();
                if let Some(item) = item {
                    return Some(item.map(|item| (item, inner.section)));
                }
            },
            None => return None,
        }

        // Advance to next section if possible, and retry
        let inner = self.inner.take()?;
        match inner.next_section() {
            Ok(section) => {
                self.inner = section;
                self.next()
            }
            Err(err) => Some(Err(err))
        }
    }
}


//------------ RecordIter ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RecordIter<Ref, Data> {
    section: RecordSection<Ref>,
    marker: PhantomData<Data>
}

impl<Ref: OctetsRef, Data: ParseRecordData<Ref>> RecordIter<Ref, Data> {
    /// Creates a new record iterator.
    fn new(section: RecordSection<Ref>) -> Self {
        RecordIter { section, marker: PhantomData }
    }

    /// Trades the iterator for the full iterator.
    ///
    /// The returned iterator will continue right after the last record
    /// previously returned.
    pub fn unwrap(self) -> RecordSection<Ref> {
        self.section
    }

    /// Proceeds to the next section if there is one.
    pub fn next_section(
        self
    ) -> Result<Option<RecordSection<Ref>>, ParseError> {
        self.section.next_section()
    }
}


//--- Iterator

impl<Ref, Data> Iterator for RecordIter<Ref, Data>
where Ref: OctetsRef, Data: ParseRecordData<Ref> {
    type Item = Result<Record<ParsedDname<Ref>, Data>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = match self.section.next() {
                Some(Ok(record)) => record,
                Some(Err(err)) => return Some(Err(err)),
                None => return None,
            };
            match record.into_record() {
                Ok(Some(record)) => return Some(Ok(record)),
                Err(err) => return Some(Err(err)),
                Ok(None) => { }
            }
        }
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use unwrap::unwrap;
    use crate::base::message_builder::MessageBuilder;
    use crate::base::name::Dname;
    use crate::rdata::{Ns, AllRecordData};
    use super::*;

    // Helper for test cases
    fn get_test_message() -> Message<Vec<u8>> {
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.answer();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("foo.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        let mut msg = msg.authority();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("bar.example.com.")),
            86000,
            Ns::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        msg.into_message()
    }

    #[test]
    fn short_message() {
        assert!(Message::from_octets(&[0u8; 11]).is_err());
        assert!(Message::from_octets(&[0u8; 12]).is_ok());
    }

    #[test]
    fn canonical_name() {
        // Message without CNAMEs.
        let mut msg = MessageBuilder::new_vec().question();
        unwrap!(
            msg.push((unwrap!(Dname::vec_from_str("example.com.")), Rtype::A))
        );
        let msg_ref = msg.as_message();
        assert_eq!(
            unwrap!(Dname::vec_from_str("example.com.")),
            unwrap!(msg_ref.canonical_name())
        );

        // Message with CNAMEs.
        let mut msg = msg.answer();
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("bar.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("baz.example.com.")))
        )));
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("foo.example.com.")))
        )));
        unwrap!(msg.push((
            unwrap!(Dname::vec_from_str("foo.example.com.")),
            86000,
            Cname::new(unwrap!(Dname::vec_from_str("bar.example.com.")))
        )));
        let msg_ref = msg.as_message();
        assert_eq!(
            unwrap!(Dname::vec_from_str("baz.example.com.")),
            unwrap!(msg_ref.canonical_name())
        );
    }

    #[test]
    fn message_iterator() {
        let msg = get_test_message();
        let mut iter = msg.iter();

        // Check that it returns a record from first section
        let (_rr, section) = unwrap!(unwrap!(iter.next()));
        assert_eq!(Section::Answer, section);

        // Check that it advances to next section
        let (_rr, section) = unwrap!(unwrap!(iter.next()));
        assert_eq!(Section::Authority, section);
    }

    #[test]
    fn copy_records() {
        let msg = get_test_message();
        let msg = msg.as_ref_message();
        let target = MessageBuilder::new_vec().question();
        let res = msg.copy_records(target.answer(), |rr| {
            if let Ok(Some(rr)) =
                    rr.into_record::<AllRecordData<_, ParsedDname<_>>>() {
                if rr.rtype() == Rtype::Cname {
                    return Some(rr);
                }
            }
            return None;
        });

        assert!(res.is_ok());
        if let Ok(target) = res {
            let msg = target.into_message();
            assert_eq!(1, msg.header_counts().ancount());
            assert_eq!(0, msg.header_counts().arcount());
        }
    }
}

