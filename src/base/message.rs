//! Accessing existing DNS messages.
//!
//! This module defines a number of types for processing the content of a DNS
//! message in wire format. Because many components of the message are of
//! varying length, this can only be done iteratively. The type [`Message`]
//! wraps an octets sequence containing a complete message. It provides access
//! to the four sections of the message via additional types.
//!
//! For details, see the [`Message`] type.
//!
//! [`Message`]: struct.Message.html

use super::dig_printer::DigPrinter;
use super::header::{Header, HeaderCounts, HeaderSection};
use super::iana::{Class, OptRcode, Rcode, Rtype};
use super::message_builder::{AdditionalBuilder, AnswerBuilder, PushError};
use super::name::ParsedName;
use super::opt::{Opt, OptRecord};
use super::question::Question;
use super::rdata::{ParseAnyRecordData, ParseRecordData};
use super::record::{ComposeRecord, ParsedRecord, Record};
use super::wire::{Composer, ParseError};
use crate::rdata::rfc1035::Cname;
use core::marker::PhantomData;
use core::{fmt, mem};
use octseq::{Octets, OctetsFrom, Parser};

//------------ Message -------------------------------------------------------

/// A DNS message.
///
/// This type wraps an octets sequence containing the complete wire-format DNS
/// message and allows access to the various components of the message.
///
/// You create a message by passing an octets sequence to the [`from_octets`]
/// associate function which does some basic sanity checks and, if they
/// succeed, returns a message for the sequence. All further parsing happens
/// lazily when you access more of the message. This means that a message is
/// not necessarily well-formatted and further parsing may fail later on.
///
/// Section 4 of [RFC 1035] defines DNS messages as being divded into five
/// sections named header, question, answer, authority, and additional.
///
/// The header section is of a fixed sized and can be accessed at any time
/// through the methods given under [Header Section]. Most likely, you will
/// be interested in the first part of the header which is
/// returned by the [`header`] method.  The second part of the header
/// section contains the number of entries in the following four sections
/// and is of less interest as there are more sophisticated ways of accessing
/// these sections. If you do care, you can get access through
/// [`header_counts`].
///
/// The meaning of the next four sections depends on the type of message as
/// described by the [opcode] field of the header. Since the most common
/// type is a query, the sections are named after their function in this type
/// and the following description will focus on it.
///
/// The question section contains what was asked of the DNS by a query. It
/// contains a number of questions that consist of a domain name, a record
/// type, and class. A query asks for all records of the given record type
/// that are owned by the domain name within the class. In queries, there will
/// be exactly one question. With other opcodes, there may be multiple
/// questions.
///
/// You can acquire an iterator over the questions through the [`question`]
/// method. It returns a [`QuestionSection`] value that is an iterator over
/// questions. Since a single question is such a common case, there is a
/// convenience method [`first_question`] that returns the first question
/// only.
///
/// The following three section all contain DNS resource records. In
/// queries, they are empty in a request and may or may not contain records
/// in a response. The *answer* section contains all the records that answer
/// the given question. The *authority* section contains records declaring
/// which name server provided authoritative information for the question,
/// and the *additional* section can contain records that the name server
/// thought might be useful for processing the question. For instance, if you
/// trying to find out the mail server of a domain by asking for MX records,
/// you likely also want the IP addresses for the server, so the name server
/// may include these right away and free of charge.
///
/// There are functions to access all three sections directly: [`answer`],
/// [`authority`], and [`additional`]. Each method returns a value of type
/// [RecordSection] which acts as an iterator over the records in the
/// section. Since there are no pointers to where the later sections start,
/// accessing them directly means iterating over the previous sections. This
/// is why it is more efficitent to call [`RecordSection::next_section`] to
/// progress to a later section. Alternatively, you can use the message’s
/// [`sections`] method that gives you all four sections at once with the
/// minimal amount of iterating necessary.
///
/// When iterating over the record section, you will receive values of type
/// [`ParsedRecord`], an intermediary type that only parsed the parts common
/// to all records. In order to access the data of the record, you will want
/// to convert it into a [`Record`] which is generic over the actual record
/// type data. This can be done via [`ParsedRecord::into_record`].
///
/// Alternatively, you can trade the record section for one that only returns
/// the types you are interested in via the [`RecordSection::limit_to`]
/// method. The iterator returned by that method will quietly skip over all
/// records that aren’t of the type you are interested in.
///
/// So, if you want to iterate over the MX records in the answer section, you
/// would do something like this:
///
/// ```
/// use domain::base::Message;
/// use domain::rdata::Mx;
///
/// # let octets = b"\0\0\0\0\0\0\0\0\0\0\0\0".as_slice();
/// let msg = Message::from_octets(octets).unwrap();
/// for record in msg.answer().unwrap().limit_to::<Mx<_>>() {
///     if let Ok(record) = record {
///         // Do something with the record ...
///     }
/// }
/// ```
///
/// The `limit_to` method takes the record type as a type argument. Many
/// record types, like [`Mx`], are generic over octet sequences but the
/// compiler generally can figure out the concrete type itself, so in most
/// cases you get away with the underscore there.
///
/// Note how the iterator doesn’t actually return records but results of
/// records and parse errors. This is because only now can it check whether
/// the record is actually properly formatted. An error signals that something
/// went wrong while parsing. If only the record data is broken, the message
/// remains useful and parsing can continue with the next record. If the
/// message is fully broken, the next iteration will return `None` to signal
/// that.
///
/// [`additional`]: #method.additional
/// [`answer`]: #method.answer
/// [`authority`]: #method.authority
/// [`first_question`]: #method.first_question
/// [`from_octets`]: #method.from_octets
/// [`header`]: #method.header
/// [`header_counts`]: #method.header_counts
/// [`question`]: #method.question
/// [`sections`]: #method.sections
/// [`Mx`]: ../../rdata/rfc1035/struct.Mx.html
/// [`ParsedRecord`]: ../record/struct.ParsedRecord.html
/// [`ParsedRecord::into_record`]: ../record/struct.ParsedRecord.html#method.into_record
/// [`QuestionSection`]: struct.QuestionSection.html
/// [`Record`]: ../record/struct.Record.html
/// [`RecordSection`]: struct.RecordSection.html
/// [`RecordSection::limit_to`]: ../struct.RecordSection.html#method.limit_to
/// [`RecordSection::next_section`]: ../struct.RecordSection.html#method.next_section
/// [Header Section]: #header-section
/// [rdata]: ../../rdata/index.html
/// [opcode]: ../iana/opcode/enum.Opcode.html
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Message<Octs: ?Sized> {
    octets: Octs,
}

/// # Creation and Conversion
///
impl<Octs> Message<Octs> {
    /// Creates a message from an octets sequence.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns ok, the message may still be broken with other
    /// methods returning errors later one.
    pub fn from_octets(octets: Octs) -> Result<Self, ShortMessage>
    where
        Octs: AsRef<[u8]>,
    {
        Message::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a message from octets, returning the octets if it fails.
    pub fn try_from_octets(octets: Octs) -> Result<Self, Octs>
    where
        Octs: AsRef<[u8]>,
    {
        if Message::check_slice(octets.as_ref()).is_err() {
            Err(octets)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a message from a bytes value without checking.
    ///
    /// # Safety
    ///
    /// The methods for header access rely on the octets being at least as
    /// long as a header. If the sequence is shorter, the behavior is
    /// undefined.
    pub(super) unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Message { octets }
    }
}

impl Message<[u8]> {
    /// Creates a message from an octets slice.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns ok, the message may still be broken with other
    /// methods returning errors later one.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, ShortMessage> {
        Message::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a message from a bytes value without checking.
    ///
    /// # Safety
    ///
    /// The methods for header access rely on the octets being at least as
    /// long as a header. If the sequence is shorter, the behavior is
    /// undefined.
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: Message has repr(transparent)
        mem::transmute(slice)
    }

    /// Checks that the slice can be used for a message.
    fn check_slice(slice: &[u8]) -> Result<(), ShortMessage> {
        if slice.len() < mem::size_of::<HeaderSection>() {
            Err(ShortMessage(()))
        } else {
            Ok(())
        }
    }
}

impl<Octs: ?Sized> Message<Octs> {
    /// Returns a reference to the underlying octets sequence.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    /// Converts the message into the underlying octets sequence.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    /// Returns a slice to the underlying octets sequence.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }

    /// Returns a mutable slice to the underlying octets sequence.
    ///
    /// Because it is possible to utterly break the message using this slice,
    /// the method is private.
    fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octs: AsMut<[u8]>,
    {
        self.octets.as_mut()
    }

    /// Returns a message for a slice of the octets sequence.
    pub fn for_slice(&self) -> &Message<[u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe { Message::from_slice_unchecked(self.octets.as_ref()) }
    }

    /// Returns a message for a slice reference.
    pub fn for_slice_ref(&self) -> Message<&[u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe { Message::from_octets_unchecked(self.octets.as_ref()) }
    }
}

/// # Header Section
///
impl<Octs: AsRef<[u8]> + ?Sized> Message<Octs> {
    /// Returns the message header.
    pub fn header(&self) -> Header {
        *Header::for_message_slice(self.as_slice())
    }

    /// Returns a mutable reference to the message header.
    pub fn header_mut(&mut self) -> &mut Header
    where
        Octs: AsMut<[u8]>,
    {
        Header::for_message_slice_mut(self.as_slice_mut())
    }

    /// Returns the header counts of the message.
    pub fn header_counts(&self) -> HeaderCounts {
        *HeaderCounts::for_message_slice(self.as_slice())
    }

    /// Returns the entire header section.
    pub fn header_section(&self) -> HeaderSection {
        *HeaderSection::for_message_slice(self.as_slice())
    }

    /// Returns whether the rcode of the header is NoError.
    pub fn no_error(&self) -> bool {
        self.header().rcode() == Rcode::NOERROR
    }

    /// Returns whether the rcode of the header is one of the error values.
    pub fn is_error(&self) -> bool {
        self.header().rcode() != Rcode::NOERROR
    }
}

/// # Access to Sections
///
impl<Octs: Octets + ?Sized> Message<Octs> {
    /// Returns the question section.
    pub fn question(&self) -> QuestionSection<'_, Octs> {
        QuestionSection::new(&self.octets)
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection<'_, Octs> {
        self.question()
    }

    /// Returns the answer section.
    ///
    /// Iterates over the question section in order to access the answer
    /// section. If you are accessing the question section anyway, using
    /// its [`next_section`] method may be more efficient.
    ///
    /// [`next_section`]: ../struct.QuestionSection.html#method.next_section
    pub fn answer(&self) -> Result<RecordSection<'_, Octs>, ParseError> {
        self.question().next_section()
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(
        &self,
    ) -> Result<RecordSection<'_, Octs>, ParseError> {
        self.answer()
    }

    /// Returns the authority section.
    ///
    /// Iterates over both the question and the answer sections to determine
    /// the start of the authority section. If you are already accessing the
    /// answer section, using [`next_section`] on it is more efficient.
    ///
    /// [`next_section`]: ../struct.RecordSection.html#method.next_section
    pub fn authority(&self) -> Result<RecordSection<'_, Octs>, ParseError> {
        Ok(self.answer()?.next_section()?.unwrap())
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> Result<RecordSection<'_, Octs>, ParseError> {
        self.authority()
    }

    /// Returns the additional section.
    ///
    /// Iterates over all three previous sections to determine the start of
    /// the additional section. If you are already accessing the
    /// authority section, using [`next_section`] on it is more efficient.
    ///
    /// [`next_section`]: ../struct.RecordSection.html#method.next_section
    pub fn additional(&self) -> Result<RecordSection<'_, Octs>, ParseError> {
        Ok(self.authority()?.next_section()?.unwrap())
    }

    /// Returns all four sections in one fell swoop.
    #[allow(clippy::type_complexity)]
    pub fn sections(
        &self,
    ) -> Result<
        (
            QuestionSection<'_, Octs>,
            RecordSection<'_, Octs>,
            RecordSection<'_, Octs>,
            RecordSection<'_, Octs>,
        ),
        ParseError,
    > {
        let question = self.question();
        let answer = question.next_section()?;
        let authority = answer.next_section()?.unwrap();
        let additional = authority.next_section()?.unwrap();
        Ok((question, answer, authority, additional))
    }

    /// Returns an iterator over the records in the message.
    ///
    /// The iterator’s item is a pair of a [`ParsedRecord`] and the
    /// [`Section`] it was found in.
    ///
    /// As is customary, this iterator is also accessible via the
    /// `IntoIterator` trait on a reference to the message.
    ///
    /// [`ParsedRecord`]: ../record/struct.ParsedRecord.html
    /// [`Section`]: enum.Section.html
    pub fn iter(&self) -> MessageIter<'_, Octs> {
        self.into_iter()
    }
}

/// # Helpers for Common Tasks
///
impl<Octs: Octets + ?Sized> Message<Octs> {
    /// Returns whether this is the answer to some other message.
    ///
    /// The method checks whether the ID fields of the headers are the same,
    /// whether the QR flag is set in this message, and whether the questions
    /// are the same.
    pub fn is_answer<Other: Octets + ?Sized>(
        &self,
        query: &Message<Other>,
    ) -> bool {
        if !self.header().qr()
            || self.header().id() != query.header().id()
            || self.header_counts().qdcount()
                != query.header_counts().qdcount()
        {
            false
        } else {
            self.question() == query.question()
        }
    }

    /// Returns whether the message has a question that is either AXFR or
    /// IXFR.
    pub fn is_xfr(&self) -> bool {
        self.first_question()
            .map(|q| matches!(q.qtype(), Rtype::AXFR | Rtype::IXFR))
            .unwrap_or_default()
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(
        &self,
    ) -> Option<Question<ParsedName<Octs::Range<'_>>>> {
        match self.question().next() {
            None | Some(Err(..)) => None,
            Some(Ok(question)) => Some(question),
        }
    }

    /// Returns the sole question of the message.
    ///
    /// This is like [`first_question`] but returns an error if there isn’t
    /// exactly one question or there is a parse error.
    ///
    /// [`first_question`]: #method.first_question
    pub fn sole_question(
        &self,
    ) -> Result<Question<ParsedName<Octs::Range<'_>>>, ParseError> {
        match self.header_counts().qdcount() {
            0 => return Err(ParseError::form_error("no question")),
            1 => {}
            _ => return Err(ParseError::form_error("multiple questions")),
        }
        self.question().next().unwrap()
    }

    /// Returns the query type of the first question, if any.
    pub fn qtype(&self) -> Option<Rtype> {
        self.first_question().map(|x| x.qtype())
    }

    /// Returns whether the message contains answers of a given type.
    pub fn contains_answer<'s, Data>(&'s self) -> bool
    where
        Data: ParseRecordData<'s, Octs>,
    {
        let answer = match self.answer() {
            Ok(answer) => answer,
            Err(..) => return false,
        };
        answer.limit_to::<Data>().next().is_some()
    }

    /// Resolves the canonical name of the answer.
    ///
    /// The CNAME record allows a domain name to be an alias for a different
    /// name. Aliases may be chained. The ‘canonical name’ referred to be the
    /// method’s name is the last name in this chain. A recursive resolver
    /// will support a stub resolver in figuring out this canonical name by
    /// including all necessary CNAME records in its answer. This method can
    /// be used on such an answer to determine the canonical name. As such,
    /// it will only consider CNAMEs present in the message’s answer section.
    ///
    /// It starts with the question name and follows CNAME records until there
    /// is no next CNAME in the chain and then returns the last CNAME.
    ///
    /// If the message doesn’t have a question, if there is a parse error, or
    /// if there is a CNAME loop the method returns `None`.
    //
    //  Loop detection is done by breaking off after ANCOUNT + 1 steps -- if
    //  there is more steps then there is records in the answer section we
    //  must have a loop. While the ANCOUNT could be unreasonably large, the
    //  iterator would break off in this case and we break out with a None
    //  right away.
    pub fn canonical_name(&self) -> Option<ParsedName<Octs::Range<'_>>> {
        let question = match self.first_question() {
            None => return None,
            Some(question) => question,
        };
        let mut name = question.into_qname();
        let answer = match self.answer() {
            Ok(answer) => answer.limit_to::<Cname<_>>(),
            Err(_) => return None,
        };

        for _ in 0..self.header_counts().ancount() + 1 {
            let mut found = false;
            for record in answer.clone() {
                let record = match record {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                if *record.owner() == name {
                    name = record.into_data().into_cname();
                    found = true;
                    break;
                }
            }
            if !found {
                return Some(name);
            }
        }

        None
    }

    /// Returns the OPT record from the message, if there is one.
    pub fn opt(&self) -> Option<OptRecord<Octs::Range<'_>>> {
        match self.additional() {
            Ok(section) => match section.limit_to::<Opt<_>>().next() {
                Some(Ok(rr)) => Some(OptRecord::from(rr)),
                _ => None,
            },
            Err(_) => None,
        }
    }

    /// Returns the last additional record from the message.
    ///
    /// The method tries to parse the last record of the additional section
    /// as the provided record type. If that succeeds, it returns that
    /// parsed record.
    ///
    /// If the last record is of the wrong type or parsing fails, returns
    /// `None`.
    pub fn get_last_additional<'s, Data: ParseRecordData<'s, Octs>>(
        &'s self,
    ) -> Option<Record<ParsedName<Octs::Range<'s>>, Data>> {
        let mut section = match self.additional() {
            Ok(section) => section,
            Err(_) => return None,
        };
        loop {
            match section.count {
                Err(_) => return None,
                Ok(0) => return None,
                Ok(1) => break,
                _ => {}
            }
            let _ = section.next();
        }
        let record = match ParsedRecord::parse(&mut section.parser) {
            Ok(record) => record,
            Err(_) => return None,
        };
        let record = match record.into_record() {
            Ok(Some(record)) => record,
            _ => return None,
        };
        Some(record)
    }

    /// Drops the last additional record from the message.
    ///
    /// Does so by decreasing the ’arcount.’ Does, however, not change the
    /// underlying octet sequence.
    ///
    /// # Panics
    ///
    /// The method panics if the additional section is empty.
    pub fn remove_last_additional(&mut self)
    where
        Octs: AsMut<[u8]>,
    {
        HeaderCounts::for_message_slice_mut(self.octets.as_mut())
            .dec_arcount();
    }

    /// Copy records from a message into the target message builder.
    ///
    /// The method uses `op` to process records from all record sections
    /// before inserting, caller can use this closure to filter or manipulate
    /// records before inserting.
    pub fn copy_records<'s, R, F, T, O>(
        &'s self,
        target: T,
        mut op: F,
    ) -> Result<AdditionalBuilder<O>, CopyRecordsError>
    where
        Octs: Octets,
        R: ComposeRecord + 's,
        F: FnMut(ParsedRecord<'s, Octs>) -> Option<R>,
        T: Into<AnswerBuilder<O>>,
        O: Composer,
    {
        let mut source = self.answer()?;
        let mut target = target.into();
        for rr in &mut source {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr).map_err(CopyRecordsError::Push)?;
            }
        }

        let mut source = source.next_section()?.unwrap();
        let mut target = target.authority();
        for rr in &mut source {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr).map_err(CopyRecordsError::Push)?;
            }
        }

        let source = source.next_section()?.unwrap();
        let mut target = target.additional();
        for rr in source {
            let rr = rr?;
            if let Some(rr) = op(rr) {
                target.push(rr).map_err(CopyRecordsError::Push)?;
            }
        }

        Ok(target)
    }

    /// Get the extended rcode of a message or the normal rcode converted
    /// to an extended rcode if no opt record is present.
    pub fn opt_rcode(&self) -> OptRcode {
        self.opt()
            .map(|opt| opt.rcode(self.header()))
            .unwrap_or_else(|| self.header().rcode().into())
    }
}

/// # Printing
impl<Octs: AsRef<[u8]>> Message<Octs> {
    /// Create a wrapper that displays the message in a dig style
    ///
    /// The dig style resembles a zonefile format (see also [`ZonefileFmt`]),
    /// with additional lines that are commented out that contain information
    /// about the header, OPT record and more.
    ///
    /// [`ZonefileFmt`]: super::zonefile_fmt::ZonefileFmt
    pub fn display_dig_style(&self) -> impl core::fmt::Display + '_ {
        DigPrinter { msg: self }
    }
}

//--- AsRef

// Octs here can’t be ?Sized or it’ll conflict with AsRef<[u8]> below.
// But [u8] is covered by that impl anyway, so no harm done.
//
impl<Octs> AsRef<Octs> for Message<Octs> {
    fn as_ref(&self) -> &Octs {
        &self.octets
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for Message<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.octets.as_ref()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<Message<[u8]>> for Message<Octs> {
    fn as_ref(&self) -> &Message<[u8]> {
        unsafe { Message::from_slice_unchecked(self.octets.as_ref()) }
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Message<SrcOcts>> for Message<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Message<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.octets)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- IntoIterator

impl<'a, Octs: Octets + ?Sized> IntoIterator for &'a Message<Octs> {
    type Item = Result<(ParsedRecord<'a, Octs>, Section), ParseError>;
    type IntoIter = MessageIter<'a, Octs>;

    fn into_iter(self) -> Self::IntoIter {
        MessageIter {
            inner: self.answer().ok(),
        }
    }
}

//--- Debug

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Message<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.header().id())
            .field("qr", &self.header().qr())
            .field("opcode", &self.header().opcode())
            .field("flags", &self.header().flags())
            .field("rcode", &self.header().rcode())
            .field("qdcount", &self.header_counts().qdcount())
            .field("ancount", &self.header_counts().ancount())
            .field("nscount", &self.header_counts().nscount())
            .field("arcount", &self.header_counts().arcount())
            .finish()
    }
}

//------------ QuestionSection ----------------------------------------------

/// An iterator over the question section of a DNS message.
///
/// The iterator’s item is the result of trying to parse the question. In case
/// of a parse error, `next` will return an error once and `None` after that.
///
/// You can create a value of this type through [`Message::question`]. Use the
/// [`answer`] or [`next_section`] methods on a question section to proceed
/// to an iterator over the answer section.
///
/// [`Message::question`]: struct.Message.html#method.question
/// [`answer`]: #method.answer
/// [`next_section`]: #method.next_section
#[derive(Debug)]
pub struct QuestionSection<'a, Octs: ?Sized> {
    /// The parser for generating the questions.
    parser: Parser<'a, Octs>,

    /// The remaining number of questions.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParseError>,
}

impl<'a, Octs: Octets + ?Sized> QuestionSection<'a, Octs> {
    /// Creates a new question section from a reference to the message octets.
    fn new(octets: &'a Octs) -> Self {
        let mut parser = Parser::from_ref(octets);
        parser.advance(mem::size_of::<HeaderSection>()).unwrap();
        QuestionSection {
            count: Ok(
                HeaderCounts::for_message_slice(parser.as_slice()).qdcount()
            ),
            parser,
        }
    }

    /// Returns the current position relative to the beginning of the message.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.parser.pos()
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into the
    /// first [`RecordSection`].
    ///
    /// [`RecordSection`]: struct.RecordSection.html
    pub fn answer(mut self) -> Result<RecordSection<'a, Octs>, ParseError> {
        while self.next().is_some() {}
        let _ = self.count?;
        Ok(RecordSection::new(self.parser, Section::first()))
    }

    /// Proceeds to the answer section.
    ///
    /// This is identical to [`answer`][Self::answer] and is here for
    /// consistency.
    pub fn next_section(self) -> Result<RecordSection<'a, Octs>, ParseError> {
        self.answer()
    }
}

//--- Clone and Clone

impl<'a, Octs: ?Sized> Clone for QuestionSection<'a, Octs> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Octs: ?Sized> Copy for QuestionSection<'a, Octs> {}

//--- Iterator

impl<'a, Octs: Octets + ?Sized> Iterator for QuestionSection<'a, Octs> {
    type Item = Result<Question<ParsedName<Octs::Range<'a>>>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => match Question::parse(&mut self.parser)
            {
                Ok(question) => {
                    self.count = Ok(count - 1);
                    Some(Ok(question))
                }
                Err(err) => {
                    self.count = Err(err);
                    Some(Err(err))
                }
            },
            _ => None,
        }
    }
}

//--- PartialEq

impl<'a, 'o, Octs, Other> PartialEq<QuestionSection<'o, Other>>
    for QuestionSection<'a, Octs>
where
    Octs: Octets + ?Sized,
    Other: Octets + ?Sized,
{
    fn eq(&self, other: &QuestionSection<'o, Other>) -> bool {
        let mut me = *self;
        let mut other = *other;
        loop {
            match (me.next(), other.next()) {
                (Some(Ok(left)), Some(Ok(right))) => {
                    if left != right {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }
}

//------------ Section -------------------------------------------------------

/// A helper type enumerating the three kinds of record sections.
///
/// See the documentation of [`Message`] for what the three sections are.
///
/// [`Message`]: struct.Message.html
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

impl Section {
    /// Returns the first section.
    #[must_use]
    pub fn first() -> Self {
        Section::Answer
    }

    /// Returns the correct record count for this section.
    fn count(self, counts: HeaderCounts) -> u16 {
        match self {
            Section::Answer => counts.ancount(),
            Section::Authority => counts.nscount(),
            Section::Additional => counts.arcount(),
        }
    }

    /// Returns the value for the following section or `None` if this is last.
    pub(crate) fn next_section(self) -> Option<Self> {
        match self {
            Section::Answer => Some(Section::Authority),
            Section::Authority => Some(Section::Additional),
            Section::Additional => None,
        }
    }
}

//------------ RecordSection -----------------------------------------------

/// An iterator over the records in one of the three record sections.
///
/// The iterator’s item is the result of parsing a raw record represented by
/// [`ParsedRecord`]. This type will allow access to an unparsed record. It
/// can be converted into a concrete [`Record`] via its [`into_record`]
/// method. If parsing the raw record fails, the iterator will return an
/// error once and `None` after that.
///
/// Alternatively, you can trade in a value of this type into a
/// [`RecordIter`] that iterates over [`Record`]s of a specific type by
/// calling the [`limit_to`] method. In particular, you can use this together
/// with [`AllRecordData`] to acquire an iterator that parses all known
/// record types.
///
/// `RecordSection` values cannot be created directly. You can get one either
/// by calling the method for the section in question of a [`Message`] value
/// or by proceeding from another section via its `next_section` method.
///
/// [`limit_to`]: #method.limit_to
/// [`AllRecordData`]: ../../rdata/enum.AllRecordData.html
/// [`Message`]: struct.Message.html
/// [`ParseRecord`]: ../record/struct.ParsedRecord.html
/// [`Record`]: ../record/struct.Record.html
/// [`RecordIter`]: struct.RecordIter.html
/// [`into_record`]: ../record/struct.ParsedRecord.html#method.into_record
#[derive(Debug)]
pub struct RecordSection<'a, Octs: ?Sized> {
    /// The parser for generating the records.
    parser: Parser<'a, Octs>,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of records.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParseError>,
}

impl<'a, Octs: Octets + ?Sized> RecordSection<'a, Octs> {
    /// Creates a new section from a parser.
    ///
    /// The parser must be positioned at the beginning of this section.
    fn new(parser: Parser<'a, Octs>, section: Section) -> Self {
        RecordSection {
            count: Ok(section
                .count(*HeaderCounts::for_message_slice(parser.as_slice()))),
            section,
            parser,
        }
    }

    /// Returns the current position relative to the beginning of the message.
    #[must_use]
    pub fn pos(&self) -> usize {
        self.parser.pos()
    }

    /// Trades `self` in for an iterator limited to a concrete record type.
    ///
    /// The record type is given through its record data type. Since the data
    /// is being parsed, this type must implement [`ParseRecordData`]. For
    /// record data types that are generic over domain name types, this is
    /// normally achieved by giving them a [`ParsedName`]. As a convenience,
    /// type aliases for all the fundamental record data types exist in the
    /// [domain::rdata::parsed] module.
    ///
    /// The returned limited iterator will continue at the current position
    /// of `self`. It will *not* start from the beginning of the section.
    ///
    /// [`ParseRecordData`]: ../rdata/trait.ParseRecordData.html
    /// [`ParsedName`]: ../name/struct.ParsedName.html
    /// [domain::rdata::parsed]: ../../rdata/parsed/index.html
    #[must_use]
    pub fn limit_to<Data: ParseRecordData<'a, Octs>>(
        self,
    ) -> RecordIter<'a, Octs, Data> {
        RecordIter::new(self, false)
    }

    /// Trades `self` in for an iterator limited to a type in IN class.
    ///
    /// Behaves exactly like [`limit_to`] but skips over records that are not
    /// of class IN.
    ///
    /// [`limit_to`]: #method.limit_to
    #[must_use]
    pub fn limit_to_in<Data: ParseRecordData<'a, Octs>>(
        self,
    ) -> RecordIter<'a, Octs, Data> {
        RecordIter::new(self, true)
    }

    /// Trades `self` for an interator over all the record.
    #[must_use]
    pub fn into_records<Data: ParseAnyRecordData<'a, Octs>>(
        self,
    ) -> AnyRecordIter<'a, Octs, Data> {
        AnyRecordIter::new(self)
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unusable
    /// now.
    pub fn next_section(mut self) -> Result<Option<Self>, ParseError> {
        let section = match self.section.next_section() {
            Some(section) => section,
            None => return Ok(None),
        };
        while self.skip_next().is_some() {}
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
            _ => None,
        }
    }
}

//--- Clone and Copy

impl<'a, Octs: ?Sized> Clone for RecordSection<'a, Octs> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, Octs: ?Sized> Copy for RecordSection<'a, Octs> {}

//--- Iterator

impl<'a, Octs: Octets + ?Sized> Iterator for RecordSection<'a, Octs> {
    type Item = Result<ParsedRecord<'a, Octs>, ParseError>;

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
            _ => None,
        }
    }
}

//------------ MessageIter ---------------------------------------------------

/// An iterator over the records of a message.
pub struct MessageIter<'a, Octs: ?Sized> {
    inner: Option<RecordSection<'a, Octs>>,
}

impl<'a, Octs: Octets + ?Sized> Iterator for MessageIter<'a, Octs> {
    type Item = Result<(ParsedRecord<'a, Octs>, Section), ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to get next record from current section
        match self.inner {
            Some(ref mut inner) => {
                let item = inner.next();
                if let Some(item) = item {
                    return Some(item.map(|item| (item, inner.section)));
                }
            }
            None => return None,
        }

        // Advance to next section if possible, and retry
        let inner = self.inner.take()?;
        match inner.next_section() {
            Ok(section) => {
                self.inner = section;
                self.next()
            }
            Err(err) => Some(Err(err)),
        }
    }
}

//------------ RecordIter ----------------------------------------------------

/// An iterator over specific records of a record section of a DNS message.
///
/// The iterator’s item type is the result of trying to parse a record.
/// It silently skips over all records that `Data` cannot or does not want to
/// parse. If parsing the record data fails, the iterator will return an
/// error but can continue with the next record. If parsing the entire record
/// fails the item will be an error and subsequent attempts to continue will
/// also produce errors. This case can be distinguished from an error while
/// parsing the record data by [`next_section`] returning an error, too.
///
/// You can create a value of this type through the
/// [`RecordSection::limit_to`] method.
///
/// [`next_section`]: #method.next_section
/// [`RecordSection::limit_to`]: struct.RecordSection.html#method.limit_to
#[derive(Debug)]
pub struct RecordIter<'a, Octs: ?Sized, Data> {
    section: RecordSection<'a, Octs>,
    in_only: bool,
    marker: PhantomData<Data>,
}

impl<'a, Octs, Data> RecordIter<'a, Octs, Data>
where
    Octs: Octets + ?Sized,
    Data: ParseRecordData<'a, Octs>,
{
    /// Creates a new record iterator.
    fn new(section: RecordSection<'a, Octs>, in_only: bool) -> Self {
        RecordIter {
            section,
            in_only,
            marker: PhantomData,
        }
    }

    /// Trades the limited iterator for the full iterator.
    ///
    /// The returned iterator will continue right after the last record
    /// previously returned.
    #[must_use]
    pub fn unwrap(self) -> RecordSection<'a, Octs> {
        self.section
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing the message has failed. Returns
    /// `Ok(None)` if this iterator was already on the additional section.
    pub fn next_section(
        self,
    ) -> Result<Option<RecordSection<'a, Octs>>, ParseError> {
        self.section.next_section()
    }
}

//--- Clone

impl<'a, Octs: ?Sized, Data> Clone for RecordIter<'a, Octs, Data> {
    fn clone(&self) -> Self {
        RecordIter {
            section: self.section,
            in_only: self.in_only,
            marker: PhantomData,
        }
    }
}

//--- Iterator

impl<'a, Octs, Data> Iterator for RecordIter<'a, Octs, Data>
where
    Octs: Octets + ?Sized,
    Data: ParseRecordData<'a, Octs>,
{
    type Item = Result<Record<ParsedName<Octs::Range<'a>>, Data>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = match self.section.next() {
                Some(Ok(record)) => record,
                Some(Err(err)) => return Some(Err(err)),
                None => return None,
            };
            if self.in_only && record.class() != Class::IN {
                continue;
            }
            match record.into_record() {
                Ok(Some(record)) => return Some(Ok(record)),
                Err(err) => return Some(Err(err)),
                Ok(None) => {}
            }
        }
    }
}

//------------ AnyRecordIter -------------------------------------------------

/// An iterator over the records of a record section of a DNS message.
///
/// The iterator’s item type is the result of trying to parse a record.
/// If parsing the record data fails, the iterator will return an
/// error but can continue with the next record. If parsing the entire record
/// fails the item will be an error and subsequent attempts to continue will
/// also produce errors. This case can be distinguished from an error while
/// parsing the record data by [`next_section`] returning an error, too.
///
/// [`next_section`]: Self::next_section
#[derive(Debug)]
pub struct AnyRecordIter<'a, Octs: ?Sized, Data> {
    section: RecordSection<'a, Octs>,
    marker: PhantomData<Data>,
}

impl<'a, Octs, Data> AnyRecordIter<'a, Octs, Data>
where
    Octs: Octets + ?Sized,
    Data: ParseAnyRecordData<'a, Octs>,
{
    /// Creates a new record iterator.
    fn new(section: RecordSection<'a, Octs>) -> Self {
        Self {
            section,
            marker: PhantomData,
        }
    }

    /// Trades the limited iterator for the full iterator.
    ///
    /// The returned iterator will continue right after the last record
    /// previously returned.
    #[must_use]
    pub fn unwrap(self) -> RecordSection<'a, Octs> {
        self.section
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing the message has failed. Returns
    /// `Ok(None)` if this iterator was already on the additional section.
    pub fn next_section(
        self,
    ) -> Result<Option<RecordSection<'a, Octs>>, ParseError> {
        self.section.next_section()
    }
}

//--- Clone

impl<'a, Octs: ?Sized, Data> Clone for AnyRecordIter<'a, Octs, Data> {
    fn clone(&self) -> Self {
        Self {
            section: self.section,
            marker: PhantomData,
        }
    }
}

//--- Iterator

impl<'a, Octs, Data> Iterator for AnyRecordIter<'a, Octs, Data>
where
    Octs: Octets + ?Sized,
    Data: ParseAnyRecordData<'a, Octs>,
{
    type Item = Result<Record<ParsedName<Octs::Range<'a>>, Data>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        let record = match self.section.next() {
            Some(Ok(record)) => record,
            Some(Err(err)) => return Some(Err(err)),
            None => return None,
        };
        Some(record.into_any_record())
    }
}
//============ Error Types ===================================================

//------------ ShortMessage --------------------------------------------------

/// A message was too short to even contain the header.
#[derive(Clone, Copy, Debug)]
pub struct ShortMessage(());

impl fmt::Display for ShortMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("short message")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShortMessage {}

//------------ CopyRecordsError ----------------------------------------------

/// An error occurrd while copying records.
#[derive(Clone, Copy, Debug)]
pub enum CopyRecordsError {
    /// Parsing the source message failed.
    Parse(ParseError),

    /// Not enough space in the target.
    Push(PushError),
}

//--- From

impl From<ParseError> for CopyRecordsError {
    fn from(err: ParseError) -> Self {
        CopyRecordsError::Parse(err)
    }
}

impl From<PushError> for CopyRecordsError {
    fn from(err: PushError) -> Self {
        CopyRecordsError::Push(err)
    }
}

//--- Display and Error

impl fmt::Display for CopyRecordsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CopyRecordsError::Parse(ref err) => err.fmt(f),
            CopyRecordsError::Push(ref err) => err.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CopyRecordsError {}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    #[cfg(feature = "std")]
    use crate::base::message_builder::MessageBuilder;
    #[cfg(feature = "std")]
    use crate::base::name::Name;
    #[cfg(feature = "std")]
    use crate::rdata::{AllRecordData, Ns};
    #[cfg(feature = "std")]
    use std::vec::Vec;

    // Helper for test cases
    #[cfg(feature = "std")]
    fn get_test_message() -> Message<Vec<u8>> {
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.answer();
        msg.push((
            Name::vec_from_str("foo.example.com.").unwrap(),
            86000,
            Cname::new(Name::vec_from_str("baz.example.com.").unwrap()),
        ))
        .unwrap();
        let mut msg = msg.authority();
        msg.push((
            Name::vec_from_str("bar.example.com.").unwrap(),
            86000,
            Ns::new(Name::vec_from_str("baz.example.com.").unwrap()),
        ))
        .unwrap();
        msg.into_message()
    }

    #[test]
    fn short_message() {
        assert!(Message::from_octets(&[0u8; 11]).is_err());
        assert!(Message::from_octets(&[0u8; 12]).is_ok());
    }

    #[test]
    #[cfg(feature = "std")]
    fn canonical_name() {
        use crate::rdata::A;

        // Message without CNAMEs.
        let mut msg = MessageBuilder::new_vec().question();
        msg.push((Name::vec_from_str("example.com.").unwrap(), Rtype::A))
            .unwrap();
        let msg_ref = msg.as_message();
        assert_eq!(
            Name::vec_from_str("example.com.").unwrap(),
            msg_ref.canonical_name().unwrap()
        );

        // Message with CNAMEs.
        let mut msg = msg.answer();
        msg.push((
            Name::vec_from_str("bar.example.com.").unwrap(),
            86000,
            Cname::new(Name::vec_from_str("baz.example.com.").unwrap()),
        ))
        .unwrap();
        msg.push((
            Name::vec_from_str("example.com.").unwrap(),
            86000,
            Cname::new(Name::vec_from_str("foo.example.com.").unwrap()),
        ))
        .unwrap();
        msg.push((
            Name::vec_from_str("foo.example.com.").unwrap(),
            86000,
            Cname::new(Name::vec_from_str("bar.example.com.").unwrap()),
        ))
        .unwrap();
        let msg_ref = msg.as_message();
        assert_eq!(
            Name::vec_from_str("baz.example.com.").unwrap(),
            msg_ref.canonical_name().unwrap()
        );

        // CNAME loop.
        msg.push((
            Name::vec_from_str("baz.example.com").unwrap(),
            86000,
            Cname::new(Name::vec_from_str("foo.example.com").unwrap()),
        ))
        .unwrap();
        assert!(msg.as_message().canonical_name().is_none());
        msg.push((
            Name::vec_from_str("baz.example.com").unwrap(),
            86000,
            A::from_octets(127, 0, 0, 1),
        ))
        .unwrap();
        assert!(msg.as_message().canonical_name().is_none());
    }

    #[test]
    #[cfg(feature = "std")]
    fn message_iterator() {
        let msg = get_test_message();
        let mut iter = msg.iter();

        // Check that it returns a record from first section
        let (_rr, section) = iter.next().unwrap().unwrap();
        assert_eq!(Section::Answer, section);

        // Check that it advances to next section
        let (_rr, section) = iter.next().unwrap().unwrap();
        assert_eq!(Section::Authority, section);
    }

    #[test]
    #[cfg(feature = "std")]
    fn copy_records() {
        let msg = get_test_message();
        let target = MessageBuilder::new_vec().question();
        let res = msg.copy_records(target.answer(), |rr| {
            if let Ok(Some(rr)) =
                rr.into_record::<AllRecordData<_, ParsedName<_>>>()
            {
                if rr.rtype() == Rtype::CNAME {
                    return Some(rr);
                }
            }
            None
        });

        assert!(res.is_ok());
        if let Ok(target) = res {
            let msg = target.into_message();
            assert_eq!(1, msg.header_counts().ancount());
            assert_eq!(0, msg.header_counts().arcount());
        }
    }
}
