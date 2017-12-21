//! Accessing exisiting DNS messages.
//!
//! This module defines a number of types for disecting the content of a
//! DNS message in wire format. Because many of the components of the message
//! are of varying length, this can only be done iteratively. You start out
//! with a value of type [`Message`] that wraps the data of a complete
//! message and progressively trade it in for values of other types
//! representing other sections of the message.
//!
//! For all details, see the [`Message`] type.
//!
//! [`Message`]: struct.Message.html


use std::{mem, ops};
use std::marker::PhantomData;
use bytes::Bytes;
use ::iana::{Rcode, Rtype};
use ::rdata::Cname;
use super::header::{Header, HeaderCounts, HeaderSection};
use super::name::{ParsedDname, ParsedDnameError};
use super::parse::{Parse, Parser, ShortBuf};
use super::question::Question;
use super::rdata::ParseRecordData;
use super::record::{ParsedRecord, Record, RecordParseError};


//------------ Message -------------------------------------------------------

/// A DNS message.
///
/// This type wraps a bytes value with the wire-format content of a DNS
/// message and allows parsing the content for further processing.
///
/// Typically, you create a message by passing a bytes value with data you
/// received from the network to the [`from_bytes`] function. This function
/// does a quick sanity check if the data can be a DNS message at all
/// before returning a message value. All further parsing happens lazily when
/// you access more of the message.
///
/// Section 4 of [RFC 1035] defines DNS messages as being divded into five
/// sections named header, question, answer, authority, and additional.
///
/// The header section is of a fixed sized and can be accessed at any time
/// through the methods given under [Header Section]. Most likely, you will
/// be interested in the first part of the header for which references 
/// are returned by the [`header`] method.  The second part of the header
/// section contains the number of entries in the following four sections
/// and is of less interest as there are more sophisticated ways of accessing
/// these sections. If you do care, you can get a reference through
/// [`counts`].
///
/// The question section contains what was asked of the DNS by a request.
/// These questions consist of a domain name, a record type, and class. With
/// normal queries, a requests asks for all records of the given record type
/// that are owned by the domain name within the class. There will normally
/// be exactly one question for normal queries. With other query operations,
/// the questions may refer to different things.
///
/// You can get access to the question section through the [`question`]
/// method. It returns a [`QuestionSection`] value that is an iterator over
/// questions. Since a single question is a very common case, there is a 
/// convenience method [`first_question`] that simple returns the first
/// question if there is any.
///
/// The following three section all contain DNS resource records. In normal
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
/// [`authority`], and [`additional`]. However, since there are no
/// pointers to where the later sections start, accessing them directly
/// means iterating over the previous sections. This is why it is more
/// efficitent to call [`next_section`] on the returned value and process
/// them in order. Alternatively, you can use the [`sections`] function
/// that gives you all four sections at once with the minimal amount of
/// iterating necessary.
///
/// Each record in the record sections is of a specific type. Each type has
/// its specific record data. Because there are so many types, we decided
/// against having only one giant enum. Instead, invidual types can either
/// implement the record data for one single record type or there can be
/// compound types covering multiple record types. An example of the latter
/// is [`AllRecordData`] from the [rdata] module that does indeed provide
/// this one giant enum if you insist on using it.
/// 
/// Consequently, the typ representing a record section of a message,
/// somewhat obviously named [`RecordSection`], iterates over a stand-in type,
/// [`ParseRecord`], that gives you access to all information of the record
/// except for its data.
///
/// There are two ways to convert that value into a [`Record`] with actual
/// data. [`ParseRecord::into_record`] takes a record data type as a type
/// argument—turbo-fish style—and tries to reparse the record as a record
/// with that data. Alternatively, you can switch the entire record section
/// to inly iterate over such records via the [`limit_to`] method.
///
/// So, if you want to iterate over the MX records in the answer section, you
/// would do something like this:
///
/// ```
/// # use domain::bits::message::Message;
/// use domain::rdata::parsed::Mx;
///
/// # let bytes = vec![0; 12].into();
/// let msg = Message::from_bytes(bytes).unwrap();
/// for record in msg.answer().unwrap().limit_to::<Mx>() {
///     if let Ok(record) = record {
///         // Do something with the record ...
///     }
/// }
/// ```
///
/// The code inside the for loop deals with the fact that iterator actually
/// returns a `Result<T, E>`. An error signals that something went wrong while
/// parsing. If only the record data is broken, the message remains useful and
/// parsing can continue with the next record. If the message is fully
/// broken, the next iteration will return `None` to signal that.
///
/// [`additional`]: #method.additional
/// [`answer`]: #method.answer
/// [`authority`]: #method.authority
/// [`counts`]: #method.counts
/// [`first_question`]: #method.first_question
/// [`from_bytes`]: #method.from_bytes
/// [`header`]: #method.header
/// [`limit_to`]: ../struct.RecordSection.html#method.limit_to
/// [`next_section`]: ../struct.RecordSection.html#method.next_section
/// [`question`]: #method.question
/// [`sections`]: #method.sections
/// [`AllRecordData`]: ../../rdata/enum.AllRecordData.html
/// [`QuestionSection`]: struct.QuestionSection.html
/// [`ParseRecord`]: ../record/struct.ParseRecord.html
/// [`ParseRecord::into_record`]: ../record/struct.ParseRecord.html#method.into_record
/// [`RecordSection`]: struct.RecordSection.html
/// [Header Section]: #header-section
/// [rdata]: ../../rdata/index.html
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone, Debug)]
pub struct Message {
    bytes:Bytes,
}

/// # Creation and Conversion
///
impl Message {
    /// Creates a message from a bytes value.
    ///
    /// This fails if the slice is too short to even contain a complete
    /// header section.  No further checks are done, though, so if this
    /// function returns `Ok`, the message may still be broken with other
    /// methods returning `Err(_)`.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortBuf> {
        if bytes.len() < mem::size_of::<HeaderSection>() {
            Err(ShortBuf)
        }
        else {
            Ok(Message { bytes })
        }
    }

    /// Creates a message from a bytes value without checking.
    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Message { bytes }
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


/// # Header Section
///
impl Message {
    /// Returns a reference to the message header.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(self.as_slice())
    }

    /// Returns a refernce the header counts of the message.
    pub fn header_counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(self.as_slice())
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


/// # Sections
///
impl Message {
    /// Returns the question section.
    pub fn question(&self) -> QuestionSection {
        QuestionSection::new(self.bytes.clone())
    }

    /// Returns the zone section of an UPDATE message.
    ///
    /// This is identical to `self.question()`.
    pub fn zone(&self) -> QuestionSection { self.question() }

    /// Returns the answer section.
    pub fn answer(&self) -> Result<RecordSection, ParsedDnameError> {
        Ok(self.question().next_section()?)
    }

    /// Returns the prerequisite section of an UPDATE message.
    ///
    /// This is identical to `self.answer()`.
    pub fn prerequisite(&self) -> Result<RecordSection, ParsedDnameError> {
        self.answer()
    }

    /// Returns the authority section.
    pub fn authority(&self) -> Result<RecordSection, ParsedDnameError> {
        Ok(self.answer()?.next_section()?.unwrap())
    }

    /// Returns the update section of an UPDATE message.
    ///
    /// This is identical to `self.authority()`.
    pub fn update(&self) -> Result<RecordSection, ParsedDnameError> {
        self.authority()
    }

    /// Returns the additional section.
    pub fn additional(&self) -> Result<RecordSection, ParsedDnameError> {
        Ok(self.authority()?.next_section()?.unwrap())
    }

    /// Returns all four sections in one fell swoop.
    pub fn sections(&self) -> Result<(QuestionSection, RecordSection,
                                      RecordSection, RecordSection),
                                     ParsedDnameError> {
        let question = self.question();
        let answer = question.clone().next_section()?;
        let authority = answer.clone().next_section()?.unwrap();
        let additional = authority.clone().next_section()?.unwrap();
        Ok((question, answer, authority, additional))
    }
}


/// # Helpers for Common Tasks
///
impl Message {
    /// Returns whether this is the answer to some other message.
    ///
    /// The method checks whether the ID fields of the headers are the same,
    /// whether the QR flag is set in this message, and whether the questions
    /// are the same.
    pub fn is_answer(&self, query: &Message) -> bool {
        if !self.header().qr()
                || self.header_counts().qdcount()
                        != query.header_counts().qdcount() {
            false
        }
        else { self.question().eq(query.question()) }
    }

    /// Returns the first question, if there is any.
    ///
    /// The method will return `None` both if there are no questions or if
    /// parsing fails.
    pub fn first_question(&self) -> Option<Question<ParsedDname>> {
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
    pub fn contains_answer<D: ParseRecordData>(&self) -> bool {
        let answer = match self.answer() {
            Ok(answer) => answer,
            Err(..) => return false
        };
        answer.limit_to::<D>().next().is_some()
    }

    /// Resolves the canonical name of the answer.
    ///
    /// Returns `None` if either the message doesn’t have a question or there
    /// was a parse error. Otherwise starts with the question’s name,
    /// follows any CNAME trail and returns the name answers should be for.
    pub fn canonical_name(&self) -> Option<ParsedDname> {
        let question = match self.first_question() {
            None => return None,
            Some(question) => question
        };
        let mut name = question.qname().clone();
        let answer = match self.answer() {
            Ok(answer) => answer.limit_to::<Cname<ParsedDname>>(),
            Err(_) => return None,
        };

        loop {
            let mut found = false;
            for record in answer.clone() {
                let record = match record {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                if *record.name() == name {
                    name = record.data().cname().clone();
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
}


//--- Deref and AsRef

impl ops::Deref for Message {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl AsRef<Message> for Message {
    fn as_ref(&self) -> &Message {
        self
    }
}

impl AsRef<Bytes> for Message {
    fn as_ref(&self) -> &Bytes {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}


//------------ QuestionSection ----------------------------------------------

/// An iterator over the question section of a DNS message.
///
/// The iterator’s item is the result of trying to parse the questions. In
/// case of a parse error, `next()` will return an error once and
/// `None` after that.
///
/// You can create a value of this type through the [`Message::section`]
/// method. Use the [`answer`] or [`next_section`] methods to proceed
/// to an iterator over the answer section.
///
/// [`Message::section`]: struct.Message.html#method.section
/// [`answer`]: #method.answer
/// [`next_section`]: #method.next_section
#[derive(Clone, Debug)]
pub struct QuestionSection {
    /// The parser for generating the questions.
    parser: Parser,

    /// The remaining number of questions.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParsedDnameError>
}

impl QuestionSection {
    /// Creates a new question section from a bytes value.
    fn new(bytes: Bytes) -> Self {
        let mut parser = Parser::from_bytes(bytes);
        parser.advance(mem::size_of::<HeaderSection>()).unwrap();
        QuestionSection {
            count: Ok(HeaderCounts::for_message_slice(
                                                parser.as_slice()).qdcount()),
            parser: parser,
        }
    }

    /// Proceeds to the answer section.
    ///
    /// Skips over any remaining questions and then converts itself into
    /// the first [`RecordSection`].
    ///
    /// [`RecordSection`]: struct.RecordSection.html
    pub fn answer(mut self) -> Result<RecordSection, ParsedDnameError> {
        // XXX Use Parser::skip here.
        for question in &mut self {
            let _ = question?;
        }
        match self.count {
            Ok(..) => Ok(RecordSection::new(self.parser, Section::first())),
            Err(err) => Err(err)
        }
    }

    /// Proceeds to the answer section.
    ///
    /// This is an alias for the [`answer`] method.
    ///
    /// [`answer`]: #method.answer
    pub fn next_section(self) -> Result<RecordSection, ParsedDnameError> {
        self.answer()
    }
}


//--- Iterator

impl Iterator for QuestionSection {
    type Item = Result<Question<ParsedDname>, ParsedDnameError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match Question::parse(&mut self.parser) {
                    Ok(question) => {
                        self.count = Ok(count - 1);
                        Some(Ok(question))
                    }
                    Err(err) => {
                        self.count = Err(err.clone());
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//------------ Section -------------------------------------------------------

/// A helper type enumerating which section a `RecordSection` is currently in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Answer,
    Authority,
    Additional
}


impl Section {
    /// Returns the first section.
    fn first() -> Self { Section::Answer }

    /// Returns the correct record count for this section.
    fn count(&self, counts: &HeaderCounts) -> u16 {
        match *self {
            Section::Answer => counts.ancount(),
            Section::Authority => counts.nscount(),
            Section::Additional => counts.arcount()
        }
    }

    /// Returns the value for the following section or `None` if this is last.
    fn next_section(self) -> Option<Self> {
        match self {
            Section::Answer => Some(Section::Authority),
            Section::Authority => Some(Section::Additional),
            Section::Additional => None
        }
    }
}


//------------ RecordSection -----------------------------------------------

/// An iterator over one of the three record sections of a DNS message.
/// 
/// The iterator’s item is the result of parsing a raw record represented by
/// [`ParseRecord`]. This type will only allow access to a record’s header
/// only. It also can be converted into a concrete [`Record`] via its
/// [`into_record`] method. If parsing the raw record fails, the iterator
/// will return an error once and `None` after that.
///
/// You can also trait this value for an iterator skipping over unwanted
/// records through the [`limit_to`] method.
///
/// `RecordSection` values cannot be created directly. You can get one either
/// by calling the method for the section in question of a [`Message`] value
/// or by proceeding from another section via its `next_section` method.
///
/// [`limit_to`]: #method.limit_to
/// [`Message`]: struct.Message.html
/// [`ParseRecord`]: ../record/struct.ParseRecord.html
/// [`into_record`]: ../record/struct.ParseRecord.html#method.into_record
#[derive(Clone, Debug)]
pub struct RecordSection {
    /// The parser for generating the records.
    parser: Parser,

    /// Which section are we, really?
    section: Section,

    /// The remaining number of records.
    ///
    /// The `Result` is here to monitor an error during iteration.
    /// It is used to fuse the iterator after an error and is also returned
    /// by `answer()` should that be called after an error.
    count: Result<u16, ParsedDnameError>
}


impl RecordSection {
    /// Creates a new section from a parser.
    ///
    /// The parser must only wrap the bytes of the message and it must be
    /// positioned at the beginning of the section.
    fn new(parser: Parser, section: Section) ->  Self {
        RecordSection {
            count: Ok(section.count(
                        HeaderCounts::for_message_slice(parser.as_slice()))),
            section: section,
            parser: parser
        }
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
    pub fn limit_to<D: ParseRecordData>(self) -> RecordIter<D> {
        RecordIter::new(self)
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unsable
    /// now.
    pub fn next_section(mut self)
                        -> Result<Option<Self>, ParsedDnameError> {
        let section = match self.section.next_section() {
            Some(section) => section,
            None => return Ok(None)
        };
        // XXX Use Parser::skip here.
        for record in &mut self {
            let _ = try!(record);
        }
        match self.count {
            Ok(..) => Ok(Some(RecordSection::new(self.parser, section))),
            Err(err) => Err(err)
        }
    }
}


//--- Iterator

impl Iterator for RecordSection {
    type Item = Result<ParsedRecord, ParsedDnameError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.count {
            Ok(count) if count > 0 => {
                match ParsedRecord::parse(&mut self.parser) {
                    Ok(record) => {
                        self.count = Ok(count - 1);
                        Some(Ok(record))
                    }
                    Err(err) => {
                        self.count = Err(err.clone());
                        Some(Err(err))
                    }
                }
            }
            _ => None
        }
    }
}


//------------ RecordIter ----------------------------------------------------

/// An iterator over specific records of a record section of a DNS message.
///
/// The iterator’s item type is the result of trying to parse a record.
/// It silently skips over all records that `D` cannot or does not want to
/// parse. If parsing the record data fails, the iterator will return an
/// error but can continue with the next record. If parsing the entire record
/// fails (and the message thus becoming unusable) or if the end of the
/// section is reached, the iterator produces `None`. The latter case can be
/// distinguished by [`next_section`] returning an error.
///
/// You can create a value of this type through the
/// [`RecordSection::limit_to`] method.
///
/// [`next_section`]: #method.next_section
/// [`RecordSection::limit_to`]: struct.RecordSection.html#method.limit_to
#[derive(Clone, Debug)]
pub struct RecordIter<D: ParseRecordData> {
    section: RecordSection,
    marker: PhantomData<D>
}

impl<D: ParseRecordData> RecordIter<D> {
    /// Creates a new limited record iterator from the given section.
    fn new(section: RecordSection) -> Self {
        RecordIter { section, marker: PhantomData }
    }

    /// Trades in the limited iterator for the complete iterator.
    ///
    /// The complete iterator will continue right after the last record
    /// returned by `self`. It will *not* restart from the beginning of the
    /// section.
    pub fn unwrap(self) -> RecordSection {
        self.section
    }

    /// Proceeds to the next section if there is one.
    ///
    /// Returns an error if parsing has failed and the message is unusable
    /// now.
    pub fn next_section(self)
                        -> Result<Option<RecordSection>, ParsedDnameError> {
        self.section.next_section()
    }
}


//--- Iterator

impl<D: ParseRecordData> Iterator for RecordIter<D> {
    type Item = Result<Record<ParsedDname, D>,
                       RecordParseError<ParsedDnameError, D::Err>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let record = match self.section.next() {
                Some(Ok(record)) => record,
                Some(Err(err)) => {
                    return Some(Err(RecordParseError::Name(err)))
                }
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
    use super::*;

    #[test]
    fn short_message() {
        assert!(Message::from_bytes(Bytes::from_static(&[0u8; 11])).is_err());
        assert!(Message::from_bytes(Bytes::from_static(&[0u8; 12])).is_ok());
    }


        /*
    use std::str::FromStr;
    use bits::message_builder::MessageBuilder;
    use bits::name::Dname;
    use bits::question::Question;
    use iana::Rtype;
    use rdata::Cname;

    #[test]
    fn canonical_name() {
        // Message without CNAMEs.
        let mut msg = MessageBuilder::new_udp();
        msg.push(&Question::new_in(Dname::from_str("example.com.").unwrap(),
                                   Rtype::A)).unwrap();
        let msg = Message::from_bytes(msg.freeze()).unwrap();
        println!("{:?}", msg);
        assert_eq!(Dname::from_str("example.com.").unwrap(),
                   msg.canonical_name().unwrap());
        // Message with CNAMEs.
        let mut msg = MessageBuilder::new(ComposeMode::Unlimited,
                                          true).unwrap();
        msg.push((DNameBuf::from_str("example.com.").unwrap(),
                  Rtype::A)).unwrap();
        let mut answer = msg.answer();
        answer.push((DNameBuf::from_str("bar.example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("baz.example.com.")
                                         .unwrap())))
              .unwrap();
        answer.push((DNameBuf::from_str("example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("foo.example.com.")
                                         .unwrap())))
              .unwrap();
        answer.push((DNameBuf::from_str("foo.example.com.").unwrap(), 86000,
                     Cname::new(DNameBuf::from_str("bar.example.com.")
                                         .unwrap())))
              .unwrap();
        let msg = MessageBuf::from_vec(answer.finish()).unwrap();
        assert_eq!(DNameBuf::from_str("baz.example.com.").unwrap(),
                   msg.canonical_name().unwrap());
    }
        */
}
