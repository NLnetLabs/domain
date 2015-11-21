//! Handling of incoming DNS messages
//!

use std::ascii::AsciiExt;
use std::io;
use std::iter;
use std::marker::PhantomData;
use std::net;
use std::ops;
use super::error::{Error, Result};
use super::header::Header;
use super::name::{self, DomainName, DomainNameBuf};
use super::record::RecordData;


//------------ Message ------------------------------------------------------

/// An incoming DNS message.
///
/// The message owns the raw data. You can either create it a raw vec or
/// by reading it directly out of a socket or reader.
///
#[derive(Debug)]
pub struct Message {
    buf: Vec<u8>,

    header: Header,
    question: SectionSpec,
    answer: SectionSpec,
    authority: SectionSpec,
    additional: SectionSpec,
}

impl Message {
    /// Creates a message using the data in `buf`.
    ///
    pub fn from_vec(buf: Vec<u8>) -> Result<Message> {
        let mut res = Message { buf: buf, header: Header::new(),
                                question: SectionSpec::new(),
                                answer: SectionSpec::new(),
                                authority: SectionSpec::new(),
                                additional: SectionSpec::new() };

        try!(res.prepare());
        Ok(res)
    }

    fn prepare(&mut self) -> Result<()> {
        let mut frag = Fragment::from_buf(&self.buf);
        self.header = Header::from_u32(try!(frag.parse_u32()));
        let qdcount = try!(frag.parse_u16());
        let ancount = try!(frag.parse_u16());
        let nscount = try!(frag.parse_u16());
        let arcount = try!(frag.parse_u16());
        self.question = try!(SectionSpec::questions_from_count(&mut frag,
                                                               qdcount));
        self.answer = try!(SectionSpec::records_from_count(&mut frag,
                                                           ancount));
        self.authority = try!(SectionSpec::records_from_count(&mut frag,
                                                              nscount));
        self.additional = try!(SectionSpec::records_from_count(&mut frag,
                                                               arcount));
        Ok(())
    }

    /// Creates a message reading the data from a UDP socket.
    ///
    /// The maximum size of the datagram read is given by `size`. Upon
    /// success returns the message and the source address the message was
    /// received from.
    ///
    pub fn from_udp(sock: &net::UdpSocket, size: usize)
        -> Result<(Message, net::SocketAddr)>
    {
        let mut buf = vec![0; size];
        let (len, addr) = try!(sock.recv_from(&mut buf));
        buf.truncate(len);

        Message::from_vec(buf).map(|res| (res, addr))
    }

    /// Creates a message from a reader.
    ///
    /// This assumes to the reader to be positioned at the beginning of a
    /// TCP-like DNS message, ie., the first two bytes contain the length
    /// of the message in network format.
    ///
    pub fn from_reader<R: io::Read>(s: &mut R) -> Result<Message> {
        let len = try!(read_u16(s)) as usize;
        let mut buf = vec![0; len];
        try!(read_exact(s, &mut buf));

        Message::from_vec(buf)
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn question(&self) -> QuestionSection {
        QuestionSection::from_spec(self, &self.question)
    }

    pub fn answer(&self) -> RecordSection {
        RecordSection::from_spec(self, &self.answer)
    }

    pub fn authority(&self) -> RecordSection {
        RecordSection::from_spec(self, &self.authority)
    }

    pub fn additional(&self) -> RecordSection {
        RecordSection::from_spec(self, &self.additional)
    }

}


//------------ Fragment -----------------------------------------------------

#[derive(Clone)]
pub struct Fragment<'a> {
    buf: &'a [u8],
    range: ops::Range<usize>
}

impl<'a> Fragment<'a> {
    fn from_buf(buf: &'a [u8]) -> Fragment<'a> {
        Fragment { buf: buf, range: ops::Range { start: 0, end: buf.len() } }
    }

    fn from_bounds(buf: &'a [u8], start: usize, end: usize) -> Fragment<'a> {
        Fragment { buf: buf, range: ops::Range { start: start, end: end } }
    }

    fn from_range(buf: &'a [u8], range: &ops::Range<usize>)
        -> Fragment<'a>
    {
        Fragment::from_bounds(buf, range.start, range.end)
    }

    fn check_len(&self, len: usize) -> Result<()> {
        if self.range.start + len > self.range.end {
            Err(Error::ShortFragment)
        }
        else { Ok(()) }
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf[self.range.start ..].as_ptr()
    }

    pub fn parse_fragment(&mut self, len: usize) -> Result<Fragment<'a>> {
        try!(self.check_len(len));
        let res = Fragment::from_bounds(self.buf, self.range.start,
                                        self.range.start + len);
        self.range.start += len;
        Ok(res)
    }

    pub fn parse_u8(&mut self) -> Result<u8> {
        try!(self.check_len(1));
        let res = self.buf[self.range.start];
        self.range.start += 1; 
        Ok(res)
    }

    pub fn parse_u16(&mut self) -> Result<u16> {
        try!(self.check_len(2));
        let res = u16::from_be(unsafe { *(self.as_ptr() as *const u16) });
        self.range.start += 2;
        Ok(res)
    }

    pub fn parse_u32(&mut self) -> Result<u32> {
        try!(self.check_len(4));
        let res = u32::from_be(unsafe { *(self.as_ptr() as *const u32) });
        self.range.start += 4;
        Ok(res)
    }

    pub fn parse_bytes(&mut self, len: usize) -> Result<&[u8]> {
        try!(self.check_len(len));
        let start = self.range.start;
        self.range.start += len;
        Ok(&self.buf[start .. start + len])
    }

    pub fn skip_u8(&mut self) -> Result<()> {
        self.skip_bytes(1)
    }

    pub fn skip_u16(&mut self) -> Result<()> {
        self.skip_bytes(2)
    }

    pub fn skip_u32(&mut self) -> Result<()> {
        self.skip_bytes(4)
    }

    pub fn skip_bytes(&mut self, len: usize) -> Result<()> {
        try!(self.check_len(len));
        self.range.start += len;
        return Ok(())
    }

    pub fn skip_name(&mut self) -> Result<()> {
        loop {
            let ltype = try!(self.parse_u8());
            match ltype {
                0 => return Ok(()),
                1 ... 63 => try!(self.skip_bytes(ltype as usize)),
                0xC0 ... 0xFF => {
                    try!(self.skip_u8());
                    return Ok(());
                },
                0x41 => {
                    let mut bits = try!(self.parse_u8()) as usize;
                    if bits == 0 { bits = 256 };
                    try!(self.skip_bytes(bits >> 2));
                },
                _ => {
                    return Err(Error::NameError(
                                              name::Error::IllegalLabelType));
                }
            };
        };
    }

    pub fn parse_name(&mut self) -> Result<DomainNameBuf> {
        let mut res = DomainNameBuf::new();
        try!(self._parse_name(&mut res));
        Ok(res)
    }

    fn _parse_name(&mut self, name: &mut DomainNameBuf) -> Result<()> {
        loop {
            let ltype = try!(self.parse_u8()) as usize;
            match ltype {
                0 => return Ok(()),
                1 ... 63 => name.push(&try!(self.parse_bytes(ltype))),
                0xC0 ... 0xFF => {
                    let ptr = ((ltype & 0x3F)) << 8
                            | try!(self.parse_u8()) as usize;
                    return Fragment::from_bounds(self.buf, ptr, self.buf.len())
                                ._parse_name(name)
                }
                _ => return Err(Error::NameError(name::Error::IllegalLabelType))
            }
        }
    }

    /// Returns whether the name at the beginning of `self` matches `name`. 
    ///
    /// Does not move the fragment forward.
    ///
    pub fn name_eq(&self, name: &DomainName) -> bool {
        match self._name_eq(name) {
            Err(_) => false,
            Ok(res) => res
        }
    }

    fn _name_eq(&self, name: &DomainName) -> Result<bool> {
        let mut frag = self.clone();
        let mut name = name;
        loop {
            let ltype = try!(frag.parse_u8()) as usize;
            if ltype < 64 {
                if name.is_empty() {
                    return Ok(false)
                }
                let (label, tail) = name.split_first().unwrap();
                if ltype != label.len() {
                    return Ok(false)
                }
                else if ltype == 0 {
                    return Ok(true)
                }
                else if !try!(frag.parse_bytes(ltype))
                              .eq_ignore_ascii_case(label.as_bytes()) {
                    return Ok(false)
                }
                else {
                    name = tail;
                }
            }
            else if ltype >= 0xC0 {
                let ptr = ((ltype & 0x3F)) << 8
                        | try!(frag.parse_u8()) as usize;
                frag = Fragment::from_bounds(frag.buf, ptr,
                                             frag.buf.len())
            }
            else {
                return Ok(false)
            }
        }
    }


    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn is_empty(&self) -> bool {
        self.range.end == self.range.start
    }
}


//------------ SectionSpec --------------------------------------------------

#[derive(Clone, Debug)]
struct SectionSpec {
    range: ops::Range<usize>,
    count: u16,
}

impl SectionSpec {
    fn new() -> SectionSpec {
        SectionSpec { range: ops::Range { start: 0, end: 0 }, count: 0 }
    }

    fn from_values(start: usize, end: usize, count: u16) -> SectionSpec {
        SectionSpec { range: ops::Range { start: start, end: end },
                      count: count }
    }

    fn questions_from_count(frag: &mut Fragment, count: u16)
        -> Result<SectionSpec>
    {
        let start = frag.range.start;
        for _ in 0 .. count {
            try!(frag.skip_name());
            try!(frag.skip_bytes(4));
        }
        Ok(SectionSpec::from_values(start, frag.range.start, count))
    }

    fn records_from_count(frag: &mut Fragment, count: u16)
        -> Result<SectionSpec>
    {
        let start = frag.range.start;
        for _ in 0 .. count {
            try!(frag.skip_name());
            try!(frag.skip_bytes(8));
            let rdlen = try!(frag.parse_u16()) as usize;
            try!(frag.skip_bytes(rdlen));
        }
        Ok(SectionSpec::from_values(start, frag.range.start, count))
    }

}


//------------ QuestionSection ----------------------------------------------

/// The section of a DNS message containing the questions.
///
pub struct QuestionSection<'a> {
    frag: Fragment<'a>,
}

impl<'a> QuestionSection<'a> {
    fn from_spec(msg: &'a Message, spec: &SectionSpec) -> QuestionSection<'a>
    {
        QuestionSection { frag: Fragment::from_range(&msg.buf, &spec.range) }
    }

    /// Returns an iterator over the questions.
    ///
    pub fn iter(&mut self) -> QuestionIter<'a> {
        QuestionIter::from_section(self)
    }
}


//------------ Question -----------------------------------------------------

/// A question requests answers for a certain type of resource records.
///
#[derive(Clone, Debug)]
pub struct Question {
    /// The name of the node for which records are requested.
    ///
    pub qname: DomainNameBuf,

    /// The type of records that are requested.
    ///
    pub qtype: u16,

    /// The requested class.
    ///
    pub qclass: u16
}

impl Question {
    fn from_frag(frag: &mut Fragment) -> Result<Question> {
        let qname = try!(frag.parse_name());
        let qtype = try!(frag.parse_u16());
        let qclass = try!(frag.parse_u16());
        Ok(Question { qname: qname, qtype: qtype, qclass: qclass })
    }

    fn skip(frag: &mut Fragment) -> Result<()> {
        try!(frag.skip_name());
        try!(frag.skip_bytes(4));
        Ok(())
    }
}


/// An iterator over questions.
///
pub struct QuestionIter<'a> {
    frag: Fragment<'a>
}

impl<'a> QuestionIter<'a> {
    fn from_section(section: &QuestionSection<'a>) -> QuestionIter<'a> {
        QuestionIter { frag: section.frag.clone() }
    }

    fn skip_next(&mut self) -> bool {
        if self.frag.is_empty() { false }
        else { Question::skip(&mut self.frag).unwrap(); true }
    }
}

impl<'a> Iterator for QuestionIter<'a> {
    type Item = Result<Question>;

    fn next(&mut self) -> Option<Result<Question>> {
        if self.frag.is_empty() { None }
        else { Some(Question::from_frag(&mut self.frag)) }
    }

    fn count(mut self) -> usize {
        let mut res = 0;
        while self.skip_next() { res += 1 }
        res
    }

    fn last(mut self) -> Option<Result<Question>> {
        if self.frag.is_empty() { return None }
        let mut frag = self.frag.clone();
        while self.skip_next() {
            frag = self.frag.clone();
        }
        Some(Question::from_frag(&mut frag))
    }

    fn nth(&mut self, n: usize) -> Option<Result<Question>> {
        for _ in 0 .. n {
            if !self.skip_next() {
                return None
            }
        }
        self.next()
    }
}


//------------ RecordSection ------------------------------------------------

/// One of the three sections of a DNS message containing resource records.
///
pub struct RecordSection<'a> {
    frag: Fragment<'a>,
}

impl<'a> RecordSection<'a> {
    fn from_spec(msg: &'a Message, spec: &SectionSpec) -> RecordSection<'a> {
        RecordSection { frag: Fragment::from_range(&msg.buf, &spec.range) }
                  
    }
}

impl<'a> RecordSection<'a> {
    /// Returns an iterator over the resource records of type `R`.
    ///
    /// Quietly skips over records where parsing of name or data fails.
    ///
    pub fn iter<R: RecordData>(&mut self) -> RecordIter<'a, R> {
        RecordIter::from_section(self)
    }

    /// Returns a strict iterator over the resource records of type `R`.
    ///
    pub fn strict_iter<R: RecordData>(&mut self) -> StrictRecordIter<'a, R> {
        StrictRecordIter::from_section(self)
    }

    /// Returns an iterator over the record data of a resource record set.
    ///
    pub fn rrset<R: RecordData>(&mut self, name: &'a DomainName,
                                rclass: u16) -> RRSetIter<'a, R>
    {
        RRSetIter::from_section(self, name, rclass)
    }

    /// Returns an iterator over the record data of a resource record set.
    ///
    pub fn strict_rrset<R: RecordData>(&mut self, name: &'a DomainName,
                                       rclass: u16) -> StrictRRSetIter<'a, R>
    {
        StrictRRSetIter::from_section(self, name, rclass)
    }

    /// Returns an iterator over the type-independent field of a resource
    /// record.
    ///
    pub fn iter_info(&mut self) -> RecordInfoIter<'a> {
        RecordInfoIter::from_section(self)
    }

}


//------------ Resource Record References -----------------------------------

/// A reference to a resource record inside some fragment.
///
/// This type is used internally only to limit the parsing necessary when
/// iterating over sections. It uses ranges instead of fragments to work
/// around limitation of lifetimes in traits.
///
#[derive(Clone, Debug)]
pub struct RecordRange {
    range: ops::Range<usize>,
    rtype: u16,
    rclass: u16,
}

impl RecordRange {
    /// Creates a record range for the next record in `frag`.
    ///
    fn from_frag(frag: &mut Fragment) -> RecordRange {
        // The fragment has been pre-parsed when building the sections,
        // so integer parsing and skipping cannot fail. Unwrapping should
        // be fine.
        let start = frag.range.start;
        frag.skip_name().unwrap();
        let rtype = frag.parse_u16().unwrap();
        let rclass = frag.parse_u16().unwrap();
        frag.skip_bytes(4).unwrap();
        let rdlen = frag.parse_u16().unwrap();
        frag.skip_bytes(rdlen as usize).unwrap();
        RecordRange { range: ops::Range { start: start,
                                          end: frag.range.start },
                      rtype: rtype, rclass: rclass }
    }

    fn skip(frag: &mut Fragment) {
        frag.skip_name().unwrap();
        frag.skip_bytes(8).unwrap();
        let rdlen = frag.parse_u16().unwrap();
        frag.skip_bytes(rdlen as usize).unwrap();
    }
}


/// Foundation for iterators over resource records.
///
pub struct RecordRangeIter<'a> {
    frag: Fragment<'a>,
}

impl<'a> RecordRangeIter<'a> {
    fn from_section(section: &RecordSection<'a>) -> RecordRangeIter<'a> {
        RecordRangeIter { frag: section.frag.clone() }
    }

    fn skip_next(&mut self) -> bool {
        if self.frag.is_empty() { false }
        else { RecordRange::skip(&mut self.frag); true }
    }
}

impl<'a> Iterator for RecordRangeIter<'a> {
    type Item = RecordRange;

    fn next(&mut self) -> Option<RecordRange> {
        if self.frag.is_empty() { None }
        else { Some(RecordRange::from_frag(&mut self.frag)) }
    }

}


//------------ Concrete Resource Record -------------------------------------

/// A parsed resource record of a given record type.
///
#[derive(Clone, Debug)]
pub struct Record<R: RecordData> {
    /// The name of the node to which to record pertains.
    pub name: DomainNameBuf,

    /// The record type in its integer form.
    ///
    pub rtype: u16,

    /// The record's class in its integer form.
    ///
    pub rclass: u16,

    /// The number of seconds this resource record may be cached.
    ///
    pub ttl: u32,

    /// The data of the record.
    ///
    pub data: R
}

impl<R: RecordData> Record<R> {
    /// Creates a record from a fragment and a record range.
    ///
    /// Since this includes of the name and data fields, returns a result.
    ///
    fn from_range(frag: &Fragment, range: RecordRange) -> Result<Record<R>> {
        let mut frag = Fragment::from_range(frag.buf, &range.range);
        let name = try!(frag.parse_name());
        try!(frag.skip_u16());
        let rclass = try!(frag.parse_u16());
        let ttl = try!(frag.parse_u32());
        try!(frag.skip_u16());
        let data = try!(R::from_fragment(&mut frag));
        Ok(Record { name: name, rtype: range.rtype, rclass: rclass, ttl: ttl,
                    data: data } )
    }
}


/// An iterator over the resource records of a given type.
///
/// Iterates over all records in the section that have a type matching `R`.
/// If parsing a record's name or data fails, skips this record without
/// any indication of error.
///
/// Because of this feature, all iterator methods that skip over elements
/// (such as `count()` or `nth()`) have to parse records, too, making them
/// more expensive. Use this iterator only for looping or collecting.
///
pub struct RecordIter<'a, R: RecordData> {
    base: RecordRangeIter<'a>,
    record_type: PhantomData<R>,
}

impl<'a, R: RecordData> RecordIter<'a, R> {
    fn from_section(section: &RecordSection<'a>) -> RecordIter<'a, R> {
        RecordIter { base: RecordRangeIter::from_section(section),
                           record_type: PhantomData }
    }
}

impl<'a, R: RecordData> Iterator for RecordIter<'a, R> {
    type Item = Record<R>;

    fn next(&mut self) -> Option<Record<R>> {
        loop {
            match self.base.next() {
                None => return None,
                Some(range) => {
                    if range.rtype == R::rtype() {
                        match Record::from_range(&self.base.frag, range) {
                            Ok(res) => return Some(res),
                            _ => { }
                        }
                    }
                },
            }
        }
    }
}


/// A strict iterator over the resource records of a given type.
///
/// Iterates over all records in a section that have a type matching `R`.
/// If parsing a record's name or data fails, returns an error for this
/// record.
///
pub struct StrictRecordIter<'a, R: RecordData> {
    base: RecordRangeIter<'a>,
    record_type: PhantomData<R>,
}

impl<'a, R: RecordData> StrictRecordIter<'a, R> {
    fn from_section(section: &RecordSection<'a>) -> StrictRecordIter<'a, R> {
        StrictRecordIter { base: RecordRangeIter::from_section(section),
                           record_type: PhantomData }
    }

    fn next_range(&mut self) -> Option<RecordRange> {
        loop {
            match self.base.next() {
                Some(ref range) if range.rtype != R::rtype() => (),
                x @ _ => return x
            }
        }
    }
}

impl<'a, R: RecordData> Iterator for StrictRecordIter<'a, R> {
    type Item = Result<Record<R>>;

    fn next(&mut self) -> Option<Result<Record<R>>> {
        self.next_range().map(|x| Record::from_range(&self.base.frag, x))
    }

    fn count(self) -> usize {
        self.base.filter(|x| x.rtype == R::rtype()).count()
    }

    fn last(mut self) -> Option<Result<Record<R>>> {
        let mut last = None;
        loop {
            match self.next_range() {
                None => break,
                x @ _ => last = x
            }
        }
        last.map(|x| Record::from_range(&self.base.frag, x))
    }

    fn nth(&mut self, n: usize) -> Option<Result<Record<R>>> {
        for _ in 0 .. n {
            if self.next_range().is_none() { return None }
        }
        self.next()
    }
}


//------------ Iterating over a RRSet ---------------------------------------

/// An iterator over the record data of a given resource record set.
///
pub struct RRSetIter<'a, R: RecordData> {
    base: RecordRangeIter<'a>,
    name: &'a DomainName,
    rclass: u16,
    record_type: PhantomData<R>,
}

impl<'a, R: RecordData> RRSetIter<'a, R> {
    fn from_section(section: &RecordSection<'a>, name: &'a DomainName,
                    rclass: u16) -> RRSetIter<'a, R>
    {
        RRSetIter { base: RecordRangeIter::from_section(section),
                    name: name, rclass: rclass,
                     record_type: PhantomData }
    }
}

impl<'a, R: RecordData> Iterator for RRSetIter<'a, R> {
    type Item = R;

    fn next(&mut self) -> Option<R> {
        loop {
            if self.base.frag.is_empty() { return None }
            else if !self.base.frag.name_eq(self.name) {
                self.base.skip_next();
            }
            else {
                let range = self.base.next().unwrap();
                if range.rtype == R::rtype() && range.rclass == self.rclass {
                    match rdata_from_range(&self.base.frag, range) {
                        Ok(res) => return Some(res),
                        _ => { }
                    }
                }
            }
        }
    }
}


/// An iterator over the record data of a given resource record set.
///
pub struct StrictRRSetIter<'a, R: RecordData> {
    base: RecordRangeIter<'a>,
    name: &'a DomainName,
    rclass: u16,
    record_type: PhantomData<R>,
}


impl<'a, R: RecordData> StrictRRSetIter<'a, R> {
    fn from_section(section: &RecordSection<'a>, name: &'a DomainName,
                    rclass: u16) -> StrictRRSetIter<'a, R>
    {
        StrictRRSetIter { base: RecordRangeIter::from_section(section),
                    name: name, rclass: rclass,
                     record_type: PhantomData }
    }

    fn next_range(&mut self) -> Option<RecordRange> {
        loop {
            if self.base.frag.is_empty() { return None }
            if self.base.frag.name_eq(self.name) {
                let range = self.base.next().unwrap();
                if range.rtype == R::rtype() && range.rclass == self.rclass {
                    return Some(range)
                }
            }
            else {
                self.base.skip_next();
            }
        }
    }
}

impl<'a, R: RecordData> Iterator for StrictRRSetIter<'a, R> {
    type Item = Result<R>;

    fn next(&mut self) -> Option<Result<R>> {
        self.next_range().map(|x| rdata_from_range(&self.base.frag, x))
    }

    fn count(mut self) -> usize {
        let mut res = 0;
        while self.next_range().is_some() { res += 1 }
        res
    }

    fn last(mut self) -> Option<Result<R>> {
        let mut last = None;
        loop {
            match self.next_range() {
                None => break,
                x @ _ => last = x
            }
        }
        last.map(|x| rdata_from_range(&self.base.frag, x))
    }

    fn nth(&mut self, n: usize) -> Option<Result<R>> {
        for _ in 0 .. n {
            if self.next_range().is_none() { return None }
        }
        self.next()
    }
}

fn rdata_from_range<R: RecordData>(frag: &Fragment, r: RecordRange)
    -> Result<R>
{
    let mut frag = Fragment::from_range(frag.buf, &r.range);
    try!(frag.skip_name());
    try!(frag.skip_bytes(10));
    R::from_fragment(&mut frag)
}

//------------ Resource Record Information ----------------------------------

/// Information about a resource record.
///
#[derive(Clone, Debug)]
pub struct RecordInfo {
    pub name: DomainNameBuf,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    data_range: ops::Range<usize>,
}

impl RecordInfo {
    fn from_range(frag: &Fragment, range: RecordRange)
        -> Result<RecordInfo>
    {
        let mut frag = Fragment::from_range(frag.buf, &range.range);
        let name = try!(frag.parse_name());
        try!(frag.skip_u16());
        let rclass = try!(frag.parse_u16());
        let ttl = try!(frag.parse_u32());
        try!(frag.skip_u16());
        Ok(RecordInfo { name: name, rtype: range.rtype, rclass: rclass,
                        ttl: ttl, data_range: frag.range })
    }
}


/// An iterator over the resource record information.
///
pub struct RecordInfoIter<'a> {
    base: RecordRangeIter<'a>,
}

impl<'a> RecordInfoIter<'a> {
    fn from_section(section: &RecordSection<'a>) -> RecordInfoIter<'a> {
        RecordInfoIter { base: RecordRangeIter::from_section(section) }
    }

    fn next_range(&mut self) -> Option<RecordRange> {
        self.base.next()
    }
}

impl<'a> iter::Iterator for RecordInfoIter<'a> {
    type Item = Result<RecordInfo>;

    fn next(&mut self) -> Option<Result<RecordInfo>> {
        self.next_range().map(|x| RecordInfo::from_range(&self.base.frag, x))
    }

    fn count(self) -> usize {
        self.base.count()
    }

    fn last(self) -> Option<Result<RecordInfo>> {
        let frag = self.base.frag.clone();
        self.base.last().map(|x| RecordInfo::from_range(&frag, x))
    }

    fn nth(&mut self, n: usize) -> Option<Result<RecordInfo>> {
        self.base.nth(n).map(|x| RecordInfo::from_range(&self.base.frag, x))
    }
}


//------------ Helpers ------------------------------------------------------

fn read_u16<R: io::Read>(s: &mut R) -> io::Result<u16> {
    let mut buf = [0; 2];

    try!(read_exact(s, &mut buf));
    Ok(u16::from_be(unsafe { *(buf.as_ptr() as *const u16)}))
}

// XXX std::io::Read::read_exact() unstable 
//
fn read_exact<R: io::Read>(s: &mut R, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match s.read(buf) {
            Ok(0) => break,
            Ok(n) => { let tmp = buf; buf = &mut tmp[n..]; }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    if !buf.is_empty() {
        Err(io::Error::new(io::ErrorKind::InvalidData,
                       "failed to fill whole buffer"))
    } else {
        Ok(())
    }
}


//------------ Tests -----------------------------------------------------

#[cfg(test)]
#[macro_use]
mod tests {
    use std::net::Ipv4Addr;
    use super::*;
    use super::super::record;

    fn make_data() -> Vec<u8> {
        b"\xd3\x88\x81\x80\x00\x01\x00\x01\x00\x04\x00\x04\x06github\x03com\
          \x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x14\
         \x00\x04\xc0\x1e\xfc\x80\xc0\x0c\x00\x02\x00\x01\x00\x00\xf7\
         \xd9\x00\x14\x03ns3\x03p16\x06dynect\x03net\x00\xc0\x0c\x00\
         \x02\x00\x01\x00\x00\xf7\xd9\x00\x06\x03ns1\xc0<\xc0\x0c\x00\
         \x02\x00\x01\x00\x00\xf7\xd9\x00\x06\x03ns2\xc0<\xc0\x0c\x00\
         \x02\x00\x01\x00\x00\xf7\xd9\x00\x06\x03ns4\xc0<\xc0X\x00\x01\
         \x00\x01\x00\x01\x10\xe9\x00\x04\xd0NF\x10\xc0j\x00\x01\x00\x01\
         \x00\x01\x00w\x00\x04\xcc\x0d\xfa\x10\xc08\x00\x01\x00\x01\x00\
         \x01#A\x00\x04\xd0NG\x10\xc0|\x00\x01\x00\x01\x00\x00\xf9\x93\
         \x00\x04\xcc\x0d\xfb\x10".to_vec()
    }

    #[test]
    fn test_from_vec() {
        let res = Message::from_vec(make_data()).unwrap();
        /*
        for q in res.question().iter() { println!("{:?}", q) }
        for rr in res.answer().iter::<record::A>() { println!("{:?}", rr) }
        for rr in res.authority().iter::<record::NS>() { println!("{:?}", rr) }
        for rr in res.additional().iter_info() { println!("{:?}", rr) }
        */
        let mut rdata: Vec<record::A> =
            res.additional().rrset::<record::A>(&dname!("ns4", "p16", "dynect",
                                                        "net", ""), 1)
                .collect();
        assert_eq!(rdata.len(), 1);
        assert_eq!(rdata.pop().unwrap().addr,
                   Ipv4Addr::new(204,13,251,16));
    }
}
