//! Handling of incoming DNS messages
//!

use std::io;
use std::iter;
use std::marker::PhantomData;
use std::net;
use std::ops;
use super::error::{Error, Result};
use super::header::Header;
use super::name::{self, DomainNameBuf};
use super::record::RecordData;


//------------ Message ------------------------------------------------------

/// An incoming DNS message.
///
/// The message owns the raw data. You can either create it a raw vec or
/// by reading it directly out of a socket or reader.
///
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
        self.question = try!(SectionSpec::from_rrcount(&mut frag, qdcount));
        self.answer = try!(SectionSpec::from_rrcount(&mut frag, ancount));
        self.authority = try!(SectionSpec::from_rrcount(&mut frag, nscount));
        self.additional = try!(SectionSpec::from_rrcount(&mut frag, arcount));
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

    pub fn question(&self) -> Section {
        Section::from_spec(self, &self.question)
    }

    pub fn answer(&self) -> Section {
        Section::from_spec(self, &self.answer)
    }

    pub fn authority(&self) -> Section {
        Section::from_spec(self, &self.authority)
    }

    pub fn additional(&self) -> Section {
        Section::from_spec(self, &self.additional)
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
        if self.range.end + len < self.buf.len() { Err(Error::ShortFragment) }
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

    pub fn parse_name(&mut self) -> Result<DomainNameBuf> {
        // TODO
        try!(self.skip_name());
        Ok(DomainNameBuf::new())
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

    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }

    pub fn is_empty(&self) -> bool {
        self.range.end == self.range.start
    }
}


//------------ SectionSpec --------------------------------------------------

#[derive(Clone)]
struct SectionSpec {
    range: ops::Range<usize>,
    rrcount: u16,
}

impl SectionSpec {
    fn new() -> SectionSpec {
        SectionSpec { range: ops::Range { start: 0, end: 0 }, rrcount: 0 }
    }

    fn from_values(start: usize, end: usize, rrcount: u16) -> SectionSpec {
        SectionSpec { range: ops::Range { start: start, end: end },
                      rrcount: rrcount }
    }

    fn from_rrcount(frag: &mut Fragment, rrcount: u16)
        -> Result<SectionSpec>
    {
        let start = frag.range.start;
        for _ in 0..rrcount {
            try!(frag.skip_name());
            try!(frag.skip_bytes(8));
            let rdlen = try!(frag.parse_u16()) as usize;
            try!(frag.skip_bytes(rdlen));
        }
        Ok(SectionSpec::from_values(start, frag.range.start, rrcount))
    }

}


//------------ Section ------------------------------------------------------

pub struct Section<'a> {
    frag: Fragment<'a>,
}

impl<'a> Section<'a> {
    fn from_spec(msg: &'a Message, spec: &SectionSpec) -> Section<'a> {
        Section { frag: Fragment::from_range(&msg.buf, &spec.range) }
                  
    }

    pub fn iter<R: RecordData>(&mut self) -> RecordIter<'a, R> {
        RecordIter::from_section(self)
    }

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
pub struct RecordRange {
    range: ops::Range<usize>,
    rtype: u16,
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
        frag.skip_bytes(6).unwrap();
        let rdlen = frag.parse_u16().unwrap();
        frag.skip_bytes(rdlen as usize).unwrap();
        RecordRange { range: ops::Range { start: start,
                                          end: frag.range.start },
                      rtype: rtype }
    }
}


/// Foundation for iterators over resource records.
///
pub struct RecordRangeIter<'a> {
    frag: Fragment<'a>,
}

impl<'a> RecordRangeIter<'a> {
    fn from_section(section: &Section<'a>) -> RecordRangeIter<'a> {
        RecordRangeIter { frag: section.frag.clone() }
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
/// Iterates over all records in a section that have a type matching `R`.
/// The iterator creates (and therefore parses) the records on the fly.
/// Since this may fail, it returns a result, which, admittedly, is a little
/// awkward.
///
pub struct RecordIter<'a, R: RecordData> {
    base: RecordRangeIter<'a>,
    record_type: PhantomData<R>,
}

impl<'a, R: RecordData> RecordIter<'a, R> {
    fn from_section(section: &Section<'a>) -> RecordIter<'a, R> {
        RecordIter { base: RecordRangeIter::from_section(section),
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

impl<'a, R: RecordData> Iterator for RecordIter<'a, R> {
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


//------------ Resource Record Information ----------------------------------

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


pub struct RecordInfoIter<'a> {
    base: RecordRangeIter<'a>,
}

impl<'a> RecordInfoIter<'a> {
    fn from_section(section: &Section<'a>) -> RecordInfoIter<'a> {
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
mod tests {
    use super::*;

}
