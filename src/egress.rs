//! Construction of DNS messages for sending
//!

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net;
use std::ptr;
use super::header::Header;
use super::name;
use super::record::{RecordData, RecordDataAssembly};

//------------ Assembly -----------------------------------------------------

/// A type to assemble an outgoing DNS message.
///
/// When assembling messages you sadly need to know what is going on later
/// or come back to parts written earlier. The Assembly type does exactly
/// that.
///
/// Use this type directly if you already know what to put into the message
/// before starting to create it. Otherwise, use `Message` which allows you
/// put things together step by step.
///
#[derive(Debug)]
pub struct Assembly {
    // The message's data.
    inner: Vec<u8>,

    // If we are writing to a stream, the message actually starts with two
    // octets for the length, but references for name pointers and such
    // are relative to after that. To make the math easier, we simply keep
    // the index of the real start of the message in here.
    origin: usize,

    // Maximum size of the resulting package (and thus, `self.inner`).
    //
    // This is limited to 65535 due either to the maximum UDP datagram
    // size or the 16 bit length marker in a stream. We still use usize
    // here because with origin we can overrun the 16 bit boundary.
    maxlen: usize,

    // If we overrun our maxlen while writing, we set this flag. The
    // higher level methods know what to do in this case.
    tc: bool,

    // We need a copy of the header because we may have to modify the
    // tc bit when we are done.
    header: Header,

    // If we do compression, then we will store labels in this here map.
    // If we don't do compression, there is no map.
    compress: Option<HashMap<name::DomainNameBuf, u16>>,
}

// Management
//
impl Assembly {

    /// Creates a new assembly.
    ///
    /// The maximum package size is given in `maxlen`. If more data is
    /// pushed to the assembly, it will be truncated at a record boundary
    /// and the TC bit will be set in the header.
    ///
    /// If the assembly is for a stream, set `for_stream` to true. In this
    /// case the first two octets of the resulting data will be the size
    /// of the message in network order.
    ///
    /// Set `compress` to false, if you want domain names never to be
    /// compressed.
    ///
    pub fn new(maxlen: u16, for_stream: bool, compress: bool) -> Assembly {
        let map = match compress {
            true => Some(HashMap::new()),
            false => None
        };
        if for_stream {
            let mut res = Assembly { inner: Vec::new(),
                                     maxlen: (maxlen as usize) + 2,
                                     origin: 2, tc: false,
                                     header: Header::new(),
                                     compress: map };
            res.push_u16(0);
            res
        }
        else {
            Assembly { inner: Vec::new(), maxlen: maxlen as usize, origin: 0,
                       tc: false, header: Header::new(), compress: map }
        }
    }
}

// Low level writing -- use this in record data implementations.
//
impl Assembly {

    /// Pushes a u8 to the end of the assembly.
    ///
    pub fn push_u8(&mut self, data: u8) {
        if self.keep_pushing(1) {
            self.inner.push(data)
        }
    }

    /// Pushes a u16 to the end of the assembly.
    ///
    pub fn push_u16(&mut self, data: u16) {
        if self.keep_pushing(2) {
            let data = data.to_be();
            let bytes: [u8; 2] = unsafe { mem::transmute(data) };
            self.inner.extend(&bytes);
        }
    }

    /// Pushes a u32 to the end of the assembly.
    ///
    pub fn push_u32(&mut self, data: u32) {
        if self.keep_pushing(4) {
            let data = data.to_be();
            let bytes: [u8; 4] = unsafe { mem::transmute(data) };
            self.inner.extend(&bytes);
        }
    }

    /// Pushes `data` to the end of the assembly.
    ///
    pub fn push_bytes(&mut self, data: &[u8]) {
        if self.keep_pushing(data.len()) {
            self.inner.extend(data);
        }
    }

    /// Pushes a domain name to the end of the assembly.
    ///
    /// The domain name will not be compressed, even if compression is
    /// enabled for the assembly. This is the default because RFC 3597
    /// limits name compression to those record types intially defined in
    /// RFC 1035. So, if you implement a `RecordDataAssembly`, you likely
    /// want to use uncompressed name pushage.
    ///
    pub fn push_name(&mut self, name: &name::DomainName) {
        assert!(!name.is_empty());

        if self.compress.is_none() {
            self._push_name_simple(name);
        }
        else {
            self._push_name_uncompressed(name);
        }
    }

    /// Pushes a domain name to the end of the assembly employing compression.
    ///
    /// This is similar to `push_name()` except that name compression will
    /// be used if it has been enabled for the assembly.
    ///
    pub fn push_name_compressed(&mut self, name: &name::DomainName) {
        assert!(!name.is_empty());

        if self.compress.is_none() {
            self._push_name_simple(name);
        }
        else {
            self._push_name_compressed(name);
        }
    }

    // Simply pushes `name`'s bytes. Luckily, our internal domain name
    // encoding is actually the wire format. Smart, huh?!
    fn _push_name_simple(&mut self, name: &name::DomainName) {
        if self.keep_pushing(name.as_bytes().len()) {
            self.push_bytes(name.as_bytes());
        }
    }

    // Pushes `name` storing the label positions for later referencing
    // if compression is enabled.
    fn _push_name_uncompressed(&mut self, name: &name::DomainName) {
        let mut name = name;
        while !name.is_empty() {
            name = self._push_label(name);
        }
    }

    // Pushes `name`, using a reference for the longest known tail.
    fn _push_name_compressed(&mut self, name: &name::DomainName) {
        let mut name = name;
        while !name.is_empty() {
            let pos;
            {
                pos = match self.compress {
                    None => None,
                    Some(ref map) => {
                        match map.get(name) {
                            None => None,
                            Some(&pos) => Some(pos)
                        }
                    }
                }
            }
            match pos {
                None => name = self._push_label(name),
                Some(pos) => {
                    if self.keep_pushing(2) {
                        self.push_u16(pos | 0xC000);
                    }
                    return
                }
            }
        }
    }

    // Pushes the first label in `name`, store a reference to `name` for
    // later use in compression.
    fn _push_label<'a>(&mut self, name: &'a name::DomainName)
        -> &'a name::DomainName
    {
        let pos = self.pos();
        match self.compress {
            None => { },
            Some(ref mut map) => {
                map.insert(name.to_owned(), (pos - self.origin) as u16);
            }
        }
        let (head, tail) = name.split_first().unwrap();
        assert!(head.len() < 64);
        if self.keep_pushing(head.as_bytes().len() + 1) {
            self.push_u8(head.len() as u8);
            self.push_bytes(head.as_bytes());
        }
        tail
    }

    // Returns whether it is fine to push `len` octets.
    //
    fn keep_pushing(&mut self, len: usize) -> bool {
        if self.inner.len() + len > self.maxlen {
            self.tc = true;
            false
        }
        else { true }
    }

    /// Returns the current position of the assembly.
    ///
    /// You must use the returned position for later use in the replace
    /// methods only. Do not assign any other meaning to it.
    ///
    pub fn pos(&self) -> usize {
        self.inner.len()
    }

    /// Replaces the u8 at position `pos` with `data`.
    ///
    pub fn replace_u8(&mut self, pos: usize, data: u8) {
        assert!(pos < self.inner.len());
        self.inner[pos] = data;
    }

    /// Replaces the u16 beginning at position `pos` with `data`.
    ///
    pub fn replace_u16(&mut self, pos: usize, data: u16) {
        let data = data.to_be();
        assert!(pos + 1 < self.inner.len());
        unsafe {
            let src: [u8; 2] = mem::transmute(data);
            ptr::copy_nonoverlapping(&src.as_ptr(),
                                     &mut self.inner[pos .. pos + 2].as_ptr(),
                                     2);
        }
    }

    /// Replaces the u32 beginning at position `pos` with `data`.
    ///
    pub fn replace_u32(&mut self, pos: usize, data: u32) {
        let data = data.to_be();
        assert!(pos + 1 < self.inner.len());
        unsafe {
            let src: [u8; 4] = mem::transmute(data);
            ptr::copy_nonoverlapping(&src.as_ptr(),
                                     &mut self.inner[pos .. pos + 4].as_ptr(),
                                     4);
        }
    }
}

// High-level writing
//
impl Assembly {
    /// Pushes the message header to the assembly.
    ///
    /// A call to this method must be the first thing on a new assembly.
    /// Later there must not be any more calls to it on threat of a panic.
    ///
    /// The arguments are the actual header, followed by the number of
    /// elements in each seection. You must follow up this call with the
    /// correct number of calls to `push_question()` and `push_rr()` or
    /// `push_raw_rr()`. Finally, you must finish with calling `finish()`.
    ///
    pub fn push_header(&mut self, header: &Header, qdcount: u16, ancount: u16,
                       nscount: u16, arcount: u16)
    {
        assert!(self.pos() == self.origin);
        self.header = header.clone();
        self.header.set_tc(false);
        let header_bytes = self.header.as_u32();
        self.push_u32(header_bytes);
        self.push_u16(qdcount);
        self.push_u16(ancount);
        self.push_u16(nscount);
        self.push_u16(arcount);
    }

    /// Finishes the assembly.
    ///
    /// This must be the last thing you do with the assembly. To make this
    /// clear, the method moves the inner vec back to the caller. This
    /// returned vec can be sent over the wire as is.
    ///
    pub fn finish(mut self) -> Vec<u8> {
        if self.origin == 2 {
            let len = (self.inner.len() - self.origin) as u16;
            self.replace_u16(0, len);
        }
        if self.tc {
            self.header.set_tc(true);
            let pos = self.origin;
            let header_bytes = self.header.as_u32();
            self.replace_u32(pos, header_bytes);
        }
        self.inner
    }

    /// Pushes a question to the assembly.
    ///
    /// If doing so would exceed the maximum length, nothing will be
    /// written, the TC bit will be set in the header later, and false
    /// will be returned now.
    ///
    /// If all goes well, true will be returned.
    ///
    pub fn push_question(&mut self, qname: &name::DomainName, qtype: u16,
                         qclass: u16) -> bool
    {
        if self.tc { return false }
        let pos = self.pos();
        self.push_name_compressed(qname);
        self.push_u16(qtype);
        self.push_u16(qclass);
        if self.tc {
            self.inner.truncate(pos);
        }
        !self.tc
    }

    /// Pushes a raw resource record to the assembly.
    ///
    /// For our purposes, a raw resource record is one for which the type
    /// is explicitely given and record data is already given in its wire
    /// format.
    ///
    /// Returns true if the entire record could be pushed to the assembly.
    /// If this would exceed the maximum length, nothing is pushed at all
    /// and false is returned. Upon finishing the assembly, the TC bit will
    /// be set in the header.
    ///
    pub fn push_raw_rr(&mut self, name: &name::DomainName, rtype: u16,
                       rclass: u16, ttl: u32, rdata: &[u8]) -> bool
    {
        assert!(rdata.len() <= ::std::u16::MAX as usize); 
        if self.tc { return false }
        let pos = self.pos();
        self.push_name_compressed(name);
        self.push_u16(rtype);
        self.push_u16(rclass);
        self.push_u32(ttl);
        self.push_u16(rdata.len() as u16);
        self.push_bytes(rdata);
        if self.tc {
            self.inner.truncate(pos);
        }
        !self.tc
    }

    /// Pushes a resource record to the assembly.
    ///
    /// The record data is being assembled by calling `assembly()` on the
    /// trait object `rdata`. If pushing
    /// the record would exceed the maximum length, it is removed again and
    /// the TC bit will later be set in the header when the assembly is
    /// being finished. The method returns whether this did not happen.
    ///
    pub fn push_rr(&mut self, name: &name::DomainName, rtype: u16,
                                      rclass: u16, ttl: u32,
                                      rdata: &RecordDataAssembly) -> bool
    {
        if self.tc { return false }
        let pos = self.pos();
        self.push_name_compressed(name);
        self.push_u16(rtype);
        self.push_u16(rclass);
        self.push_u32(ttl);
        let rdlen_pos = self.pos();
        self.push_u16(0);
        rdata.assemble(self);
        if self.tc {
            self.inner.truncate(pos);
        }
        else {
            let rdlen = self.pos() - rdlen_pos;
            self.replace_u16(rdlen_pos, rdlen as u16);
        }
        !self.tc
    }

}

//------------ Message ------------------------------------------------------

/// An outgoing DNS message.
///
/// The message consists of four sections that are vecs over questions or
/// resource records, keeping their own data.
///
/// Once you have all data collected, you can have the actual wire data
/// assembled or even sent out directly.
///
#[derive(Debug)]
pub struct Message {
    header: Header, 
    question: QuestionSection,
    answer: RecordSection,
    authority: RecordSection,
    additional: RecordSection
}

impl Message {
    /// Creates a new, empty message.
    ///
    pub fn new() -> Message {
        Message { header: Header::new(), question: QuestionSection::new(),
                  answer: RecordSection::new(),
                  authority: RecordSection::new(),
                  additional: RecordSection::new() }
    }

    /// Gives access to the message header.
    ///
    pub fn header(&mut self) -> &mut Header {
        &mut self.header
    }

    /// Gives access to the question section.
    ///
    /// The question section contains the question being asked in a query.
    ///
    pub fn question(&mut self) -> &mut QuestionSection {
        &mut self.question
    }

    /// Gives access to the zone section of an Update query.
    ///
    /// In an update query, the question section is actually the zone
    /// section specifing the zone to be updated.
    ///
    pub fn zone(&mut self) -> &mut QuestionSection {
        &mut self.question
    }

    /// Gives access to the answer section.
    ///
    /// The answer sections contains those resource records that answer
    /// the question.
    ///
    /// In an Update query, this 
    ///
    pub fn answer(&mut self) -> &mut RecordSection {
        &mut self.answer
    }

    /// Gives access to the prerequiste section of an Update query.
    ///
    /// The prerequisite section contains resource records or resource
    /// record sets that must or must not preexist.
    ///
    pub fn prerequisite(&mut self) -> &mut RecordSection {
        &mut self.answer
    }

    /// Gives access to the authority section.
    ///
    /// The authority section contains resource records identifying the
    /// authoritative name servers responsible for answering the question.
    ///
    pub fn authority(&mut self) -> &mut RecordSection {
        &mut self.authority
    }

    /// Gives access to the update section of an Update query.
    ///
    /// The update section contains resource records or resource record
    /// sets to be added or delete.
    ///
    pub fn update(&mut self) -> &mut RecordSection {
        &mut self.authority
    }

    /// Gives access to the additional section.
    ///
    /// The additional section contains resource records that help making
    /// sense of the answer. What exactly ought to be in here depends on
    /// the record type being asked for.
    ///
    pub fn additional(&mut self) -> &mut RecordSection {
        &mut self.additional
    }

    //--- Finish it off ...
    
    /// Assembles the message.
    ///
    /// Returns a vector containing the wire data of the message and whether
    /// the wire message had to be truncated because it would have been
    /// longer than `maxlen`.
    ///
    /// If you plan on writing the data into a stream, such as a
    /// `TcpStream`, set `for_stream` to true. In this case, the resulting
    /// data will start with the required length indication. If you wish
    /// domain names to be compressed where applicable, set `compress` to
    /// true.
    pub fn assemble(&self, maxlen: u16, for_stream: bool, compress: bool)
        -> (Vec<u8>, bool)
    {
        let mut asm = Assembly::new(maxlen, for_stream, compress);
        asm.push_header(&self.header, self.question.len(),
                        self.answer.len(), self.authority.len(),
                        self.additional.len());
        let complete =  self.question.assemble(&mut asm)
                     && self.answer.assemble(&mut asm)
                     && self.authority.assemble(&mut asm)
                     && self.additional.assemble(&mut asm);
        (asm.finish(), complete)
    }

    pub fn to_udp<A: net::ToSocketAddrs>(&self, sock: &net::UdpSocket,
                                         addr: A, maxlen: u16, compress: bool)
        -> io::Result<(usize, bool)>
    {
        let (vec, complete) = self.assemble(maxlen, false, compress);
        sock.send_to(&vec, addr).map(|x| (x, complete))
    }

    pub fn to_writer<W: io::Write>(&self, w: &mut W, compress: bool)
        -> io::Result<(usize, bool)>
    {
        let (vec, complete) = self.assemble(::std::u16::MAX, true, compress);
        w.write(&vec).map(|x| (x, complete))
    }
}


//------------ QuestionSection ----------------------------------------------

#[derive(Debug)]
struct Question {
    qname: name::DomainNameBuf,
    qtype: u16,
    qclass: u16,
}


/// Collects the questions for a message.
///
#[derive(Debug)]
pub struct QuestionSection {
    inner: Vec<Question>,
}

impl QuestionSection {
    fn new() -> QuestionSection {
        QuestionSection { inner: Vec::new() }
    }

    /// Adds a questions.
    ///
    pub fn push(&mut self, qname: name::DomainNameBuf, qtype: u16,
                qclass: u16)
    {
        assert!(self.inner.len() < ::std::u16::MAX as usize);
        self.inner.push(Question { qname: qname, qtype: qtype,
                                   qclass: qclass })
    }

    /// Returns the length of the question section.
    ///
    pub fn len(&self) -> u16 {
        self.inner.len() as u16
    }

    fn assemble(&self, asm: &mut Assembly) -> bool {
        for q in self.inner.iter() {
            if !asm.push_question(&q.qname, q.qtype, q.qclass) {
                return false
            }
        }
        true
    }
}


//------------ RecordSection ------------------------------------------------

#[derive(Debug)]
struct Record {
    name: name::DomainNameBuf,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: Box<RecordDataAssembly>
}


/// Collects the resource records of one of the three record sections.
///
#[derive(Debug)]
pub struct RecordSection {
    inner: Vec<Record>,
}

impl RecordSection {
    fn new() -> RecordSection {
        RecordSection { inner: Vec::new() }
    }

    pub fn push<R: RecordData + 'static>(&mut self, name: name::DomainNameBuf,
                                         rclass: u16, ttl: u32,
                                         data: R)
    {
        self.inner.push(Record { name: name, rtype: R::rtype(),
                                 rclass: rclass, ttl: ttl,
                                 rdata: Box::new(data) })
    }

    /// Returns the number of records in the section.
    ///
    pub fn len(&self) -> u16 {
        self.inner.len() as u16
    }

    fn assemble(&self, asm: &mut Assembly) -> bool {
        for rr in self.inner.iter() {
            if !asm.push_rr(&rr.name, rr.rtype, rr.rclass, rr.ttl, &*rr.rdata)
            {
                return false
            }
        }
        true
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {

    #[test]
    fn test_it() {
    }
}
