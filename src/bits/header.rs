//! The header of a DNS message.
//!
//! The message header has been split into two parts represented by two
//! separate types: `Header` contains the first 32 bits with the ID,
//! opcode, response code, and the various flags, while `HeaderCounts`
//! contains the item counts for the four message sections. A `FullHeader`
//! type is available that combines the two.
//!
//! The split has been done to reflect that when building a message you
//! should be able to freely manipulate the former part whereas the counts
//! should be set in accordance with the actual items in the message as it
//! is built.
//!

use std::mem;
use iana::{Opcode, Rcode};
use super::error::{ComposeError, ComposeResult};


//------------ Header --------------------------------------------------

/// The first part of the header of a DNS message.
///
/// This type represents the information contained in the first four bytes of
/// the header: the message ID, opcode, rcode, and the various flags.
///
/// The header is layed out like this:
///
/// ```text
///                                 1  1  1  1  1  1
///   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      ID                       |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |QR|   Opcode  |AA|TC|RD|RA|Z |AD|CD|   RCODE   |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// Most of this is defined in RFC 1035, except for the AD and CD flags,
/// which are defined in RFC 4035.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Header {
    /// The actual header in its wire format representation.
    ///
    /// This means that data is in big endian.
    inner: [u8; 4]
}

/// # Creation and Conversion
///
impl Header {
    /// Creates a new header.
    ///
    /// The new header has all fields as either zero or false. Thus, the
    /// opcode will be `Opcode::Query` and the response code will be
    /// `Rcode::NoError`.
    ///
    pub fn new() -> Header {
        Header { inner: [0; 4] }
    }

    /// Creates a header reference from a bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message(s: &[u8]) -> &Header {
        &*(s.as_ptr() as *const Header)
    }

    /// Creates a mutable header reference from a bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message_mut(s: &mut [u8]) -> &mut Header {
        &mut *(s.as_ptr() as *mut Header)
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}


/// # Field Access
///
impl Header {
    /// Returns the ID field.
    ///
    /// The ID field is an identifier chosen by whoever created a query
    /// and is copied into a response.
    pub fn id(&self) -> u16 { self.get_u16(0) }

    /// Sets the ID field.
    pub fn set_id(&mut self, value: u16) { self.set_u16(0, value) }

    /// Sets the ID field to a randomly chosen number.
    pub fn set_random_id(&mut self) { self.set_id(::rand::random()) }

    /// Returns the value of the QR bit.
    ///
    /// The QR bit specifies whether this message is a query (`false`) or
    /// a response (`true`). In other words, this bit is actually stating
    /// whether the message is *not* a query.
    pub fn qr(&self) -> bool { self.get_bit(2, 7) }

    /// Sets the value of the QR bit.
    ///
    pub fn set_qr(&mut self, set: bool) { self.set_bit(2, 7, set) }

    /// Returns the Opcode field.
    ///
    /// This field specifies the kind of query this message contains. See
    /// the `Opcode` type for more information on the possible values and
    /// their meaning.
    pub fn opcode(&self) -> Opcode {
        Opcode::from_int((self.inner[2] >> 3) & 0x0F)
    }

    /// Sets the opcode field.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.inner[2] = self.inner[2] & 0x87 | (opcode.to_int() << 3);
    }

    /// Returns the value of the AA bit.
    ///
    /// Using this field, a name server generating a response states whether
    /// it is authoritative for the requested domain name, ie., whether this
    /// response is a *authoritative answer.* The field has no meaning in 
    /// a query.
    pub fn aa(&self) -> bool { self.get_bit(2, 2) }

    /// Sets the value of the AA bit.
    pub fn set_aa(&mut self, set: bool) { self.set_bit(2, 2, set) }

    /// Returns the value of the TC bit.
    ///
    /// The *truncation* bit is set if there was more data then fit into the
    /// message.
    pub fn tc(&self) -> bool { self.get_bit(2, 1) }

    /// Sets the value of the TC bit.
    pub fn set_tc(&mut self, set: bool) { self.set_bit(2, 1, set) }

    /// Returns the value of the RD bit.
    ///
    /// The *recursion desired* bit may be set in a query to ask the name
    /// server to try and recursively gather a response if it doesn’t have
    /// the data available locally. The bit’s value is copied into the
    /// response.
    pub fn rd(&self) -> bool { self.get_bit(2, 0) }

    /// Sets the value of the RD bit.
    pub fn set_rd(&mut self, set: bool) { self.set_bit(2, 0, set) }

    /// Returns the value of the RA bit.
    ///
    /// In a response, the *recursion available* bit denotes whether the
    /// responding name server supports recursion. It has no meaning in
    /// a query.
    pub fn ra(&self) -> bool { self.get_bit(3, 7) }

    /// Sets the value of the RA bit.
    pub fn set_ra(&mut self, set: bool) { self.set_bit(3, 7, set) }

    /// Returns the value of the reserved bit.
    ///
    /// This bit must be `false` in all queries and responses.
    pub fn z(&self) -> bool { self.get_bit(3, 6) }

    /// Sets the value of the reserved bit.
    pub fn set_z(&mut self, set: bool) { self.set_bit(3, 6, set) }

    /// Returns the value of the AD bit.
    ///
    /// The *authentic data* bit is used by security-aware recursive name
    /// servers to indicate that it considers all RRsets in its response to
    /// be authentic.
    pub fn ad(&self) -> bool { self.get_bit(3, 5) }

    /// Sets the value of the AD bit.
    pub fn set_ad(&mut self, set: bool) { self.set_bit(3, 5, set) }

    /// Returns the value of the CD bit.
    ///
    /// The *checking disabled* bit is used by security-aware resolvers
    /// to indicate that it does not want upstream name servers to perform
    /// verification bit will do all that itself.
    pub fn cd(&self) -> bool { self.get_bit(3, 4) }

    /// Sets the value of the CD bit.
    pub fn set_cd(&mut self, set: bool) { self.set_bit(3, 4, set) }

    /// Returns the RCODE field.
    ///
    /// The *response code* is used in a response to indicate what happened
    /// when processing the query. See the `Rcode` type for information on
    /// possible values and their meaning.
    pub fn rcode(&self) -> Rcode {
        Rcode::from_int(self.inner[3] & 0x0F)
    }

    /// Sets the RCODE field.
    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.inner[3] = self.inner[3] & 0xF0 | (rcode.to_int() & 0x0F);
    }


    //--- Internal helpers
    
    fn get_u16(&self, offset: usize) -> u16 {
        assert!(offset < 11);

        (self.inner[offset] as u16) << 8 | (self.inner[offset + 1] as u16)
    }

    fn set_u16(&mut self, offset: usize, value: u16) {
        assert!(offset < 11);

        self.inner[offset] = (value >> 8) as u8;
        self.inner[offset + 1] = value as u8;
    }

    fn get_bit(&self, offset: usize, bit: usize) -> bool {
        assert!(offset < 12);
        assert!(bit < 8);

        self.inner[offset] & (1 << bit) != 0
    }

    fn set_bit(&mut self, offset: usize, bit: usize, set: bool) {
        if set { self.inner[offset] |= 1 << bit }
        else { self.inner[offset] &= !(1 << bit) }
    }
}


//------------ HeaderCounts -------------------------------------------------

/// The section count part of the header of a DNS message.
///
/// This part consists of four 16 bit counters for the number of entries in
/// the four sections of a DNS message.
///
/// The counters are arranged in the
/// same order as the sections themselves: QDCOUNT for the question section,
/// ANCOUNT for the answer section, NSCOUNT for the authority section, and
/// ARCOUNT for the additional section. These are defined in RFC 1035.
///
/// RFC 2136 defines the UPDATE method and reuses the four section for
/// different purposes. Here the counters are ZOCOUNT for the zone section,
/// PRCOUNT for the prerequisite section, UPCOUNT for the update section,
/// and ADCOUNT for the additional section. The type has convenience methods
/// for these fields as well so you don’t have to remember which is which.
///
/// For each field there are three methods for getting, setting, and
/// incrementing by one.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HeaderCounts {
    inner: [u8; 8]
}

/// # Creation and Conversion
///
impl HeaderCounts {
    /// Creates a new empty counts.
    pub fn new() -> HeaderCounts {
        HeaderCounts { inner: [0; 8] }
    }

    /// Creates a reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message(s: &[u8]) -> &HeaderCounts {
        &*((s[mem::size_of::<Header>()..].as_ptr()) as *const HeaderCounts)
    }

    /// Creates a mutable reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message_mut(s: &mut [u8]) -> &mut HeaderCounts {
        &mut *((s[mem::size_of::<Header>()..].as_ptr()) as *mut HeaderCounts)
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}


/// # Field Access
///
impl HeaderCounts {
    //--- Count fields in regular messages

    /// Returns the QDCOUNT field.
    ///
    /// This field contains the number of questions in the first
    /// section of the message, normally the question section.
    pub fn qdcount(&self) -> u16 {
        self.get_u16(0)
    }

    /// Sets the QDCOUNT field.
    pub fn set_qdcount(&mut self, value: u16) {
        self.set_u16(0, value)
    }

    /// Increase the QDCOUNT field by one.
    pub fn inc_qdcount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(0, inc)
    }

    /// Returns the ANCOUNT field.
    ///
    /// This field contains the number of resource records in the second
    /// section of the message, normally the answer section.
    pub fn ancount(&self) -> u16 {
        self.get_u16(2)
    }

    /// Sets the ANCOUNT field.
    pub fn set_ancount(&mut self, value: u16) {
        self.set_u16(2, value)
    }

    /// Increases the ANCOUNT field.
    pub fn inc_ancount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(2, inc)
    }

    /// Returns the NSCOUNT field.
    ///
    /// This field contains the number of resource records in the third
    /// section of the message, normally the authority section.
    pub fn nscount(&self) -> u16 {
        self.get_u16(4)
    }

    /// Sets the NSCOUNT field.
    pub fn set_nscount(&mut self, value: u16) {
        self.set_u16(4, value)
    }

    /// Increases the NSCOUNT field.
    pub fn inc_nscount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(4, inc)
    }

    /// Returns the ARCOUNT field.
    ///
    /// This field contains the number of resource records in the fourth
    /// section of the message, normally the additional section.
    pub fn arcount(&self) -> u16 {
        self.get_u16(6)
    }

    /// Sets the ARCOUNT field.
    pub fn set_arcount(&mut self, value: u16) {
        self.set_u16(6, value)
    }

    /// Increases the ARCOUNT field.
    pub fn inc_arcount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(6, inc)
    }


    //--- Count fields in UPDATE messages

    /// Returns the ZOCOUNT field.
    ///
    /// This is the same as the `qdcount()`. It is used in UPDATE queries
    /// where the first section is the zone section.
    pub fn zocount(&self) -> u16 {
        self.get_u16(0)
    }

    /// Sets the ZOCOUNT field.
    pub fn set_zocount(&mut self, value: u16) {
        self.set_u16(0, value)
    }

    /// Increments the ZOCOUNT field.
    pub fn inc_zocount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(0, inc)
    }

    /// Returns the PRCOUNT field.
    ///
    /// This is the same as the `ancount()`. It is used in UPDATE queries
    /// where the first section is the prerequisite section.
    pub fn prcount(&self) -> u16 {
        self.get_u16(2)
    }

    /// Sete the PRCOUNT field.
    pub fn set_prcount(&mut self, value: u16) {
        self.set_u16(2, value)
    }

    /// Increments the PRCOUNT field,
    pub fn inc_prcount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(2, inc)
    }

    /// Returns the UPCOUNT field.
    ///
    /// This is the same as the `nscount()`. It is used in UPDATE queries
    /// where the first section is the update section.
    pub fn upcount(&self) -> u16 {
        self.get_u16(4)
    }

    /// Sets the UPCOUNT field.
    pub fn set_upcount(&mut self, value: u16) {
        self.set_u16(4, value)
    }

    /// Increments the UPCOUNT field.
    pub fn inc_upcount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(4, inc)
    }

    /// Returns the ADCOUNT field.
    ///
    /// This is the same as the `arcount()`. It is used in UPDATE queries
    /// where the first section is the additional section.
    pub fn adcount(&self) -> u16 {
        self.get_u16(6)
    }

    /// Sets the ADCOUNT field.
    pub fn set_adcount(&mut self, value: u16) {
        self.set_u16(6, value)
    }

    /// Increments the ADCOUNT field.
    pub fn inc_adcount(&mut self, inc: u16) -> ComposeResult<()> {
        self.inc_u16(6, inc)
    }


    //--- Internal helpers
    
    fn get_u16(&self, offset: usize) -> u16 {
        assert!(offset < 7);

        (self.inner[offset] as u16) << 8 | (self.inner[offset + 1] as u16)
    }

    fn set_u16(&mut self, offset: usize, value: u16) {
        assert!(offset < 7);

        self.inner[offset] = (value >> 8) as u8;
        self.inner[offset + 1] = value as u8;
    }

    fn inc_u16(&mut self, offset: usize, inc: u16) -> ComposeResult<()> {
        let value = match self.get_u16(offset).checked_add(inc) {
            Some(value) => value,
            None => return Err(ComposeError::Overflow),
        };
        self.set_u16(offset, value);
        Ok(())
    }
}


//------------ FullHeader ---------------------------------------------------

/// The complete header of a DNS message.
///
/// Consists of a `Header` and a `HeaderCounts`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FullHeader {
    inner: [u8; 12]
}

/// # Creation and Conversion
///
impl FullHeader {
    /// Creates a new empty header.
    pub fn new() -> FullHeader {
        FullHeader { inner: [0; 12] }
    }

    /// Creates a reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message(s: &[u8]) -> &FullHeader {
        &*(s.as_ptr() as *const FullHeader)
    }

    /// Creates a mutable reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message_mut(s: &mut [u8]) -> &mut FullHeader {
        &mut *(s.as_ptr() as *mut FullHeader)
    }

    /// Returns the underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}


/// # Access to Header and Counts
///
impl FullHeader {
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        unsafe { Header::from_message(&self.inner) }
    }

    /// Returns a mutable reference to the header.
    pub fn header_mut(&mut self) -> &mut Header {
        unsafe { Header::from_message_mut(&mut self. inner) }
    }

    /// Returns a reference to the header counts.
    pub fn counts(&self) -> &HeaderCounts {
        unsafe { HeaderCounts::from_message(&self.inner) }
    }

    /// Returns a mutable reference to the header counts.
    pub fn counts_mut(&mut self) -> &mut HeaderCounts {
        unsafe { HeaderCounts::from_message_mut(&mut self.inner) }
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use iana::{Opcode, Rcode};

    macro_rules! test_field {
        ($get:ident, $set:ident, $default:expr, $($value:expr),*) => {
            $({
                let mut h = Header::new();
                assert_eq!(h.$get(), $default);
                h.$set($value);
                assert_eq!(h.$get(), $value);
            })*
        }
    }

    #[test]
    fn header() {
        test_field!(id, set_id, 0, 0x1234);
        test_field!(qr, set_qr, false, true, false);
        test_field!(opcode, set_opcode, Opcode::Query, Opcode::Notify);
        test_field!(aa, set_aa, false, true, false);
        test_field!(tc, set_tc, false, true, false);
        test_field!(rd, set_rd, false, true, false);
        test_field!(ra, set_ra, false, true, false);
        test_field!(z, set_z, false, true, false);
        test_field!(ad, set_ad, false, true, false);
        test_field!(cd, set_cd, false, true, false);
        test_field!(rcode, set_rcode, Rcode::NoError, Rcode::Refused);
    }

    #[test]
    fn counts() {
        let mut c = HeaderCounts { inner: [ 1, 2, 3, 4, 5, 6, 7, 8 ] };
        assert_eq!(c.qdcount(), 0x0102);
        assert_eq!(c.ancount(), 0x0304);
        assert_eq!(c.nscount(), 0x0506);
        assert_eq!(c.arcount(), 0x0708);
        c.inc_qdcount(1).unwrap();
        c.inc_ancount(1).unwrap();
        c.inc_nscount(0x0100).unwrap();
        c.inc_arcount(0x0100).unwrap();
        assert_eq!(c.inner, [ 1, 3, 3, 5, 6, 6, 8, 8 ]);
        c.set_qdcount(0x0807);
        c.set_ancount(0x0605);
        c.set_nscount(0x0403);
        c.set_arcount(0x0201);
        assert_eq!(c.inner, [ 8, 7, 6, 5, 4, 3, 2, 1 ]);
    }

    #[test]
    fn update_counts() {
        let mut c = HeaderCounts { inner: [ 1, 2, 3, 4, 5, 6, 7, 8 ] };
        assert_eq!(c.zocount(), 0x0102);
        assert_eq!(c.prcount(), 0x0304);
        assert_eq!(c.upcount(), 0x0506);
        assert_eq!(c.adcount(), 0x0708);
        c.inc_zocount(1).unwrap();
        c.inc_prcount(1).unwrap();
        c.inc_upcount(0x0100).unwrap();
        c.inc_adcount(0x0100).unwrap();
        assert_eq!(c.inner, [ 1, 3, 3, 5, 6, 6, 8, 8 ]);
        c.set_zocount(0x0807);
        c.set_prcount(0x0605);
        c.set_upcount(0x0403);
        c.set_adcount(0x0201);
        assert_eq!(c.inner, [ 8, 7, 6, 5, 4, 3, 2, 1 ]);
    }
}

