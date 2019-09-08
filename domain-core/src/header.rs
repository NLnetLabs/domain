//! The header of a DNS message.
//!
//! Each DNS message starts with a twelve octet long header section
//! containing some general information related to the message as well as
//! the number of records in each of the four sections that follow the header.
//! Its content and format are defined in section 4.1.1 of [RFC 1035].
//!
//! In order to reflect the fact that changing the section counts may
//! invalidate the rest of the message whereas the other elements of the
//! header section can safely be modified, the whole header has been split
//! into two separate types: [`Header`] contains the safely modifyable part
//! at the beginning and [`HeaderCounts`] contains the section counts. In
//! addition, the [`HeaderSection`] type wraps both of them into a single
//! type.
//!
//! [`Header`]: struct.Header.html
//! [`HeaderCounts`]: struct.HeaderCounts.html
//! [`HeaderSection`]: struct.HeaderSection.html
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use core::mem;
use core::convert::TryInto;
use unwrap::unwrap;
use crate::compose::{Compose, ComposeTarget};
use crate::iana::{Opcode, Rcode};
use crate::parse::{Parse, Parser, ShortBuf};


//------------ Header --------------------------------------------------

/// The first part of the header of a DNS message.
///
/// This type represents the information contained in the first four bytes of
/// the header: the message ID, opcode, rcode, and the various flags.
///
/// The type’s data contains such a header in its wire format which is layed
/// out like this:
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
/// Methods are available for accessing each of these fields.
/// See [Field Access] below.
///
/// The basic structure and most of the fields re defined in [RFC 1035],
/// except for the AD and CD flags, which are defined in [RFC 4035].
///
/// [Field Access]: #field-access 
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 4035]: https://tools.ietf.org/html/rfc4035
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Header {
    /// The actual header in its wire format representation.
    ///
    /// This means that the ID field is in big endian.
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
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header reference from a byte slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the byte slice is too short.
    pub fn for_message_slice(s: &[u8]) -> &Header {
        assert!(s.len() >= mem::size_of::<Header>());
        unsafe { &*(s.as_ptr() as *const Header) }
    }

    /// Creates a mutable header reference from a byte slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the byte slice is too short.
    pub fn for_message_slice_mut(s: &mut [u8]) -> &mut Header {
        assert!(s.len() >= mem::size_of::<Header>());
        unsafe { &mut *(s.as_ptr() as *mut Header) }
    }

    /// Returns a reference to the underlying bytes slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }
}


/// # Field Access
///
impl Header {
    /// Returns the value of the ID field.
    ///
    /// The ID field is an identifier chosen by whoever created a query
    /// and is copied into a response by a server. It allows matching
    /// incoming responses to their queries.
    pub fn id(self) -> u16 {
        u16::from_be_bytes(unwrap!(self.inner[..2].try_into()))
    }

    /// Sets the value of the ID field.
    pub fn set_id(&mut self, value: u16) {
        self.inner[..2].copy_from_slice(&value.to_be_bytes())
    }

    /// Sets the value of the ID field to a randomly chosen number.
    ///
    /// This uses [`rand::random`] which may not be good enough.
    pub fn set_random_id(&mut self) { self.set_id(::rand::random()) }

    /// Returns whether the QR bit is set.
    ///
    /// The QR bit specifies whether this message is a query (`false`) or
    /// a response (`true`). In other words, this bit is actually stating
    /// whether the message is *not* a query. So, perhaps it might be good
    /// to read ‘QR’ as ‘query response.’
    pub fn qr(self) -> bool { self.get_bit(2, 7) }

    /// Sets the value of the QR bit.
    ///
    pub fn set_qr(&mut self, set: bool) { self.set_bit(2, 7, set) }

    /// Returns the value of the Opcode field.
    ///
    /// This field specifies the kind of query this message contains. See
    /// the [`Opcode`] type for more information on the possible values and
    /// their meaning. Normal queries have the variant [`Opcode::Query`]
    /// which is also the value set when creating a new header.
    ///
    /// [`Opcode`]: ../../iana/opcode/enum.Opcode.html
    /// [`Opcode::Query`]: ../../iana/opcode/enum.Opcode.html#variant.Query
    pub fn opcode(self) -> Opcode {
        Opcode::from_int((self.inner[2] >> 3) & 0x0F)
    }

    /// Sets the value of the opcode field.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.inner[2] = self.inner[2] & 0x87 | (opcode.to_int() << 3);
    }

    /// Returns whether the AA bit is set.
    ///
    /// Using this bit, a name server generating a response states whether
    /// it is authoritative for the requested domain name, ie., whether this
    /// response is an *authoritative answer.* The field has no meaning in 
    /// a query.
    pub fn aa(self) -> bool { self.get_bit(2, 2) }

    /// Sets the value of the AA bit.
    pub fn set_aa(&mut self, set: bool) { self.set_bit(2, 2, set) }

    /// Returns whether the TC bit is set.
    ///
    /// The *truncation* bit is set if there was more data available then
    /// fit into the message. This is typically used when employing
    /// datagram transports such as UDP to signal to try again using a
    /// stream transport such as TCP.
    pub fn tc(self) -> bool { self.get_bit(2, 1) }

    /// Sets the value of the TC bit.
    pub fn set_tc(&mut self, set: bool) { self.set_bit(2, 1, set) }

    /// Returns whether the RD bit is set.
    ///
    /// The *recursion desired* bit may be set in a query to ask the name
    /// server to try and recursively gather a response if it doesn’t have
    /// the data available locally. The bit’s value is copied into the
    /// response.
    pub fn rd(self) -> bool { self.get_bit(2, 0) }

    /// Sets the value of the RD bit.
    pub fn set_rd(&mut self, set: bool) { self.set_bit(2, 0, set) }

    /// Returns whether the RA bit is set.
    ///
    /// In a response, the *recursion available* bit denotes whether the
    /// responding name server supports recursion. It has no meaning in
    /// a query.
    pub fn ra(self) -> bool { self.get_bit(3, 7) }

    /// Sets the value of the RA bit.
    pub fn set_ra(&mut self, set: bool) { self.set_bit(3, 7, set) }

    /// Returns whether the reserved bit is set.
    ///
    /// This bit must be `false` in all queries and responses.
    pub fn z(self) -> bool { self.get_bit(3, 6) }

    /// Sets the value of the reserved bit.
    pub fn set_z(&mut self, set: bool) { self.set_bit(3, 6, set) }

    /// Returns whether the AD bit is set.
    ///
    /// The *authentic data* bit is used by security-aware recursive name
    /// servers to indicate that it considers all RRsets in its response to
    /// be authentic.
    pub fn ad(self) -> bool { self.get_bit(3, 5) }

    /// Sets the value of the AD bit.
    pub fn set_ad(&mut self, set: bool) { self.set_bit(3, 5, set) }

    /// Returns whether the CD bit is set.
    ///
    /// The *checking disabled* bit is used by a security-aware resolver
    /// to indicate that it does not want upstream name servers to perform
    /// verification but rather would like to verify everything itself.
    pub fn cd(self) -> bool { self.get_bit(3, 4) }

    /// Sets the value of the CD bit.
    pub fn set_cd(&mut self, set: bool) { self.set_bit(3, 4, set) }

    /// Returns the value of the RCODE field.
    ///
    /// The *response code* is used in a response to indicate what happened
    /// when processing the query. See the [`Rcode`] type for information on
    /// possible values and their meaning.
    ///
    /// [`Rcode`]: ../../iana/rcode/enum.Rcode.html
    pub fn rcode(self) -> Rcode {
        Rcode::from_int(self.inner[3] & 0x0F)
    }

    /// Sets the value of the RCODE field.
    pub fn set_rcode(&mut self, rcode: Rcode) {
        self.inner[3] = self.inner[3] & 0xF0 | (rcode.to_int() & 0x0F);
    }


    //--- Internal helpers

    /// Returns the value of the bit at the given position.
    ///
    /// The argument `offset` gives the byte offset of the underlying bytes
    /// slice and `bit` gives the number of the bit with the most significant
    /// bit being 7.
    fn get_bit(self, offset: usize, bit: usize) -> bool {
        self.inner[offset] & (1 << bit) != 0
    }

    /// Sets or resets the given bit.
    fn set_bit(&mut self, offset: usize, bit: usize, set: bool) {
        if set { self.inner[offset] |= 1 << bit }
        else { self.inner[offset] &= !(1 << bit) }
    }
} 


//------------ HeaderCounts -------------------------------------------------

/// The section count part of the header section of a DNS message.
///
/// This part consists of four 16 bit counters for the number of entries in
/// the four sections of a DNS message.
///
/// The counters are arranged in the same order as the sections themselves:
/// QDCOUNT for the question section, ANCOUNT for the answer section,
/// NSCOUNT for the authority section, and ARCOUNT for the additional section.
/// These are defined in [RFC 1035].
///
/// [RFC 2136] defines the UPDATE method and reuses the four section for
/// different purposes. Here the counters are ZOCOUNT for the zone section,
/// PRCOUNT for the prerequisite section, UPCOUNT for the update section,
/// and ADCOUNT for the additional section. The type has convenience methods
/// for these fields as well so you don’t have to remember which is which.
///
/// For each field there are three methods for getting, setting, and
/// incrementing.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 2136]: https://tools.ietf.org/html/rfc2136
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderCounts {
    /// The actual headers in their wire-format representation.
    ///
    /// Ie., all values are stored big endian.
    inner: [u8; 8]
}

/// # Creation and Conversion
///
impl HeaderCounts {
    /// Creates a new value with all counters set to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header reference from a byte slice of a message.
    ///
    /// The slice `message` mut be the whole message, i.e., start with the
    /// bytes of the [`Header`](struct.Header.html).
    /// 
    /// # Panics
    ///
    /// This function panics if the bytes slice is too short.
    pub fn for_message_slice(message: &[u8]) -> &Self {
        assert!(message.len() >= mem::size_of::<HeaderSection>());
        unsafe {
            &*((message[mem::size_of::<Header>()..].as_ptr())
                                                      as *const HeaderCounts)
        }
    }

    /// Creates a mutable header reference from a bytes slice of a message.
    ///
    /// The slice `message` mut be the whole message, i.e., start with the
    /// bytes of the [`Header`](struct.Header.html).
    ///
    /// # Panics
    ///
    /// This function panics if the bytes slice is too short.
    pub fn for_message_slice_mut(message: &mut [u8]) -> &mut Self {
        assert!(message.len() >= mem::size_of::<HeaderSection>());
        unsafe {
            &mut *((message[mem::size_of::<Header>()..].as_ptr())
                                                         as *mut HeaderCounts)
        }
    }

    /// Returns a reference to the raw byte slice of the header counts.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable reference to the raw byte slice of the header counts.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Sets the counts to those from `counts`.
    pub fn set(&mut self, counts: HeaderCounts) {
        self.as_slice_mut().copy_from_slice(counts.as_slice())
    }
}


/// # Field Access
///
impl HeaderCounts {
    //--- Count fields in regular messages

    /// Returns the value of the QDCOUNT field.
    ///
    /// This field contains the number of questions in the first
    /// section of the message, normally the question section.
    pub fn qdcount(self) -> u16 {
        self.get_u16(0)
    }

    /// Sets the value of the QDCOUNT field.
    pub fn set_qdcount(&mut self, value: u16) {
        self.set_u16(0, value)
    }

    /// Increases the value of the QDCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already at its maximum.
    pub fn inc_qdcount(&mut self) {
        let count = self.qdcount();
        assert!(count < core::u16::MAX);
        self.set_qdcount(count + 1);
    }

    /// Decreases the value of the QDCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already zero.
    pub fn dec_qdcount(&mut self) {
        let count = self.qdcount();
        assert!(count > 0);
        self.set_qdcount(count - 1);
    }


    /// Returns the value of the ANCOUNT field.
    ///
    /// This field contains the number of resource records in the second
    /// section of the message, normally the answer section.
    pub fn ancount(self) -> u16 {
        self.get_u16(2)
    }

    /// Sets the value of the ANCOUNT field.
    pub fn set_ancount(&mut self, value: u16) {
        self.set_u16(2, value)
    }

    /// Increases the value of the ANCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already at its maximum.
    pub fn inc_ancount(&mut self) {
        let count = self.ancount();
        assert!(count < core::u16::MAX);
        self.set_ancount(count + 1);
    }

    /// Decreases the value of the ANCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already zero.
    pub fn dec_ancount(&mut self) {
        let count = self.ancount();
        assert!(count > 0);
        self.set_ancount(count - 1);
    }

    /// Returns the value of the NSCOUNT field.
    ///
    /// This field contains the number of resource records in the third
    /// section of the message, normally the authority section.
    pub fn nscount(self) -> u16 {
        self.get_u16(4)
    }

    /// Sets the value of the NSCOUNT field.
    pub fn set_nscount(&mut self, value: u16) {
        self.set_u16(4, value)
    }

    /// Increases the value of the NSCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already at its maximum.
    pub fn inc_nscount(&mut self) {
        let count = self.nscount();
        assert!(count < core::u16::MAX);
        self.set_nscount(count + 1);
    }

    /// Decreases the value of the NSCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already zero.
    pub fn dec_nscount(&mut self) {
        let count = self.nscount();
        assert!(count > 0);
        self.set_nscount(count - 1);
    }

    /// Returns the value of the ARCOUNT field.
    ///
    /// This field contains the number of resource records in the fourth
    /// section of the message, normally the additional section.
    pub fn arcount(self) -> u16 {
        self.get_u16(6)
    }

    /// Sets the value of the ARCOUNT field.
    pub fn set_arcount(&mut self, value: u16) {
        self.set_u16(6, value)
    }

    /// Increases the value of the ARCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already at its maximum.
    pub fn inc_arcount(&mut self) {
        let count = self.arcount();
        assert!(count < core::u16::MAX);
        self.set_arcount(count + 1);
    }

    /// Decreases the value of the ARCOUNT field by one.
    ///
    /// # Panics
    ///
    /// This method panics if the count is already zero.
    pub fn dec_arcount(&mut self) {
        let count = self.arcount();
        assert!(count > 0);
        self.set_arcount(count - 1);
    }


    //--- Count fields in UPDATE messages

    /// Returns the value of the ZOCOUNT field.
    ///
    /// This is the same as the `qdcount()`. It is used in UPDATE queries
    /// where the first section is the zone section.
    pub fn zocount(self) -> u16 {
        self.qdcount()
    }

    /// Sets the value of the ZOCOUNT field.
    pub fn set_zocount(&mut self, value: u16) {
        self.set_qdcount(value)
    }

    /// Returns the value of the PRCOUNT field.
    ///
    /// This is the same as the `ancount()`. It is used in UPDATE queries
    /// where the first section is the prerequisite section.
    pub fn prcount(self) -> u16 {
        self.ancount()
    }

    /// Sete the value of the PRCOUNT field.
    pub fn set_prcount(&mut self, value: u16) {
        self.set_ancount(value)
    }

    /// Returns the value of the UPCOUNT field.
    ///
    /// This is the same as the `nscount()`. It is used in UPDATE queries
    /// where the first section is the update section.
    pub fn upcount(self) -> u16 {
        self.nscount()
    }

    /// Sets the value of the UPCOUNT field.
    pub fn set_upcount(&mut self, value: u16) {
        self.set_nscount(value)
    }

    /// Returns the value of the ADCOUNT field.
    ///
    /// This is the same as the `arcount()`. It is used in UPDATE queries
    /// where the first section is the additional section.
    pub fn adcount(self) -> u16 {
        self.arcount()
    }

    /// Sets the value of the ADCOUNT field.
    pub fn set_adcount(&mut self, value: u16) {
        self.set_arcount(value)
    }
   

    //--- Internal helpers

    /// Returns the value of the 16 bit integer starting at a given offset.
    fn get_u16(self, offset: usize) -> u16 {
        u16::from_be_bytes(unwrap!(
            self.inner[offset..offset + 2].try_into()
        ))
    }

    /// Sets the value of the 16 bit integer starting at a given offset.
    fn set_u16(&mut self, offset: usize, value: u16) {
        self.inner[offset..offset + 2].copy_from_slice(&value.to_be_bytes())
    }
}


//------------ HeaderSection -------------------------------------------------

/// The complete header section of a DNS message.
///
/// Consists of a `Header` and a `HeaderCounts`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderSection {
    inner: [u8; 12]
}

/// # Creation and Conversion
///
impl HeaderSection {
    /// Creates a new empty header section.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a reference from the bytes slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the size of the bytes slice is smaller than
    /// the header section.
    pub fn for_message_slice(s: &[u8]) -> &HeaderSection {
        assert!(s.len() >= mem::size_of::<HeaderSection>());
        unsafe { &*(s.as_ptr() as *const HeaderSection) }
    }

    /// Creates a mutable reference from the bytes slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the size of the bytes slice is smaller than
    /// the header section.
    pub fn for_message_slice_mut(s: &mut [u8]) -> &mut HeaderSection {
        assert!(s.len() >= mem::size_of::<HeaderSection>());
        unsafe { &mut *(s.as_ptr() as *mut HeaderSection) }
    }

    /// Returns a reference to the underlying bytes slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }
}


/// # Access to Header and Counts
///
impl HeaderSection {
    /// Returns a reference to the header.
    pub fn header(&self) -> &Header {
        Header::for_message_slice(&self.inner)
    }

    /// Returns a mutable reference to the header.
    pub fn header_mut(&mut self) -> &mut Header {
        Header::for_message_slice_mut(&mut self. inner)
    }

    /// Returns a reference to the header counts.
    pub fn counts(&self) -> &HeaderCounts {
        HeaderCounts::for_message_slice(&self.inner)
    }

    /// Returns a mutable reference to the header counts.
    pub fn counts_mut(&mut self) -> &mut HeaderCounts {
        HeaderCounts::for_message_slice_mut(&mut self.inner)
    }
}


//--- Parse and Compose

impl<T: AsRef<[u8]>> Parse<T> for Header {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser<T>) -> Result<Self, Self::Err> {
        let mut res = Self::default();
        parser.parse_buf(&mut res.inner)?;
        Ok(res)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), Self::Err> {
        parser.advance(12)
    }
}

impl Compose for HeaderSection {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.inner)
    }
}


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use crate::iana::{Opcode, Rcode};
    use std::vec::Vec;
    use super::*;

    #[test]
    fn for_slice() {
        let header = b"\x01\x02\x00\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0";
        let mut vec = Vec::from(&header[..]);
        assert_eq!(Header::for_message_slice(header).as_slice(),
                   b"\x01\x02\x00\x00");
        assert_eq!(Header::for_message_slice_mut(vec.as_mut()).as_slice(),
                   b"\x01\x02\x00\x00");
        assert_eq!(HeaderCounts::for_message_slice(header).as_slice(),
                   b"\x12\x34\x56\x78\x9a\xbc\xde\xf0");
        assert_eq!(HeaderCounts::for_message_slice_mut(vec.as_mut()).as_slice(),
                   b"\x12\x34\x56\x78\x9a\xbc\xde\xf0");
        assert_eq!(HeaderSection::for_message_slice(header).as_slice(),
                   header);
        assert_eq!(HeaderSection::for_message_slice_mut(vec.as_mut())
                                 .as_slice(),
                   header);
    }

    #[test]
    #[should_panic]
    fn short_header() {
        Header::for_message_slice(b"134");
    }

    #[test]
    #[should_panic]
    fn short_header_counts() {
        HeaderCounts::for_message_slice(b"12345678");
    }

    #[test]
    #[should_panic]
    fn short_header_section() {
        HeaderSection::for_message_slice(b"1234");
    }

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
        c.inc_qdcount();
        c.inc_ancount();
        c.inc_nscount();
        c.inc_arcount();
        assert_eq!(c.inner, [ 1, 3, 3, 5, 5, 7, 7, 9 ]);
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
        c.set_zocount(0x0807);
        c.set_prcount(0x0605);
        c.set_upcount(0x0403);
        c.set_adcount(0x0201);
        assert_eq!(c.inner, [ 8, 7, 6, 5, 4, 3, 2, 1 ]);
    }

    #[test]
    #[should_panic]
    fn bad_inc_qdcount() {
        let mut c = HeaderCounts {
            inner: [ 0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff ]
        };
        c.inc_qdcount()
    }

    #[test]
    #[should_panic]
    fn bad_inc_ancount() {
        let mut c = HeaderCounts {
            inner: [ 0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff ]
        };
        c.inc_ancount()
    }

    #[test]
    #[should_panic]
    fn bad_inc_nscount() {
        let mut c = HeaderCounts {
            inner: [ 0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff ]
        };
        c.inc_nscount()
    }

    #[test]
    #[should_panic]
    fn bad_inc_arcount() {
        let mut c = HeaderCounts {
            inner: [ 0xff, 0xff,0xff,0xff,0xff,0xff,0xff,0xff ]
        };
        c.inc_arcount()
    }
}

