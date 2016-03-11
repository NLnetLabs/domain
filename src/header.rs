//! The header of a DNS message.
//!
//! The message header has been split into two parts represented by two
//! separate types: `Header` contains the first 32 bits with the ID, opcode,
//! response code, and the various bits, while `HeaderCounts` contains the
//! item counts for the four message sections. A `FullHeader` type is
//! available that combines the both.
//!
//! The split has been done to reflect that when building a message you
//! should be able to freely manipulate the former part whereas the counts
//! should be set in accordance with the actual items in the message as it
//! is built.
//!

use std::mem;
use super::bytes::{BytesSlice, Error, Result};
use super::iana::{Opcode, Rcode};


//------------ Header -------------------------------------------------------

/// The first part of the header of a DNS message.
///
#[derive(Debug, PartialEq)]
pub struct Header {
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

    /// Creates a header reference from the given slice.
    ///
    /// Returns the header reference and the remainder of the slice. Or
    /// an error if the slice is to short.
    ///
    pub fn split_from(slice: &[u8]) -> Result<(&Header, &[u8])> {
        let (left, right) = try!(slice.split_bytes(mem::size_of::<Self>()));
        Ok((unsafe { Self::from_message(left) }, right))
    }

    /// Creates a header reference from a bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message(s: &[u8]) -> &Header {
        mem::transmute(s.as_ptr())
    }

    /// Creates a mutable header reference from a bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message_mut(s: &mut [u8]) -> &mut Header {
        mem::transmute(s.as_ptr())
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
    pub fn id(&self) -> u16 { self.get_u16(0) }

    /// Sets the ID field.
    pub fn set_id(&mut self, value: u16) { self.set_u16(0, value) }

    /// Returns the value of the QR bit.
    pub fn qr(&self) -> bool { self.get_bit(2, 7) }

    /// Sets the value of the QR bit.
    pub fn set_qr(&mut self, set: bool) { self.set_bit(2, 7, set) }

    /// Returns the Opcode field.
    pub fn opcode(&self) -> Opcode {
        Opcode::from_int((self.inner[2] >> 3) & 0x0F)
    }

    /// Sets the opcode field.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.inner[2] = self.inner[2] & 0x87 | (opcode.to_int() << 3);
    }

    /// Returns the value of the AA bit.
    pub fn aa(&self) -> bool { self.get_bit(2, 2) }

    /// Sets the value of the AA bit.
    pub fn set_aa(&mut self, set: bool) { self.set_bit(2, 2, set) }

    /// Returns the value of the TC bit.
    pub fn tc(&self) -> bool { self.get_bit(2, 1) }

    /// Sets the value of the TC bit.
    pub fn set_tc(&mut self, set: bool) { self.set_bit(2, 1, set) }

    /// Returns the value of the RD bit.
    pub fn rd(&self) -> bool { self.get_bit(2, 0) }

    /// Sets the value of the RD bit.
    pub fn set_rd(&mut self, set: bool) { self.set_bit(2, 0, set) }

    /// Returns the value of the RA bit.
    pub fn ra(&self) -> bool { self.get_bit(3, 7) }

    /// Sets the value of the RA bit.
    pub fn set_ra(&mut self, set: bool) { self.set_bit(3, 7, set) }

    /// Returns the value of the reserved bit.
    pub fn z(&self) -> bool { self.get_bit(3, 6) }

    /// Sets the value of the reserved bit.
    pub fn set_z(&mut self, set: bool) { self.set_bit(3, 6, set) }

    /// Returns the value of the AD bit.
    pub fn ad(&self) -> bool { self.get_bit(3, 5) }

    /// Sets the value of the AD bit.
    pub fn set_ad(&mut self, set: bool) { self.set_bit(3, 5, set) }

    /// Returns the value of the CD bit.
    pub fn cd(&self) -> bool { self.get_bit(3, 4) }

    /// Sets the value of the CD bit.
    pub fn set_cd(&mut self, set: bool) { self.set_bit(3, 4, set) }

    /// Returns the RCODE field.
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
#[derive(Debug, PartialEq)]
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

    /// Creates a reference from the given slice.
    ///
    /// Returns the reference and the remainder of the slice.
    pub fn split_from(slice: &[u8]) -> Result<(&HeaderCounts, &[u8])> {
        let (left, right) = try!(slice.split_bytes(mem::size_of::<Self>()));
        Ok((unsafe { mem::transmute(left.as_ptr()) }, right))
    }

    /// Creates a reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message(s: &[u8]) -> &HeaderCounts {
        mem::transmute((s[mem::size_of::<Header>()..].as_ptr()))
    }

    /// Creates a mutable reference from the bytes slice of a message.
    ///
    /// This function is unsafe as it assumes the bytes slice to have the
    /// correct length.
    pub unsafe fn from_message_mut(s: &mut [u8]) -> &mut HeaderCounts {
        mem::transmute(s[mem::size_of::<Header>()..].as_ptr())
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
    pub fn qdcount(&self) -> u16 {
        self.get_u16(0)
    }

    /// Sets the QDCOUNT field.
    pub fn set_qdcount(&mut self, value: u16) {
        self.set_u16(0, value)
    }

    /// Increase the QDCOUNT field.
    pub fn inc_qdcount(&mut self, inc: u16) -> Result<()> {
        self.inc_u16(0, inc)
    }

    /// Returns the ANCOUNT field.
    pub fn ancount(&self) -> u16 {
        self.get_u16(2)
    }

    /// Sets the ANCOUNT field.
    pub fn set_ancount(&mut self, value: u16) {
        self.set_u16(2, value)
    }

    /// Increases the ANCOUNT field.
    pub fn inc_ancount(&mut self, inc: u16) -> Result<()> {
        self.inc_u16(2, inc)
    }

    /// Returns the NSCOUNT field.
    pub fn nscount(&self) -> u16 {
        self.get_u16(4)
    }

    /// Sets the NSCOUNT field.
    pub fn set_nscount(&mut self, value: u16) {
        self.set_u16(4, value)
    }

    /// Increases the NSCOUNT field.
    pub fn inc_nscount(&mut self, inc: u16) -> Result<()> {
        self.inc_u16(4, inc)
    }

    /// Returns the ARCOUNT field.
    pub fn arcount(&self) -> u16 {
        self.get_u16(6)
    }

    /// Sets the ARCOUNT field.
    pub fn set_arcount(&mut self, value: u16) {
        self.set_u16(6, value)
    }

    /// Increases the ARCOUNT field.
    pub fn inc_arcount(&mut self, inc: u16) -> Result<()> {
        self.inc_u16(6, inc)
    }


    ///--- Count fields in UPDATE messages

    /// Returns the ZOCOUNT field.
    pub fn zocount(&self) -> u16 {
        self.get_u16(0)
    }

    /// Returns the PRCOUNT field.
    pub fn prcount(&self) -> u16 {
        self.get_u16(2)
    }

    /// Returns the UPCOUNT field.
    pub fn upcount(&self) -> u16 {
        self.get_u16(4)
    }

    /// Returns the ADCOUNT field.
    pub fn adcount(&self) -> u16 {
        self.get_u16(6)
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

    fn inc_u16(&mut self, offset: usize, inc: u16) -> Result<()> {
        let value = match self.get_u16(offset).checked_add(inc) {
            Some(value) => value,
            None => return Err(Error::Overflow),
        };
        self.set_u16(offset, value);
        Ok(())
    }
}


//------------ FullHeader ---------------------------------------------------

/// The complete header of a DNS message.
///
/// Currently, this type is only used to conveniently get the size of the
/// entire header.
pub type FullHeader = [u8; 12];


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use super::super::iana::{Opcode, Rcode};

    #[test]
    fn getters() {
        let (h, r) = Header::split_from(b"\xDE\x55\x01\x25\x00\x01\
                                          \x00\x02\x03\x00\x04\x04\
                                          abc").unwrap();
        assert_eq!(h.id(), 0xDE55); 
        assert_eq!(h.qr(), false);
        assert_eq!(h.opcode(), Opcode::Query);
        assert_eq!(h.aa(), false);
        assert_eq!(h.tc(), false);
        assert_eq!(h.rd(), true);
        assert_eq!(h.ra(), false);
        assert_eq!(h.ad(), true);
        assert_eq!(h.cd(), false);
        assert_eq!(h.rcode(), Rcode::Refused);

        let (h, r) = HeaderCounts::split_from(r).unwrap();
        assert_eq!(h.qdcount(), 0x0001);
        assert_eq!(h.ancount(), 0x0002);
        assert_eq!(h.nscount(), 0x0300);
        assert_eq!(h.arcount(), 0x0404);

        assert_eq!(r, &b"abc"[..]);
    }

    #[test]
    fn setters() {
        let mut h = Header::new();
        h.set_id(0xDE55);
        h.set_rd(true);
        h.set_ad(true);
        h.set_rcode(Rcode::Refused);
        assert_eq!(h.as_bytes(), b"\xDE\x55\x01\x25");

        let mut h = HeaderCounts::new();
        h.set_qdcount(0x0001);
        h.set_ancount(0x0002);
        h.set_nscount(0x0300);
        h.set_arcount(0x0404);
        assert_eq!(h.as_bytes(), b"\x00\x01\x00\x02\x03\x00\x04\x04");
    }
}
