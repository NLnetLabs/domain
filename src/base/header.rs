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
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use super::iana::{Opcode, Rcode};
use super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf,
};
use core::convert::TryInto;
use core::{fmt, mem, str::FromStr};

//------------ Header --------------------------------------------------

/// The first part of the header of a DNS message.
///
/// This type represents the information contained in the first four octets
/// of the header: the message ID, opcode, rcode, and the various flags. It
/// keeps those four octets in wire representation, i.e., in network byte
/// order. The data is layed out like this:
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
/// Methods are available for accessing each of these fields. For more
/// information on the fields, see these methods in the section
/// [Field Access] below.
///
/// You can create owned values via the [`new`][Self::new] method or
/// the `Default` trait.  However, more often the type will
/// be used via a reference into the octets of an actual message. The
/// functions [`for_message_slice`][Self::for_message_slice] and
/// [`for_message_slice_mut`][Self::for_message_slice_mut] create such
/// references from an octets slice.
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
    inner: [u8; 4],
}

/// # Creation and Conversion
///
impl Header {
    /// Creates a new header.
    ///
    /// The new header has all fields as either zero or false. Thus, the
    /// opcode will be [`Opcode::Query`] and the response code will be
    /// [`Rcode::NoError`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header reference from an octets slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the slice is less than four octets long.
    pub fn for_message_slice(s: &[u8]) -> &Header {
        assert!(s.len() >= mem::size_of::<Header>());
        unsafe { &*(s.as_ptr() as *const Header) }
    }

    /// Creates a mutable header reference from an octets slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the slice is less than four octets long.
    pub fn for_message_slice_mut(s: &mut [u8]) -> &mut Header {
        assert!(s.len() >= mem::size_of::<Header>());
        unsafe { &mut *(s.as_ptr() as *mut Header) }
    }

    /// Returns a reference to the underlying octets slice.
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
    ///
    /// When choosing an ID for an outgoing message, make sure it is random
    /// to avoid spoofing through guessing the message ID. The method
    /// [`set_random_id`][Self::set_random_id] can be used for this purpose.
    pub fn id(self) -> u16 {
        u16::from_be_bytes(self.inner[..2].try_into().unwrap())
    }

    /// Sets the value of the ID field.
    pub fn set_id(&mut self, value: u16) {
        self.inner[..2].copy_from_slice(&value.to_be_bytes())
    }

    /// Sets the value of the ID field to a randomly chosen number.
    pub fn set_random_id(&mut self) {
        self.set_id(::rand::random())
    }

    /// Returns whether the [QR](Flags::qr) bit is set.
    pub fn qr(self) -> bool {
        self.get_bit(2, 7)
    }

    /// Sets the value of the [QR](Flags::qr) bit.
    pub fn set_qr(&mut self, set: bool) {
        self.set_bit(2, 7, set)
    }

    /// Returns the value of the Opcode field.
    ///
    /// This field specifies the kind of query a message contains. See
    /// the [`Opcode`] type for more information on the possible values and
    /// their meaning. Normal queries have the variant [`Opcode::Query`]
    /// which is also the default value when creating a new header.
    pub fn opcode(self) -> Opcode {
        Opcode::from_int((self.inner[2] >> 3) & 0x0F)
    }

    /// Sets the value of the opcode field.
    pub fn set_opcode(&mut self, opcode: Opcode) {
        self.inner[2] = self.inner[2] & 0x87 | (opcode.to_int() << 3);
    }

    /// Returns all flags contained in the header.
    ///
    /// This is a virtual field composed of all the flag bits that are present
    /// in the header. The returned [`Flags`] type can be useful when you're
    /// working with all flags, rather than a single one, which can be easily
    /// obtained from the header directly.
    pub fn flags(self) -> Flags {
        Flags {
            qr: self.qr(),
            aa: self.aa(),
            tc: self.tc(),
            rd: self.rd(),
            ra: self.ra(),
            ad: self.ad(),
            cd: self.cd(),
        }
    }

    /// Sets all flag bits.
    pub fn set_flags(&mut self, flags: Flags) {
        self.set_qr(flags.qr);
        self.set_aa(flags.aa);
        self.set_tc(flags.tc);
        self.set_rd(flags.rd);
        self.set_ra(flags.ra);
        self.set_ad(flags.ad);
        self.set_cd(flags.cd);
    }

    /// Returns whether the [AA](Flags::aa) bit is set.
    pub fn aa(self) -> bool {
        self.get_bit(2, 2)
    }

    /// Sets the value of the [AA](Flags::aa) bit.
    pub fn set_aa(&mut self, set: bool) {
        self.set_bit(2, 2, set)
    }

    /// Returns whether the [TC](Flags::tc) bit is set.
    pub fn tc(self) -> bool {
        self.get_bit(2, 1)
    }

    /// Sets the value of the [TC](Flags::tc) bit.
    pub fn set_tc(&mut self, set: bool) {
        self.set_bit(2, 1, set)
    }

    /// Returns whether the [RD](Flags::rd) bit is set.
    pub fn rd(self) -> bool {
        self.get_bit(2, 0)
    }

    /// Sets the value of the [RD](Flags::rd) bit.
    pub fn set_rd(&mut self, set: bool) {
        self.set_bit(2, 0, set)
    }

    /// Returns whether the [RA](Flags::ra) bit is set.
    pub fn ra(self) -> bool {
        self.get_bit(3, 7)
    }

    /// Sets the value of the [RA](Flags::ra) bit.
    pub fn set_ra(&mut self, set: bool) {
        self.set_bit(3, 7, set)
    }

    /// Returns whether the reserved bit is set.
    ///
    /// This bit must be `false` in all queries and responses.
    pub fn z(self) -> bool {
        self.get_bit(3, 6)
    }

    /// Sets the value of the reserved bit.
    pub fn set_z(&mut self, set: bool) {
        self.set_bit(3, 6, set)
    }

    /// Returns whether the [AD](Flags::ad) bit is set.
    pub fn ad(self) -> bool {
        self.get_bit(3, 5)
    }

    /// Sets the value of the [AD](Flags::ad) bit.
    pub fn set_ad(&mut self, set: bool) {
        self.set_bit(3, 5, set)
    }

    /// Returns whether the [CD](Flags::cd) bit is set.
    pub fn cd(self) -> bool {
        self.get_bit(3, 4)
    }

    /// Sets the value of the [CD](Flags::cd) bit.
    pub fn set_cd(&mut self, set: bool) {
        self.set_bit(3, 4, set)
    }

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
        if set {
            self.inner[offset] |= 1 << bit
        } else {
            self.inner[offset] &= !(1 << bit)
        }
    }
}

//------------ Flags ---------------------------------------------------

/// The flags contained in the DNS message header.
///
/// This is a utility type that makes it easier to work with flags. It contains
/// only standard DNS message flags that are part of the [`Header`], i.e., EDNS
/// flags are not included.
///
/// This type has a text notation and can be created from it as well. Each
/// flags that is set is represented by a two-letter token, which is the
/// uppercase version of the flag name.  If mutliple flags are set, the tokens
/// are separated by space.
///
/// ```
/// use core::str::FromStr;
/// use domain::base::header::Flags;
///
/// let flags = Flags::from_str("QR AA").unwrap();
/// assert!(flags.qr && flags.aa);
/// assert_eq!(format!("{}", flags), "QR AA");
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Flags {
    /// The `QR` bit specifies whether a message is a query (`false`) or a
    /// response (`true`). In other words, this bit is actually stating whether
    /// the message is *not* a query. So, perhaps it might be good to read ‘QR’
    /// as ‘query response.’
    pub qr: bool,

    /// Using the `AA` bit, a name server generating a response states whether
    /// it is authoritative for the requested domain name, ie., whether this
    /// response is an *authoritative answer.* The field has no meaning in a
    /// query.
    pub aa: bool,

    /// The *truncation* (`TC`) bit is set if there was more data available then
    /// fit into the message. This is typically used when employing datagram
    /// transports such as UDP to signal that the answer didn’t fit into a
    /// response and the query should be tried again using a stream transport
    /// such as TCP.
    pub tc: bool,

    /// The *recursion desired* (`RD`) bit may be set in a query to ask the name
    /// server to try and recursively gather a response if it doesn’t have the
    /// data available locally. The bit’s value is copied into the response.
    pub rd: bool,

    /// In a response, the *recursion available* (`RA`) bit denotes whether the
    /// responding name server supports recursion. It has no meaning in a query.
    pub ra: bool,

    /// The *authentic data* (`AD`) bit is used by security-aware recursive name
    /// servers to indicate that it considers all RRsets in its response are
    /// authentic, i.e., have successfully passed DNSSEC validation.
    pub ad: bool,

    /// The *checking disabled* (`CD`) bit is used by a security-aware resolver
    /// to indicate that it does not want upstream name servers to perform
    /// verification but rather would like to verify everything itself.
    pub cd: bool,
}

/// # Creation and Conversion
///
impl Flags {
    /// Creates new flags.
    ///
    /// All flags will be unset.
    pub fn new() -> Self {
        Self::default()
    }
}

//--- Display & FromStr

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut sep = "";
        if self.qr {
            write!(f, "QR")?;
            sep = " ";
        }
        if self.aa {
            write!(f, "{}AA", sep)?;
            sep = " ";
        }
        if self.tc {
            write!(f, "{}TC", sep)?;
            sep = " ";
        }
        if self.rd {
            write!(f, "{}RD", sep)?;
            sep = " ";
        }
        if self.ra {
            write!(f, "{}RA", sep)?;
            sep = " ";
        }
        if self.ad {
            write!(f, "{}AD", sep)?;
            sep = " ";
        }
        if self.cd {
            write!(f, "{}CD", sep)?;
        }
        Ok(())
    }
}

impl FromStr for Flags {
    type Err = FlagsFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut flags = Flags::new();
        for token in s.to_uppercase().split(' ') {
            match token {
                "QR" => flags.qr = true,
                "AA" => flags.aa = true,
                "TC" => flags.tc = true,
                "RD" => flags.rd = true,
                "RA" => flags.ra = true,
                "AD" => flags.ad = true,
                "CD" => flags.cd = true,
                "" => {}
                _ => return Err(FlagsFromStrError),
            }
        }
        Ok(flags)
    }
}

//------------ HeaderCounts -------------------------------------------------

/// The section count part of the header section of a DNS message.
///
/// This part consists of four 16 bit counters for the number of entries in
/// the four sections of a DNS message. The type contains the sequence of
/// these for values in wire format, i.e., in network byte order.
///
/// The counters are arranged in the same order as the sections themselves:
/// QDCOUNT for the question section, ANCOUNT for the answer section,
/// NSCOUNT for the authority section, and ARCOUNT for the additional section.
/// These are defined in [RFC 1035].
///
/// Like with the other header part, you can create an owned value via the
/// [`new`][Self::new] method or the `Default` trait or can get a reference
/// to the value atop a message slice via
/// [`for_message_slice`][Self::for_message_slice] or
/// [`for_message_slice_mut`][Self::for_message_slice_mut].
///
/// For each field there are three methods for getting, setting, and
/// incrementing.
///
/// [RFC 2136] defines the UPDATE method and reuses the four section for
/// different purposes. Here the counters are ZOCOUNT for the zone section,
/// PRCOUNT for the prerequisite section, UPCOUNT for the update section,
/// and ADCOUNT for the additional section. The type has convenience methods
/// for these fields as well so you don’t have to remember which is which.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
/// [RFC 2136]: https://tools.ietf.org/html/rfc2136
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderCounts {
    /// The actual headers in their wire-format representation.
    ///
    /// Ie., all values are stored big endian.
    inner: [u8; 8],
}

/// # Creation and Conversion
///
impl HeaderCounts {
    /// Creates a new value with all counters set to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a header counts reference from the octets slice of a message.
    ///
    /// The slice `message` mut be the whole message, i.e., start with the
    /// bytes of the [`Header`](struct.Header.html).
    ///
    /// # Panics
    ///
    /// This function panics if the octets slice is shorter than 24 octets.
    pub fn for_message_slice(message: &[u8]) -> &Self {
        assert!(message.len() >= mem::size_of::<HeaderSection>());
        unsafe {
            &*((message[mem::size_of::<Header>()..].as_ptr())
                as *const HeaderCounts)
        }
    }

    /// Creates a mutable counts reference from the octets slice of a message.
    ///
    /// The slice `message` mut be the whole message, i.e., start with the
    /// bytes of the [`Header`].
    ///
    /// # Panics
    ///
    /// This function panics if the octets slice is shorter than 24 octets.
    pub fn for_message_slice_mut(message: &mut [u8]) -> &mut Self {
        assert!(message.len() >= mem::size_of::<HeaderSection>());
        unsafe {
            &mut *((message[mem::size_of::<Header>()..].as_ptr())
                as *mut HeaderCounts)
        }
    }

    /// Returns a reference to the raw octets slice of the header counts.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a mutable reference to the octets slice of the header counts.
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
    /// If increasing the counter would result in an overflow, returns an
    /// error.
    pub fn inc_qdcount(&mut self) -> Result<(), ShortBuf> {
        match self.qdcount().checked_add(1) {
            Some(count) => {
                self.set_qdcount(count);
                Ok(())
            }
            None => Err(ShortBuf),
        }
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
    /// If increasing the counter would result in an overflow, returns an
    /// error.
    pub fn inc_ancount(&mut self) -> Result<(), ShortBuf> {
        match self.ancount().checked_add(1) {
            Some(count) => {
                self.set_ancount(count);
                Ok(())
            }
            None => Err(ShortBuf),
        }
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
    /// If increasing the counter would result in an overflow, returns an
    /// error.
    pub fn inc_nscount(&mut self) -> Result<(), ShortBuf> {
        match self.nscount().checked_add(1) {
            Some(count) => {
                self.set_nscount(count);
                Ok(())
            }
            None => Err(ShortBuf),
        }
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
    /// If increasing the counter would result in an overflow, returns an
    /// error.
    pub fn inc_arcount(&mut self) -> Result<(), ShortBuf> {
        match self.arcount().checked_add(1) {
            Some(count) => {
                self.set_arcount(count);
                Ok(())
            }
            None => Err(ShortBuf),
        }
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
        u16::from_be_bytes(self.inner[offset..offset + 2].try_into().unwrap())
    }

    /// Sets the value of the 16 bit integer starting at a given offset.
    fn set_u16(&mut self, offset: usize, value: u16) {
        self.inner[offset..offset + 2].copy_from_slice(&value.to_be_bytes())
    }
}

//------------ HeaderSection -------------------------------------------------

/// The complete header section of a DNS message.
///
/// Consists of a [`Header`] directly followed by a [`HeaderCounts`].
///
/// You can create an owned value via the [`new`][Self::new] function or the
/// `Default` trait and acquire a pointer referring the the header section of
/// an existing DNS message via the
/// [`for_message_slice`][Self::for_message_slice] or
/// [`for_message_slice_mut`][Self::for_message_slice_mut]
/// functions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HeaderSection {
    inner: [u8; 12],
}

/// # Creation and Conversion
///
impl HeaderSection {
    /// Creates a new header section.
    ///
    /// The value will have all header and header counts fields set to zero
    /// or false.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a reference from the octets slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the the octets slice is shorter than 24
    /// octets.
    pub fn for_message_slice(s: &[u8]) -> &HeaderSection {
        assert!(s.len() >= mem::size_of::<HeaderSection>());
        unsafe { &*(s.as_ptr() as *const HeaderSection) }
    }

    /// Creates a mutable reference from the ocetets slice of a message.
    ///
    /// # Panics
    ///
    /// This function panics if the the octets slice is shorter than 24
    /// octets.
    pub fn for_message_slice_mut(s: &mut [u8]) -> &mut HeaderSection {
        assert!(s.len() >= mem::size_of::<HeaderSection>());
        unsafe { &mut *(s.as_ptr() as *mut HeaderSection) }
    }

    /// Returns a reference to the underlying octets slice.
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
        Header::for_message_slice_mut(&mut self.inner)
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

//--- AsRef and AsMut

impl AsRef<Header> for HeaderSection {
    fn as_ref(&self) -> &Header {
        self.header()
    }
}

impl AsMut<Header> for HeaderSection {
    fn as_mut(&mut self) -> &mut Header {
        self.header_mut()
    }
}

impl AsRef<HeaderCounts> for HeaderSection {
    fn as_ref(&self) -> &HeaderCounts {
        self.counts()
    }
}

impl AsMut<HeaderCounts> for HeaderSection {
    fn as_mut(&mut self) -> &mut HeaderCounts {
        self.counts_mut()
    }
}

//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for HeaderSection {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let mut res = Self::default();
        parser.parse_buf(&mut res.inner)?;
        Ok(res)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance(12)
    }
}

impl Compose for HeaderSection {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.inner)
    }
}

//============ Error Types ===================================================

//------------ FlagsFromStrError --------------------------------------------

/// An error happened when converting string to flags.
#[derive(Debug)]
pub struct FlagsFromStrError;

impl fmt::Display for FlagsFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal flags token")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FlagsFromStrError {}

//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::iana::{Opcode, Rcode};

    #[test]
    #[cfg(feature = "std")]
    fn for_slice() {
        use std::vec::Vec;

        let header = b"\x01\x02\x00\x00\x12\x34\x56\x78\x9a\xbc\xde\xf0";
        let mut vec = Vec::from(&header[..]);
        assert_eq!(
            Header::for_message_slice(header).as_slice(),
            b"\x01\x02\x00\x00"
        );
        assert_eq!(
            Header::for_message_slice_mut(vec.as_mut()).as_slice(),
            b"\x01\x02\x00\x00"
        );
        assert_eq!(
            HeaderCounts::for_message_slice(header).as_slice(),
            b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        );
        assert_eq!(
            HeaderCounts::for_message_slice_mut(vec.as_mut()).as_slice(),
            b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        );
        assert_eq!(
            HeaderSection::for_message_slice(header).as_slice(),
            header
        );
        assert_eq!(
            HeaderSection::for_message_slice_mut(vec.as_mut()).as_slice(),
            header
        );
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
        test_field!(
            flags,
            set_flags,
            Flags::new(),
            Flags {
                qr: true,
                ..Default::default()
            }
        );
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
        let mut c = HeaderCounts {
            inner: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(c.qdcount(), 0x0102);
        assert_eq!(c.ancount(), 0x0304);
        assert_eq!(c.nscount(), 0x0506);
        assert_eq!(c.arcount(), 0x0708);
        c.inc_qdcount().unwrap();
        c.inc_ancount().unwrap();
        c.inc_nscount().unwrap();
        c.inc_arcount().unwrap();
        assert_eq!(c.inner, [1, 3, 3, 5, 5, 7, 7, 9]);
        c.set_qdcount(0x0807);
        c.set_ancount(0x0605);
        c.set_nscount(0x0403);
        c.set_arcount(0x0201);
        assert_eq!(c.inner, [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn update_counts() {
        let mut c = HeaderCounts {
            inner: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(c.zocount(), 0x0102);
        assert_eq!(c.prcount(), 0x0304);
        assert_eq!(c.upcount(), 0x0506);
        assert_eq!(c.adcount(), 0x0708);
        c.set_zocount(0x0807);
        c.set_prcount(0x0605);
        c.set_upcount(0x0403);
        c.set_adcount(0x0201);
        assert_eq!(c.inner, [8, 7, 6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn inc_qdcount() {
        let mut c = HeaderCounts {
            inner: [0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        };
        assert!(c.inc_qdcount().is_ok());
        assert!(c.inc_qdcount().is_err());
    }

    #[test]
    fn inc_ancount() {
        let mut c = HeaderCounts {
            inner: [0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff],
        };
        assert!(c.inc_ancount().is_ok());
        assert!(c.inc_ancount().is_err());
    }

    #[test]
    fn inc_nscount() {
        let mut c = HeaderCounts {
            inner: [0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff],
        };
        assert!(c.inc_nscount().is_ok());
        assert!(c.inc_nscount().is_err());
    }

    #[test]
    fn inc_arcount() {
        let mut c = HeaderCounts {
            inner: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe],
        };
        assert!(c.inc_arcount().is_ok());
        assert!(c.inc_arcount().is_err());
    }

    #[test]
    fn flags_display() {
        let f = Flags::new();
        assert_eq!(format!("{}", f), "");
        let f = Flags {
            qr: true,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
        };
        assert_eq!(format!("{}", f), "QR AA TC RD RA AD CD");
        let mut f = Flags::new();
        f.rd = true;
        f.cd = true;
        assert_eq!(format!("{}", f), "RD CD");
    }

    #[test]
    fn flags_from_str() {
        let f1 = Flags::from_str("").unwrap();
        let f2 = Flags::new();
        assert_eq!(f1, f2);
        let f1 = Flags::from_str("QR AA TC RD RA AD CD").unwrap();
        let f2 = Flags {
            qr: true,
            aa: true,
            tc: true,
            rd: true,
            ra: true,
            ad: true,
            cd: true,
        };
        assert_eq!(f1, f2);
        let f1 = Flags::from_str("tC Aa CD rd").unwrap();
        let f2 = Flags {
            aa: true,
            tc: true,
            rd: true,
            cd: true,
            ..Default::default()
        };
        assert_eq!(f1, f2);
        let f1 = Flags::from_str("XXXX");
        assert!(f1.is_err());
    }
}
