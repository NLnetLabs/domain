//! DNS message headers.

use core::fmt;

use zerocopy::network_endian::U16;
use zerocopy_derive::*;

//----------- Message --------------------------------------------------------

/// A DNS message.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Message {
    /// The message header.
    pub header: Header,

    /// The message contents.
    pub contents: [u8],
}

//----------- Header ---------------------------------------------------------

/// A DNS message header.
#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct Header {
    /// A unique identifier for the message.
    pub id: U16,

    /// Properties of the message.
    pub flags: HeaderFlags,

    /// Counts of objects in the message.
    pub counts: SectionCounts,
}

//--- Formatting

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of ID {:04X} ({})",
            self.flags,
            self.id.get(),
            self.counts
        )
    }
}

//----------- HeaderFlags ----------------------------------------------------

/// DNS message header flags.
#[derive(
    Copy,
    Clone,
    Default,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct HeaderFlags {
    inner: U16,
}

//--- Interaction

impl HeaderFlags {
    /// Get the specified flag bit.
    fn get_flag(&self, pos: u32) -> bool {
        self.inner.get() & (1 << pos) != 0
    }

    /// Set the specified flag bit.
    fn set_flag(mut self, pos: u32, value: bool) -> Self {
        self.inner &= !(1 << pos);
        self.inner |= (value as u16) << pos;
        self
    }

    /// The raw flags bits.
    pub fn bits(&self) -> u16 {
        self.inner.get()
    }

    /// Whether this is a query.
    pub fn is_query(&self) -> bool {
        !self.get_flag(15)
    }

    /// Whether this is a response.
    pub fn is_response(&self) -> bool {
        self.get_flag(15)
    }

    /// The operation code.
    pub fn opcode(&self) -> u8 {
        (self.inner.get() >> 11) as u8 & 0xF
    }

    /// The response code.
    pub fn rcode(&self) -> u8 {
        self.inner.get() as u8 & 0xF
    }

    /// Construct a query.
    pub fn query(mut self, opcode: u8) -> Self {
        assert!(opcode < 16);
        self.inner &= !(0xF << 11);
        self.inner |= (opcode as u16) << 11;
        self.set_flag(15, false)
    }

    /// Construct a response.
    pub fn respond(mut self, rcode: u8) -> Self {
        assert!(rcode < 16);
        self.inner &= !0xF;
        self.inner |= rcode as u16;
        self.set_flag(15, true)
    }

    /// Whether this is an authoritative answer.
    pub fn is_authoritative(&self) -> bool {
        self.get_flag(10)
    }

    /// Mark this as an authoritative answer.
    pub fn set_authoritative(self, value: bool) -> Self {
        self.set_flag(10, value)
    }

    /// Whether this message is truncated.
    pub fn is_truncated(&self) -> bool {
        self.get_flag(9)
    }

    /// Mark this message as truncated.
    pub fn set_truncated(self, value: bool) -> Self {
        self.set_flag(9, value)
    }

    /// Whether the server should query recursively.
    pub fn should_recurse(&self) -> bool {
        self.get_flag(8)
    }

    /// Direct the server to query recursively.
    pub fn request_recursion(self, value: bool) -> Self {
        self.set_flag(8, value)
    }

    /// Whether the server supports recursion.
    pub fn can_recurse(&self) -> bool {
        self.get_flag(7)
    }

    /// Indicate support for recursive queries.
    pub fn support_recursion(self, value: bool) -> Self {
        self.set_flag(7, value)
    }
}

//--- Formatting

impl fmt::Debug for HeaderFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderFlags")
            .field("is_response (qr)", &self.is_response())
            .field("opcode", &self.opcode())
            .field("is_authoritative (aa)", &self.is_authoritative())
            .field("is_truncated (tc)", &self.is_truncated())
            .field("should_recurse (rd)", &self.should_recurse())
            .field("can_recurse (ra)", &self.can_recurse())
            .field("rcode", &self.rcode())
            .field("bits", &self.inner.get())
            .finish()
    }
}

impl fmt::Display for HeaderFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_query() {
            if self.should_recurse() {
                f.write_str("recursive ")?;
            }
            write!(f, "query (opcode {})", self.opcode())?;
        } else {
            if self.is_authoritative() {
                f.write_str("authoritative ")?;
            }
            if self.should_recurse() && self.can_recurse() {
                f.write_str("recursive ")?;
            }
            write!(f, "response (rcode {})", self.rcode())?;
        }

        if self.is_truncated() {
            f.write_str(" (message truncated)")?;
        }

        Ok(())
    }
}

//----------- SectionCounts --------------------------------------------------

/// Counts of objects in a DNS message.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(C)]
pub struct SectionCounts {
    /// The number of questions in the message.
    pub questions: U16,

    /// The number of answer records in the message.
    pub answers: U16,

    /// The number of name server records in the message.
    pub authorities: U16,

    /// The number of additional records in the message.
    pub additional: U16,
}

//--- Formatting

impl fmt::Display for SectionCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut some = false;

        for (num, single, many) in [
            (self.questions.get(), "question", "questions"),
            (self.answers.get(), "answer", "answers"),
            (self.authorities.get(), "authority", "authorities"),
            (self.additional.get(), "additional", "additional"),
        ] {
            // Add a comma if we have printed something before.
            if some && num > 0 {
                f.write_str(", ")?;
            }

            // Print a count of this section.
            match num {
                0 => {}
                1 => write!(f, "1 {single}")?,
                n => write!(f, "{n} {many}")?,
            }

            some |= num > 0;
        }

        if !some {
            f.write_str("empty")?;
        }

        Ok(())
    }
}
