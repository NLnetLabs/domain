//! DNS message headers.

use core::fmt;

use domain_macros::*;

use super::wire::{AsBytes, ParseBytesByRef, U16};

//----------- Message --------------------------------------------------------

/// A DNS message.
#[derive(AsBytes, BuildBytes, ParseBytesByRef, UnsizedClone)]
#[repr(C, packed)]
pub struct Message {
    /// The message header.
    pub header: Header,

    /// The message contents.
    pub contents: [u8],
}

//--- Inspection

impl Message {
    /// Represent this as a mutable byte sequence.
    ///
    /// Given `&mut self`, it is already possible to individually modify the
    /// message header and contents; since neither has invalid instances, it
    /// is safe to represent the entire object as mutable bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY:
        // - 'Self' has no padding bytes and no interior mutability.
        // - Its size in memory is exactly 'size_of_val(self)'.
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

//--- Interaction

impl Message {
    /// Truncate the contents of this message to the given size.
    ///
    /// The returned value will have a `contents` field of the given size.
    pub fn truncate(&self, size: usize) -> &Self {
        let bytes = &self.as_bytes()[..12 + size];
        // SAFETY: 'bytes' is at least 12 bytes, making it a valid 'Message'.
        unsafe { Self::parse_bytes_by_ref(bytes).unwrap_unchecked() }
    }

    /// Truncate the contents of this message to the given size, mutably.
    ///
    /// The returned value will have a `contents` field of the given size.
    pub fn truncate_mut(&mut self, size: usize) -> &mut Self {
        let bytes = &mut self.as_bytes_mut()[..12 + size];
        // SAFETY: 'bytes' is at least 12 bytes, making it a valid 'Message'.
        unsafe { Self::parse_bytes_by_mut(bytes).unwrap_unchecked() }
    }

    /// Truncate the contents of this message to the given size, by pointer.
    ///
    /// The returned value will have a `contents` field of the given size.
    ///
    /// # Safety
    ///
    /// This method uses `pointer::offset()`: `self` must be "derived from a
    /// pointer to some allocated object".  There must be at least 12 bytes
    /// between `self` and the end of that allocated object.  A reference to
    /// `Message` will always result in a pointer satisfying this.
    pub unsafe fn truncate_ptr(this: *mut Message, size: usize) -> *mut Self {
        // Extract the metadata from 'this'.  We know it's slice metadata.
        //
        // SAFETY: '[()]' is a zero-sized type and references to it can be
        // created from arbitrary pointers, since every pointer is valid for
        // zero-sized reads.
        let len = unsafe { &*(this as *mut [()]) }.len();
        // Replicate the range check performed by normal indexing operations.
        debug_assert!(size <= len);
        core::ptr::slice_from_raw_parts_mut(this.cast::<u8>(), size)
            as *mut Self
    }
}

//----------- Header ---------------------------------------------------------

/// A DNS message header.
#[derive(
    Copy,
    Clone,
    Debug,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct HeaderFlags {
    inner: U16,
}

//--- Interaction

impl HeaderFlags {
    /// Get the specified flag bit.
    const fn get_flag(&self, pos: u32) -> bool {
        self.inner.get() & (1 << pos) != 0
    }

    /// Set the specified flag bit.
    fn set_flag(&mut self, pos: u32, value: bool) -> &mut Self {
        self.inner &= !(1 << pos);
        self.inner |= (value as u16) << pos;
        self
    }

    /// The raw flags bits.
    pub const fn bits(&self) -> u16 {
        self.inner.get()
    }

    /// The QR bit.
    pub const fn qr(&self) -> bool {
        self.get_flag(15)
    }

    /// Set the QR bit.
    pub fn set_qr(&mut self, value: bool) -> &mut Self {
        self.set_flag(15, value)
    }

    /// The OPCODE field.
    pub const fn opcode(&self) -> u8 {
        (self.inner.get() >> 11) as u8 & 0xF
    }

    /// Set the OPCODE field.
    pub fn set_opcode(&mut self, value: u8) -> &mut Self {
        debug_assert!(value < 16);
        self.inner &= !(0xF << 11);
        self.inner |= (value as u16) << 11;
        self
    }

    /// The AA bit.
    pub fn aa(&self) -> bool {
        self.get_flag(10)
    }

    /// Set the AA bit.
    pub fn set_aa(&mut self, value: bool) -> &mut Self {
        self.set_flag(10, value)
    }

    /// The TC bit.
    pub fn tc(&self) -> bool {
        self.get_flag(9)
    }

    /// Set the TC bit.
    pub fn set_tc(&mut self, value: bool) -> &mut Self {
        self.set_flag(9, value)
    }

    /// The RD bit.
    pub fn rd(&self) -> bool {
        self.get_flag(8)
    }

    /// Set the RD bit.
    pub fn set_rd(&mut self, value: bool) -> &mut Self {
        self.set_flag(8, value)
    }

    /// The RA bit.
    pub fn ra(&self) -> bool {
        self.get_flag(7)
    }

    /// Set the RA bit.
    pub fn set_ra(&mut self, value: bool) -> &mut Self {
        self.set_flag(7, value)
    }

    /// The AD bit.
    pub fn ad(&self) -> bool {
        self.get_flag(5)
    }

    /// Set the AD bit.
    pub fn set_ad(&mut self, value: bool) -> &mut Self {
        self.set_flag(5, value)
    }

    /// The CD bit.
    pub fn cd(&self) -> bool {
        self.get_flag(4)
    }

    /// Set the CD bit.
    pub fn set_cd(&mut self, value: bool) -> &mut Self {
        self.set_flag(4, value)
    }

    /// The RCODE field.
    pub const fn rcode(&self) -> u8 {
        self.inner.get() as u8 & 0xF
    }

    /// Set the RCODE field.
    pub fn set_rcode(&mut self, value: u8) -> &mut Self {
        debug_assert!(value < 16);
        self.inner &= !0xF;
        self.inner |= value as u16;
        self
    }
}

//--- Formatting

impl fmt::Debug for HeaderFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderFlags")
            .field("qr", &self.qr())
            .field("opcode", &self.opcode())
            .field("aa", &self.aa())
            .field("tc", &self.tc())
            .field("rd", &self.rd())
            .field("ra", &self.ra())
            .field("rcode", &self.rcode())
            .field("bits", &self.bits())
            .finish()
    }
}

impl fmt::Display for HeaderFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.qr() {
            if self.rd() {
                f.write_str("recursive ")?;
            }
            write!(f, "query (opcode {})", self.opcode())?;
            if self.cd() {
                f.write_str(" (checking disabled)")?;
            }
        } else {
            if self.ad() {
                f.write_str("authentic ")?;
            }
            if self.aa() {
                f.write_str("authoritative ")?;
            }
            if self.rd() && self.ra() {
                f.write_str("recursive ")?;
            }
            write!(f, "response (rcode {})", self.rcode())?;
        }

        if self.tc() {
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
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
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

//--- Interaction

impl SectionCounts {
    /// Represent these counts as an array.
    pub fn as_array(&self) -> &[U16; 4] {
        // SAFETY: 'SectionCounts' has the same layout as '[U16; 4]'.
        unsafe { core::mem::transmute(self) }
    }

    /// Represent these counts as a mutable array.
    pub fn as_array_mut(&mut self) -> &mut [U16; 4] {
        // SAFETY: 'SectionCounts' has the same layout as '[U16; 4]'.
        unsafe { core::mem::transmute(self) }
    }
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
