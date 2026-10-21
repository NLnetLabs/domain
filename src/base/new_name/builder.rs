use super::{Label, Name, NameError, RelName};

/// An incremental builder for domain names.
///
/// This type can be used to build up a domain name from a sequence of labels or
/// even simple bytes.  It can be used to concatenate or modify domain names.
///
/// The name is written into a 256-byte buffer.  This buffer can be placed on
/// the stack as it will not grow dynamically.  By requiring the buffer to have
/// a fixed size, the builder is simpler and faster.
///
/// # Building Labels
///
/// The builder may be in the middle of constructing a label.  It reaches this
/// state using [`begin_label()`], it must be in it to call [`write_slice()`],
/// and it exits this state using [`end_label()`].  At initialization, no label
/// is being built, so [`begin_label()`] must be called.
///
/// [`begin_label()`]: Self::begin_label()
/// [`write_slice()`]: Self::write_slice()
/// [`end_label()`]: Self::end_label()
///
/// Importantly, the root label (which is empty) cannot be ended explicitly.  To
/// write a root label, begin a new label by calling [`begin_label()`] and then
/// do not call [`end_label()`], directly going to [`get_name()`].
///
/// [`get_name()`]: Self::get_name()
///
/// When the builder is not in the middle of a label, convenience methods like
/// [`write_label()`], [`write_rel_name()`], and [`write_name()`] are available.
///
/// [`write_label()`]: Self::write_label()
/// [`write_rel_name()`]: Self::write_rel_name()
/// [`write_name()`]: Self::write_name()
#[derive(Clone, Default)]
pub struct NameBuilder<Buffer> {
    /// The offset the next byte will be written to.
    ///
    /// Invariants:
    ///
    /// - `write_offset <= 255`
    write_offset: u8,

    /// The offset of the current label.
    ///
    /// This is the position of the length byte of the current label.
    ///
    /// Invariants:
    ///
    /// - `label_offset < 255`
    /// - `label_offset <= write_offset`
    /// - if `label_offset < write_offset`:
    ///   - `buffer[label_offset] == 0`
    /// - `write_offset - label_offset <= 64`
    label_offset: u8,

    /// The name being constructed.
    buffer: Buffer,
}

/// # Initialization
impl<Buffer> NameBuilder<Buffer> {
    /// Construct a new [`NameBuilder`] over the given buffer.
    ///
    /// Any existing contents of the buffer will be overwritten by the builder
    /// (either upon this function call or later).  They should not be relied
    /// upon.
    #[must_use]
    pub const fn new(buffer: Buffer) -> Self {
        // TODO: Do we want to zero the buffer already?  Check benchmarks.

        Self {
            write_offset: 0,
            label_offset: 0,
            buffer,
        }
    }
}

/// # Inspection
impl<Buffer: AsRef<[u8]>> NameBuilder<Buffer> {
    /// Whether a label is currently being built.
    ///
    /// This is true in the time between [`begin_label()`] and [`end_label()`].
    ///
    /// [`begin_label()`]: Self::begin_label()
    /// [`end_label()`]: Self::end_label()
    pub fn mid_label(&self) -> bool {
        self.label_offset < self.write_offset
    }

    /// The label currently being built, if any.
    pub fn cur_label(&self) -> Option<&Label> {
        if self.label_offset < self.write_offset {
            let start = self.label_offset as usize + 1;
            let end = self.write_offset as usize;
            let label = &self.buffer.as_ref()[start..end];
            // SAFETY: The label is built correctly.
            Some(unsafe { Label::from_bytes_unchecked(label) })
        } else {
            None
        }
    }

    /// The length of the name built this far.
    ///
    /// This does not include the length of any partially-built label.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.label_offset as usize
    }

    /// The length of the name built this far.
    ///
    /// This includes the length of any partially-built label.
    pub fn total_len(&self) -> usize {
        self.write_offset as usize
    }

    /// The name built thus far.
    ///
    /// This does not include any partially-built label.
    pub fn cur_name(&self) -> &RelName {
        let name = &self.buffer.as_ref()[..self.label_offset as usize];
        // SAFETY: The name is built correctly.
        unsafe { RelName::from_bytes_unchecked(name) }
    }
}

/// # Construction
impl<Buffer: AsMut<[u8]>> NameBuilder<Buffer> {
    /// Begin a new label.
    ///
    /// A length byte for the label is allocated in the buffer.  It is left
    /// uninitialized -- it will be written to once the entire label is ready.
    ///
    /// # Panics
    ///
    /// Panics if a label is already being built.
    pub fn begin_label(&mut self) {
        assert!(
            self.label_offset == self.write_offset,
            "begin_label() was called before a previous label was ended"
        );

        // In case of the root label, 'end_label()' will not be called; we need
        // to set the length byte to 0 right now as we won't have a chance to do
        // it later.
        self.buffer.as_mut()[self.write_offset as usize] = 0;

        // Since 'label_offset < 255', this will not overflow.
        self.write_offset += 1;
    }

    /// Write a slice to a label.
    ///
    /// # Errors
    ///
    /// Fails if the bytes being written would make the label too long (64 bytes
    /// or more) or the entire name too long (256 bytes or more, including the
    /// 1-byte root label, which will follow the current bytes).
    ///
    /// # Panics
    ///
    /// Panics if no label is being built.
    pub fn write_slice(&mut self, data: &[u8]) -> Result<(), OverlongError> {
        assert!(
            self.label_offset < self.write_offset,
            "begin_label() must be called before using write_slice()"
        );

        if self.write_offset as usize + data.len()
            >= self.label_offset as usize + 1 + 64
        {
            // The label would become 64 bytes or larger.
            return Err(OverlongError);
        } else if self.write_offset as usize + data.len() + 1 > 255 {
            // The domain name would become 256 bytes or larger.
            return Err(OverlongError);
        }

        let buffer = &mut self.buffer.as_mut()[self.write_offset as usize..];
        buffer[..data.len()].copy_from_slice(data);
        self.write_offset += data.len() as u8;

        Ok(())
    }

    /// End a label being built.
    ///
    /// The length byte for the label will be updated.
    ///
    /// This must not be called on the root label.
    ///
    /// # Errors
    ///
    /// Fails if the label being built is empty.
    ///
    /// # Panics
    ///
    /// Panics if no label is being built.
    pub fn end_label(&mut self) -> Result<(), EmptyLabelError> {
        assert!(
            self.label_offset < self.write_offset,
            "begin_label() must be called before using end_label()"
        );

        if self.write_offset <= self.label_offset + 1 {
            return Err(EmptyLabelError);
        }

        let len = self.write_offset - (self.label_offset + 1);
        self.buffer.as_mut()[self.label_offset as usize] = len;
        self.label_offset = self.write_offset;

        Ok(())
    }
}

/// # Convenience Methods
impl<Buffer: AsMut<[u8]>> NameBuilder<Buffer> {
    /// Append a whole label to the name.
    ///
    /// This will start a new label, write the provided label into the buffer,
    /// and complete it immediately.  It is convenient to use if a whole label
    /// is to be written, rather than being built incrementally.
    ///
    /// # Errors
    ///
    /// Fails if the label is empty or if adding the label would make the domain
    /// name too large.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn write_label(&mut self, label: &Label) -> Result<(), BuildError> {
        assert!(
            self.label_offset == self.write_offset,
            "write_label() was called before a previous label was ended"
        );

        if self.write_offset as usize + 1 + label.len() + 1 > 255 {
            // The domain name would become 256 bytes or larger.
            return Err(OverlongError.into());
        }

        let buffer = &mut self.buffer.as_mut()[self.write_offset as usize..];
        buffer[0] = label.len() as u8;
        buffer[1..1 + label.len()].copy_from_slice(label.as_bytes());
        self.write_offset += 1 + label.len() as u8;
        self.label_offset += 1 + label.len() as u8;

        Ok(())
    }

    /// Append a relative name to the name.
    ///
    /// # Errors
    ///
    /// Fails if appending the given name would make the domain name too large.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn write_rel_name(
        &mut self,
        name: &RelName,
    ) -> Result<(), OverlongError> {
        assert!(
            self.label_offset == self.write_offset,
            "write_rel_name() was called before a previous label was ended"
        );

        if self.write_offset as usize + name.len() + 1 > 255 {
            // The domain name would become 256 bytes or larger.
            return Err(OverlongError);
        }

        self.buffer.as_mut()[self.write_offset as usize..][..name.len()]
            .copy_from_slice(name.as_bytes());
        self.write_offset += name.len() as u8;
        self.label_offset += name.len() as u8;

        Ok(())
    }

    /// Append an absolute name to the name.
    ///
    /// # Errors
    ///
    /// Fails if appending the given name would make the domain name too large.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn write_name(&mut self, name: &Name) -> Result<(), OverlongError> {
        assert!(
            self.label_offset == self.write_offset,
            "write_name() was called before a previous label was ended"
        );

        if self.write_offset as usize + name.len() > 255 {
            // The domain name would become 256 bytes or larger.
            return Err(OverlongError);
        }

        self.buffer.as_mut()[self.write_offset as usize..][..name.len()]
            .copy_from_slice(name.as_bytes());
        self.write_offset += name.len() as u8;
        self.label_offset += name.len() as u8 - 1;

        Ok(())
    }
}

/// # Extraction
impl<Buffer: AsRef<[u8]>> NameBuilder<Buffer> {
    /// Extract an absolute domain name.
    ///
    /// # Errors
    ///
    /// If a root label is not present, a [`NameError`] is returned.
    ///
    /// # Panics
    ///
    /// Panics if a label (except the root label) is still being built.
    pub fn get_name(&self) -> Result<&Name, NameError> {
        assert!(
            self.write_offset <= self.label_offset + 1,
            "get_name() was called before a previous label was ended"
        );

        if self.write_offset != self.label_offset + 1 {
            return Err(NameError);
        }

        let name = &self.buffer.as_ref()[..self.write_offset as usize];
        // SAFETY: The name is built correctly.
        Ok(unsafe { Name::from_bytes_unchecked(name) })
    }

    /// Extract a relative domain name.
    ///
    /// # Panics
    ///
    /// Panics if a label (including the root label) is still being built.
    pub fn get_rel_name(&self) -> &RelName {
        assert!(
            self.write_offset <= self.label_offset + 1,
            "get_rel_name() was called before a previous label was ended"
        );

        let name = &self.buffer.as_ref()[..self.write_offset as usize];
        // SAFETY: The name is built correctly.
        unsafe { RelName::from_bytes_unchecked(name) }
    }
}

/// An error in building a domain name.
pub enum BuildError {
    /// A domain name or label was too long.
    Overlong(OverlongError),

    /// A (non-root) label was empty.
    EmptyLabel(EmptyLabelError),
}

impl From<OverlongError> for BuildError {
    fn from(value: OverlongError) -> Self {
        Self::Overlong(value)
    }
}

impl From<EmptyLabelError> for BuildError {
    fn from(value: EmptyLabelError) -> Self {
        Self::EmptyLabel(value)
    }
}

/// A domain name or label was too long.
pub struct OverlongError;

/// A (non-root) label was empty.
pub struct EmptyLabelError;
