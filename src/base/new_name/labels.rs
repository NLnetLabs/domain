use super::Label;

/// An iterator over the labels in a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Labels<'a> {
    /// The absolute or relative name.
    name: &'a [u8],
}

impl<'a> Labels<'a> {
    /// Assume a byte string contains valid labels.
    ///
    /// # Safety
    ///
    /// The byte string must be a valid absolute or relative domain name.
    pub const unsafe fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        Self { name: bytes }
    }

    /// Retrieve the remaining bytes to be iterated over.
    pub const fn remaining(&self) -> &'a [u8] {
        self.name
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        // Based on 'Label::split_off()'.
        let (&size, name) = self.name.split_first()?;
        let (label, name) = name.split_at(size as usize);
        self.name = name;

        // SAFETY: 'label' is from a valid name.
        Some(unsafe { Label::from_bytes_unchecked(label) })
    }
}
