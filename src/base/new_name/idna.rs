//! International Domain Names in Applications.

use core::{fmt, str};

use super::Label;

impl Label {
    /// Whether this could be an A-label.
    ///
    /// An A-label is defined by [RFC 5890, section 2.3.2.1] to be the ASCII
    /// encoding of an IDNA-valid label.  This method tests that the current
    /// label begins with the ACE (ASCII-Compatible Encoding) prefix `xn--`,
    /// like all A-labels.  It does not perform the more expensive validation
    /// that the label can be decoded into a Unicode string.
    ///
    /// [RFC 5890, section 2.3.2.1]: https://datatracker.ietf.org/doc/html/rfc5890#section-2.3.2.1
    pub fn has_ace_prefix(&self) -> bool {
        self.len() >= 4 && self.as_bytes()[..4].eq_ignore_ascii_case(b"xn--")
    }

    /// Decode this label into a Unicode string.
    ///
    /// If this is an A-label, the Punycode algorithm is applied to decode the
    /// ASCII label contents into Unicode characters.  If this is an NR-LDH
    /// label, it is copied into the output verbatim.
    pub fn to_unicode(
        &self,
        mut w: impl fmt::Write,
    ) -> Result<(), DecodeError> {
        // If this is an NR-LDH label, write it out and stop.
        if self.is_nr_ldh() {
            // SAFETY: The label consists of ASCII letters, digits, and
            //   hyphens, which never compose invalid UTF-8 strings.
            w.write_str(unsafe {
                str::from_utf8_unchecked(self.as_bytes())
            })?;

            return Ok(());
        } else if !self.has_ace_prefix() {
            // This is an R-LDH or non-LDH label.
            return Err(DecodeError::BadLabel);
        }

        // This is an implementation of the Punycode algorithm as specified in
        // RFC 3492 (https://datatracker.ietf.org/doc/html/rfc3492).  A number
        // of careful implementation decisions have been made in the interests
        // of performance.

        // An A-label consists of at most 63 characters.  The first 4 are the
        // ACE prefix, 'xn--'.  Assuming there are no ASCII characters to copy
        // to the output, there are 59 encoded characters.  If each character
        // results in the output of a Unicode character, there are 59 Unicode
        // characters (each at most 4 bytes) produced.  Thus, we only have to
        // contend with 59 characters at any time.

        let mut input = &self.as_bytes()[4..];

        // TODO: I believe there is a linear algorithm for sorting output
        // characters based on their positions.  For now, however, a simple
        // quadratic-time solution is used.

        // The decoder specifies where characters must be inserted in the
        // output string.  Inserting them immediately would yield quadratic
        // runtime as characters following the insertion point would have to
        // be copied every time.  Instead, we maintain an array of character
        // and insertion position; after decoding, this array is evaluated in
        // reverse to determine the correct insertion points in linear time.

        let mut output_chars = ['\0'; 59];
        let mut output_indices = [0u8; 59];
        let mut output_len = 0;

        // Copy over any ASCII characters directly into the output.

        if let Some(num_ascii) = input.iter().rposition(|&b| b == b'-') {
            for i in 0..num_ascii {
                output_chars[i] = input[i] as char;
                output_indices[i] = i as u8;
            }
            output_len += num_ascii;
            input = &input[num_ascii + 1..];
        }

        if input.is_empty() {
            // The ACE prefix shouldn't be used if there are no non-ASCII
            // characters in the label.
            return Err(DecodeError::BadLabel);
        }

        // Determine the "digit-value" for every remaining character.

        let mut input_values = [0u8; 59];

        for (i, &b) in input.iter().enumerate() {
            // 'A'..'Z' =>  0..25
            // 'a'..'z' =>  0..25
            // '0'..'9' => 26..35
            if b.is_ascii_uppercase() {
                input_values[i] = b - b'A';
            } else if b.is_ascii_lowercase() {
                input_values[i] = b - b'a';
            } else if b.is_ascii_digit() {
                input_values[i] = b - b'0' + 26;
            } else {
                return Err(DecodeError::BadLabel);
            }
        }

        let mut input = &input_values[..input.len()];

        // Begin decoding Unicode characters.

        let mut n = 128u32;
        let mut i = 0u32;
        let mut bias = 72;
        let mut first = true;
        while !input.is_empty() {
            // Find the end of the current variable-width integer.
            let end = input
                .iter()
                .enumerate()
                .position(|(k, &b)| {
                    let t = ((k + 1) * 36).saturating_sub(bias).clamp(1, 26);
                    b < t as u8
                })
                .ok_or(DecodeError::BadLabel)?;
            input = &input[end + 1..];

            // Compute the variable-width integer.
            let int = input[..end]
                .iter()
                .enumerate()
                .map(|(k, &v)| {
                    let t = ((k + 1) * 36).saturating_sub(bias).clamp(1, 26);
                    (t as u8, v)
                })
                .try_rfold(input[end] as u32, |int, (t, v)| {
                    int.checked_mul(36 - t as u32)?.checked_add(v as u32)
                })
                .ok_or(DecodeError::BadLabel)?;

            // Update the bias value.
            bias = punycode_adapt(int, output_len as u8 + 1, first) as usize;
            i = i.checked_add(int).ok_or(DecodeError::BadLabel)?;

            // Save the decoded position-character pair.
            n += i / (output_len as u32 + 1);
            i %= output_len as u32 + 1;
            output_chars[output_len] =
                char::try_from(n).map_err(|_| DecodeError::BadLabel)?;
            output_indices[output_len] = i as u8;
            output_len += 1;

            // Prepare for the next iteration.
            first = false;
            i += 1;
        }

        // Build up the output string.
        todo!()
    }
}

/// Adjust the Punycode transcoding bias.
fn punycode_adapt(mut delta: u32, length: u8, first: bool) -> u32 {
    delta /= if first { 700 } else { 2 };
    delta += delta / length as u32;
    let mut k = 0;
    while delta > 455 {
        delta /= 35;
        k += 1;
    }
    k + (36 * delta) / (38 + delta)
}

/// A decoding error.
pub enum DecodeError {
    /// The label was not an NR-LDH label or an A-label.
    ///
    /// The label may have been:
    /// - An R-LDH label (the decoding process is unknown).
    /// - A non-LDH label (all ASCII, but not in the preferred name syntax).
    /// - A non-ASCII label.
    BadLabel,

    /// The output stream could not be written to.
    Fmt(fmt::Error),
}

impl From<fmt::Error> for DecodeError {
    fn from(value: fmt::Error) -> Self {
        Self::Fmt(value)
    }
}
