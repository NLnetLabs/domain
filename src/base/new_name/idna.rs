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
            input = &input[end + 1..];
            first = false;
            i += 1;
        }

        let mut output = ['\0'; 59];
        for i in 0..output_len {
            let o = output_indices[i] as usize;
            output.copy_within(o..i, o + 1);
            output[o] = output_chars[i];
        }

        // TODO: Verify the properties of this U-label.

        for i in 0..output_len {
            w.write_char(output[i])?;
        }

        Ok(())
    }
}

/// Adjust the Punycode transcoding bias.
fn punycode_adapt(mut delta: u32, length: u8, first: bool) -> u32 {
    delta /= if first { 700 } else { 2 };
    delta += delta / length as u32;
    let mut k = 0;
    while delta > 455 {
        delta /= 35;
        k += 36;
    }
    k + (36 * delta) / (38 + delta)
}

/// A decoding error.
#[derive(Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use std::string::String;

    use crate::base::new_name::Label;

    #[test]
    fn rfc3492_samples() {
        const A_LABELS: &[&[u8]] = &[
            b"xn--egbpdaj6bu4bxfgehfvwxn",
            b"xn--ihqwcrb4cv8a8dqg056pqjye",
            b"xn--ihqwctvzc91f659drss3x8bo0yb",
            b"xn--Proprostnemluvesky-uyb24dma41a",
            b"xn--4dbcagdahymbxekheh6e0a7fei0b",
            b"xn--i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd",
            b"xn--n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa",
            b"xn--b1abfaaepdrnnbgefbaDotcwatmq2g4l",
            b"xn--PorqunopuedensimplementehablarenEspaol-fmd56a",
            b"xn--TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g",
            b"xn--3B-ww4c5e180e575a65lsy2b",
            b"xn---with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n",
            b"xn--Hello-Another-Way--fc4qua05auwb3674vfr0b",
            b"xn--2-u9tlzr9756bt3uc0v",
            b"xn--MajiKoi5-783gue6qz075azm5e",
            b"xn--de-jg4avhby1noc0d",
            b"xn--d9juau41awczczp",
        ];

        const U_LABELS: &[&str] = &[
            "\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}",
            "\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}",
            "\u{4ED6}\u{5011}\u{7232}\u{4EC0}\u{9EBD}\u{4E0D}\u{8AAA}\u{4E2D}\u{6587}",
            "\u{0050}\u{0072}\u{006F}\u{010D}\u{0070}\u{0072}\u{006F}\u{0073}\u{0074}\u{011B}\u{006E}\u{0065}\u{006D}\u{006C}\u{0075}\u{0076}\u{00ED}\u{010D}\u{0065}\u{0073}\u{006B}\u{0079}",
            "\u{05DC}\u{05DE}\u{05D4}\u{05D4}\u{05DD}\u{05E4}\u{05E9}\u{05D5}\u{05D8}\u{05DC}\u{05D0}\u{05DE}\u{05D3}\u{05D1}\u{05E8}\u{05D9}\u{05DD}\u{05E2}\u{05D1}\u{05E8}\u{05D9}\u{05EA}",
            "\u{092F}\u{0939}\u{0932}\u{094B}\u{0917}\u{0939}\u{093F}\u{0928}\u{094D}\u{0926}\u{0940}\u{0915}\u{094D}\u{092F}\u{094B}\u{0902}\u{0928}\u{0939}\u{0940}\u{0902}\u{092C}\u{094B}\u{0932}\u{0938}\u{0915}\u{0924}\u{0947}\u{0939}\u{0948}\u{0902}",
            "\u{306A}\u{305C}\u{307F}\u{3093}\u{306A}\u{65E5}\u{672C}\u{8A9E}\u{3092}\u{8A71}\u{3057}\u{3066}\u{304F}\u{308C}\u{306A}\u{3044}\u{306E}\u{304B}",
            "\u{043F}\u{043E}\u{0447}\u{0435}\u{043C}\u{0443}\u{0436}\u{0435}\u{043E}\u{043D}\u{0438}\u{043D}\u{0435}\u{0433}\u{043E}\u{0432}\u{043E}\u{0440}\u{044F}\u{0442}\u{043F}\u{043E}\u{0440}\u{0443}\u{0441}\u{0441}\u{043A}\u{0438}",
            "\u{0050}\u{006F}\u{0072}\u{0071}\u{0075}\u{00E9}\u{006E}\u{006F}\u{0070}\u{0075}\u{0065}\u{0064}\u{0065}\u{006E}\u{0073}\u{0069}\u{006D}\u{0070}\u{006C}\u{0065}\u{006D}\u{0065}\u{006E}\u{0074}\u{0065}\u{0068}\u{0061}\u{0062}\u{006C}\u{0061}\u{0072}\u{0065}\u{006E}\u{0045}\u{0073}\u{0070}\u{0061}\u{00F1}\u{006F}\u{006C}",
            "\u{0054}\u{1EA1}\u{0069}\u{0073}\u{0061}\u{006F}\u{0068}\u{1ECD}\u{006B}\u{0068}\u{00F4}\u{006E}\u{0067}\u{0074}\u{0068}\u{1EC3}\u{0063}\u{0068}\u{1EC9}\u{006E}\u{00F3}\u{0069}\u{0074}\u{0069}\u{1EBF}\u{006E}\u{0067}\u{0056}\u{0069}\u{1EC7}\u{0074}",
            "\u{0033}\u{5E74}\u{0042}\u{7D44}\u{91D1}\u{516B}\u{5148}\u{751F}",
            "\u{5B89}\u{5BA4}\u{5948}\u{7F8E}\u{6075}\u{002D}\u{0077}\u{0069}\u{0074}\u{0068}\u{002D}\u{0053}\u{0055}\u{0050}\u{0045}\u{0052}\u{002D}\u{004D}\u{004F}\u{004E}\u{004B}\u{0045}\u{0059}\u{0053}",
            "\u{0048}\u{0065}\u{006C}\u{006C}\u{006F}\u{002D}\u{0041}\u{006E}\u{006F}\u{0074}\u{0068}\u{0065}\u{0072}\u{002D}\u{0057}\u{0061}\u{0079}\u{002D}\u{305D}\u{308C}\u{305E}\u{308C}\u{306E}\u{5834}\u{6240}",
            "\u{3072}\u{3068}\u{3064}\u{5C4B}\u{6839}\u{306E}\u{4E0B}\u{0032}",
            "\u{004D}\u{0061}\u{006A}\u{0069}\u{3067}\u{004B}\u{006F}\u{0069}\u{3059}\u{308B}\u{0035}\u{79D2}\u{524D}",
            "\u{30D1}\u{30D5}\u{30A3}\u{30FC}\u{0064}\u{0065}\u{30EB}\u{30F3}\u{30D0}",
            "\u{305D}\u{306E}\u{30B9}\u{30D4}\u{30FC}\u{30C9}\u{3067}",
        ];

        for (&a, &u) in core::iter::zip(A_LABELS, U_LABELS) {
            let a_label = Label::from_bytes(a).unwrap();
            let mut u_label = String::new();
            a_label.to_unicode(&mut u_label).unwrap();
            assert_eq!(&u_label, u);
        }
    }
}
