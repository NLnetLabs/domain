//! Scanning entries in a zonefile.
//!
//! Following the [specification] used by this implementation, a zone file is
//! a sequence of entries.  This low-level module allows a zone file to be
//! separated into individual entries, without actually parsing the contents
//! of each entry.  Since entries are separated by newlines (except within
//! parentheses), this module only focuses on finding the right newlines.
//!
//! [specification]: super#specification
//!
//! ## Usage
//!
//! Simply create an [`Entries`] scanner over some I/O source, and repeatedly
//! call [`next_entry()`](Entries::next_entry()).  If an error occurs, [`Err`]
//! is returned; when the zonefile finishes, `Ok(None)` is returned.  The
//! returned [`Entry`] objects provide the raw content of each entry as well
//! as the line numbers they spanned.
//!
//! ```
//! # use domain::new::zonefile::entries::Entries;
//! // Any type implementing 'std::io::BufRead' is appropriate.
//! let zonefile = b"Hello World!; (hi!)\nThis (entry\nspans\nlines)\n".as_slice();
//! let mut expected = [
//!     b"Hello World!".as_slice(),
//!     b"This entry\nspans\nlines".as_slice(),
//! ].into_iter();
//! let mut entries = Entries::new(zonefile);
//! while let Some(entry) = entries.next_entry().unwrap() {
//!     assert_eq!(entry.content, expected.next().unwrap());
//! }
//! ```

use core::{fmt, ops::Range};
use std::{io, vec::Vec};

//----------- Entries --------------------------------------------------------

/// The entries in a zonefile.
///
/// This is a streaming parser that loads one whole entry (which is a a record
/// or a zonefile directive) from an I/O source.  It does the minimal amount
/// of work to correctly distinguish entries from each other, and doesn't try
/// to catch all possible syntax errors.  It is the user's responsibily to try
/// parsing the contents of each entry and discover errors.
///
/// Note that this type does not implement [`Iterator`].  A single buffer is
/// used to store every entry, and it is returned by reference (which is not
/// compatible with the [`Iterator`] interface).  Users are expected to parse
/// the entry in place instead of copying the data out, minimizing the number
/// of memory allocations required.
///
/// See the [module-level documentation](self) for an example.
#[derive(Clone, Debug)]
pub struct Entries<R: io::BufRead> {
    /// The zonefile source.
    source: R,

    /// The current entry.
    entry: Vec<u8>,

    /// The current line number.
    line_number: usize,
}

//--- Construction

impl<R: io::BufRead> Entries<R> {
    /// Construct a new [`Entries`].
    ///
    /// The zonefile will be read from the given source.  It is assumed that
    /// the reader is situated at the start of the first line (line 1).
    pub fn new(source: R) -> Self {
        Self::with_line_number(source, 1)
    }

    /// Construct a new [`Entries`] from a specific line number.
    ///
    /// The zonefile will be read from the given source.  It is assumed that
    /// the reader is situated at the start of the specified line (where the
    /// first line in a file should be line 1).
    pub fn with_line_number(source: R, line_number: usize) -> Self {
        Self {
            source,
            entry: Vec::new(),
            line_number,
        }
    }
}

//--- Inspection

impl<R: io::BufRead> Entries<R> {
    /// The zonefile source.
    ///
    /// Some I/O readers can be modified through a shared reference (e.g.
    /// [`File`](std::fs::File)).  This may cause the [`Entries`] to report
    /// errors incorrectly, or to report incorrect line numbers for entries.
    pub fn source(&self) -> &R {
        &self.source
    }

    /// The current line number.
    ///
    /// This is the line number of the next character in the source.  This may
    /// be different from the line number of the next returned entry (as the
    /// source may contain a blank line).
    pub fn line_number(&self) -> usize {
        self.line_number
    }

    /// Deconstruct the [`Entries`].
    ///
    /// The original source and the current line number (the line number of
    /// the next character in the source) are returned.  The original object
    /// can be reconstructed using [`Entries::with_line_number()`].
    pub fn into_parts(self) -> (R, usize) {
        (self.source, self.line_number)
    }
}

//--- Interaction

impl<R: io::BufRead> Entries<R> {
    // NOTE: Most functions here are essentially tail-recursive, but Rust
    // doesn't give us a way to mandate that.  In debug builds, the stack
    // could overflow.  To be careful, we just implement loops explicitly.

    /// Retrieve the next entry from the zonefile.
    pub fn next_entry(&mut self) -> Result<Option<Entry<'_>>, EntriesError> {
        // Loop over entries and blank lines in the source.
        loop {
            // Clear the entry buffer from any previous (attempted) entry.
            self.entry.clear();

            // We try to avoid writing to the entry buffer unless we know that
            // we are writing out an actual entry, and not a blank line.  This
            // won't work if the zonefile source buffer is too small to find a
            // non-whitespace character on the line.

            let Some((pos, first)) = self.skip_leading_ws()? else {
                return Ok(None);
            };

            // Determine the nature of this line based on the first character.
            match first {
                b'\n' => {
                    // This was a blank line.  Skip past it and try again.
                    self.source.consume(pos + 1);
                    self.line_number += 1;
                }

                b';' => {
                    // This was a blank line with a comment.  Skip past the
                    // comment and try again.
                    self.source.consume(pos + 1);
                    let Some(()) = self.skip_comment()? else {
                        return Ok(None);
                    };
                }

                _ => {
                    // This line has an actual entry.  Copy all the leading
                    // whitespace and drop down to actual parsing.
                    let buffer = self.source.fill_buf()?;
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos);
                    return self.scan_entry().map(Some);
                }
            }
        }
    }

    /// Skip past leading whitespace.
    ///
    /// Every time the full source buffer is consumed (because it contained no
    /// non-whitespace characters), it is appended to the entry buffer.  When
    /// a buffer with a non-whitespace character is found, the data up to the
    /// character is not appended to the buffer.  Instead, the position of the
    /// character in the buffer is returned.
    ///
    /// If the zonefile is emptied, [`None`] is returned.
    fn skip_leading_ws(&mut self) -> io::Result<Option<(usize, u8)>> {
        // Loop through fills of the source buffer.
        loop {
            let buffer = self.source.fill_buf()?;
            if buffer.is_empty() {
                return Ok(None);
            }

            match buffer.iter().position(|b| !b" \t\r".contains(b)) {
                Some(pos) => break Ok(Some((pos, buffer[pos]))),
                None => {
                    // Copy the leading whitespace to the entry and try again.
                    self.entry.extend_from_slice(buffer);
                }
            }
        }
    }

    /// Skip past a comment.
    ///
    /// The current line in the zonefile source is skipped (including the line
    /// feed byte), and is not written to the entry.  If the source is emptied
    /// [`None`] is returned.
    fn skip_comment(&mut self) -> io::Result<Option<()>> {
        // Loop through fills of the source buffer.
        loop {
            let buffer = self.source.fill_buf()?;
            if buffer.is_empty() {
                return Ok(None);
            }

            match buffer.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    // Consume the comment and finish up.
                    self.source.consume(pos + 1);
                    self.line_number += 1;
                    return Ok(Some(()));
                }

                None => {
                    // Empty the buffer and try again.
                    let amount = buffer.len();
                    self.source.consume(amount);
                }
            }
        }
    }

    /// Scan an actual entry.
    ///
    /// The zonefile source should be located at the first non-whitespace
    /// character in the entry.
    fn scan_entry(&mut self) -> Result<Entry<'_>, EntriesError> {
        // The line number this entry begins at.
        let line_number = self.line_number;

        // The line number where an opening parentheses began.
        let mut paren_line_number = None;

        // Loop through fills of the source buffer.
        loop {
            let buffer = self.source.fill_buf()?;
            if buffer.is_empty() {
                // Make sure we're outside parentheses.
                if let Some(line_number) = paren_line_number {
                    return Err(EntriesError::UnmatchedRightParen {
                        line_number,
                    });
                }

                return Ok(Entry {
                    content: &self.entry,
                    line_numbers: line_number..self.line_number + 1,
                });
            }

            // Look for characters that affect the entry.
            let Some(pos) =
                buffer.iter().position(|b| b"\n;()\"".contains(b))
            else {
                // Nothing interesting here.
                let amount = buffer.len();
                self.entry.extend_from_slice(buffer);
                self.source.consume(amount);
                continue;
            };

            // Make sure the character isn't escaped.
            let num_backslashes = self
                .entry
                .iter()
                .chain(&buffer[..pos])
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            if buffer[pos] != b'\n' && num_backslashes % 2 != 0 {
                // Nothing interesting thus far.
                self.entry.extend_from_slice(&buffer[..pos + 1]);
                self.source.consume(pos + 1);
                continue;
            }

            match buffer[pos] {
                b'\n' if paren_line_number.is_some() => {
                    // We hit a new line within parentheses.  Keep going.
                    self.entry.extend_from_slice(&buffer[..pos + 1]);
                    self.source.consume(pos + 1);
                    self.line_number += 1;
                }

                b'\n' => {
                    // The entry is over.
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos + 1);
                    self.line_number += 1;
                    return Ok(Entry {
                        content: &self.entry,
                        line_numbers: line_number..self.line_number,
                    });
                }

                b';' if paren_line_number.is_some() => {
                    // We hit a comment within parentheses.  Keep going.
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos + 1);
                    self.skip_comment()?;
                    self.entry.push(b'\n');
                }

                b';' => {
                    // The entry is over, ending on a comment.
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos + 1);
                    self.skip_comment()?;
                    return Ok(Entry {
                        content: &self.entry,
                        line_numbers: line_number..self.line_number,
                    });
                }

                b'(' => {
                    // Make sure we're already outside parentheses.
                    if let Some(line_number) = paren_line_number {
                        self.source.consume(pos);
                        return Err(EntriesError::NestedOpeningParen {
                            first_line_number: line_number,
                            second_line_number: self.line_number,
                        });
                    }

                    // Begin parentheses.
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos + 1);
                    paren_line_number = Some(self.line_number);
                }

                b')' => {
                    // Make sure we're already inside parentheses.
                    if paren_line_number.is_none() {
                        self.source.consume(pos);
                        return Err(EntriesError::UnmatchedRightParen {
                            line_number: self.line_number,
                        });
                    }

                    // End parentheses.
                    self.entry.extend_from_slice(&buffer[..pos]);
                    self.source.consume(pos + 1);
                    paren_line_number = None;
                }

                b'"' => {
                    self.entry.extend_from_slice(&buffer[..pos + 1]);
                    self.source.consume(pos + 1);
                    self.scan_quoted()?;
                }

                _ => unreachable!(),
            }
        }
    }

    /// Skip past a quoted string.
    fn scan_quoted(&mut self) -> Result<(), EntriesError> {
        // The line number where the quoted string began.
        let line_number = self.line_number;

        // Loop through fills of the source buffer.
        loop {
            let buffer = self.source.fill_buf()?;
            if buffer.is_empty() {
                return Err(EntriesError::UnmatchedDoubleQuote {
                    line_number,
                });
            }

            // Look for characters that affect the entry.
            let Some(pos) = buffer.iter().position(|&b| b == b'"') else {
                // Nothing interesting here.
                let amount = buffer.len();
                self.entry.extend_from_slice(buffer);
                self.source.consume(amount);
                continue;
            };

            // Make sure the character isn't escaped.
            let num_backslashes = self
                .entry
                .iter()
                .chain(&buffer[..pos])
                .rev()
                .take_while(|&&b| b == b'\\')
                .count();
            if num_backslashes % 2 != 0 {
                // Nothing interesting thus far.
                self.entry.extend_from_slice(&buffer[..pos + 1]);
                self.source.consume(pos + 1);
                continue;
            }

            self.entry.extend_from_slice(&buffer[..pos + 1]);
            self.source.consume(pos + 1);
            return Ok(());
        }
    }
}

//----------- Entry ----------------------------------------------------------

/// An entry in a zonefile.
///
/// An entry is typically a single line, although it may contain parenthesized
/// content, which can span multiple lines.  It is usually a serialized DNS
/// record, but it may also be a zonefile directive.
///
/// The entry is left completely unparsed.  It includes all whitespace up to
/// the line terminator, comment marker, or end of the file.  For multi-line
/// entries, line terminators are preserved (but all comments are removed).
#[derive(Clone, Debug)]
pub struct Entry<'a> {
    /// The unparsed entry content.
    pub content: &'a [u8],

    /// The range of line numbers covered by the entry.
    ///
    /// Usually, line numbers start from 1.  However, if the [`Entries`] was
    /// created in the middle of a file, a custom line number can be provided
    /// to [`Entries::with_line_number()`].
    pub line_numbers: Range<usize>,
}

//----------- EntryError -----------------------------------------------------

/// An error in [`Entries::next_entry()`].
#[derive(Debug)]
pub enum EntriesError {
    /// An unmatched double-quote was found.
    UnmatchedDoubleQuote {
        /// The line number of the opening double quote.
        line_number: usize,
    },

    /// An unmatched closing parenthesis was found.
    ///
    /// Everything up to the parenthesis (except the parenthesis itself) is
    /// consumed from the zonefile source.
    UnmatchedRightParen {
        /// The line number of the opening parenthesis.
        line_number: usize,
    },

    /// A nested opening parenthesis was found.
    ///
    /// Everything up to the parenthesis (except the parenthesis itself) is
    /// consumed from the zonefile source.
    NestedOpeningParen {
        /// The line number of the first opening parenthesis.
        first_line_number: usize,

        /// The line number of the second opening parenthesis.
        second_line_number: usize,
    },

    /// The zonefile source could not be read from.
    Source(io::Error),
}

#[cfg(feature = "std")]
impl std::error::Error for EntriesError {}

//--- Conversions from sub-errors

impl From<io::Error> for EntriesError {
    fn from(error: io::Error) -> Self {
        Self::Source(error)
    }
}

//--- Formatting

impl fmt::Display for EntriesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmatchedDoubleQuote { line_number } => {
                write!(f, "a double-quote on line {line_number} was never terminated")
            }
            Self::UnmatchedRightParen { line_number } => {
                write!(f, "an opening parenthesis on line {line_number} was never terminated")
            }
            Self::NestedOpeningParen {
                first_line_number,
                second_line_number,
            } => {
                write!(f, "nested parentheses (on line {first_line_number} and {second_line_number}) were found")
            }
            Self::Source(error) => error.fmt(f),
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use core::ops::Range;

    use super::Entries;

    #[test]
    fn rfc1035() {
        let zonefile = b"\
@   IN  SOA     VENERA      Action\\.domains (
                                 20     ; SERIAL
                                 7200   ; REFRESH
                                 600    ; RETRY
                                 3600000; EXPIRE
                                 60)    ; MINIMUM

        NS      A.ISI.EDU.
        NS      VENERA
        NS      VAXA
        MX      10      VENERA
        MX      20      VAXA

A       A       26.3.0.103

VENERA  A       10.1.0.52
        A       128.9.0.32

VAXA    A       10.2.0.27
        A       128.9.0.33


$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT
";

        let expected: [(&str, Range<usize>); 12] = [
            (
                "\
@   IN  SOA     VENERA      Action\\.domains 
                                 20     
                                 7200   
                                 600    
                                 3600000
                                 60    ",
                1..7,
            ),
            ("        NS      A.ISI.EDU.", 8..9),
            ("        NS      VENERA", 9..10),
            ("        NS      VAXA", 10..11),
            ("        MX      10      VENERA", 11..12),
            ("        MX      20      VAXA", 12..13),
            ("A       A       26.3.0.103", 14..15),
            ("VENERA  A       10.1.0.52", 16..17),
            ("        A       128.9.0.32", 17..18),
            ("VAXA    A       10.2.0.27", 19..20),
            ("        A       128.9.0.33", 20..21),
            ("$INCLUDE <SUBSYS>ISI-MAILBOXES.TXT", 23..24),
        ];

        let mut entries = Entries::new(zonefile.as_slice());
        for (expected, line_numbers) in expected {
            let entry = entries.next_entry().unwrap().unwrap();
            let content = core::str::from_utf8(entry.content);
            assert_eq!(content, Ok(expected));
            assert_eq!(entry.line_numbers, line_numbers);
        }
        assert!(entries.next_entry().unwrap().is_none());

        //---

        let zonefile = b"\
MOE     MB      A.ISI.EDU.
LARRY   MB      A.ISI.EDU.
CURLEY  MB      A.ISI.EDU.
STOOGES MG      MOE
        MG      LARRY
        MG      CURLEY
";

        let expected: [(&str, Range<usize>); 6] = [
            ("MOE     MB      A.ISI.EDU.", 1..2),
            ("LARRY   MB      A.ISI.EDU.", 2..3),
            ("CURLEY  MB      A.ISI.EDU.", 3..4),
            ("STOOGES MG      MOE", 4..5),
            ("        MG      LARRY", 5..6),
            ("        MG      CURLEY", 6..7),
        ];

        let mut entries = Entries::new(zonefile.as_slice());
        for (expected, line_numbers) in expected {
            let entry = entries.next_entry().unwrap().unwrap();
            let content = core::str::from_utf8(entry.content);
            assert_eq!(content, Ok(expected));
            assert_eq!(entry.line_numbers, line_numbers);
        }
        assert!(entries.next_entry().unwrap().is_none());
    }
}
