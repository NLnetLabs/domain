
use std::str;
use ::bits::CharStr;
use ::bits::{DNameBuf, DNameSlice};
use ::bits::bytes::BytesBuf;
use ::bits::name::{DNameBuilder, DNameBuildInto};
use super::error::{Pos, ScanResult, SyntaxError, SyntaxResult};


//------------ Scanner -------------------------------------------------------

/// A trait for a scanner of master format tokens.
///
/// The master format is using a small number of different token types. This
/// trait provides a way to access a sequence of such tokens. There is a
/// method prefix by `scan_` for each type of token that tries to scan a
/// token of the given type. If it succeeds, it returns the token and
/// progresses to the end of the token. If it fails, it returns an error and
/// reverts to the position before the scanning attempt unless an IO error
/// occured in which case the scanner becomes ‘broken.’
///
/// The methods that provide access to the token’s content do so through
/// closures to let the user decide if and how copies ought to be made. Note
/// that since the scanner may throw away the content at any time after the
/// closure returns, you cannot keep the slice references passed in. This is
/// not on purpose, not a mistake with the lifetime arguments.
pub trait Scanner {
    /// # Fundamental Methods
    ///
    /// Returns whether the scanner has reached the end of data.
    ///
    /// This will return `false` if reading results in an IO error.
    fn is_eof(&mut self) -> bool;

    /// Returns the current position of the scanner.
    fn pos(&self) -> Pos;

    /// Scans a word token.
    ///
    /// A word is a sequence of non-special characters and escape sequences
    /// followed by a non-empty sequence of space unless it is followed
    /// directly by a [newline](#tymethod.scan_newline). If successful, the
    /// method will position at the end of the space sequence if it is
    /// required. That is, you can scan for two subsequent word tokens
    /// without worrying about the space between them.
    ///
    /// A reference to the content of the actual word (ie., without any
    /// trailing space) is passed to the provided closure. This is the raw
    /// content without any escape sequences translated. If the closure likes
    /// the content, it can return something which will then become the
    /// return value of the entire method. Otherwise, it returns a syntax
    /// error. In this case, the whole method will fails returning the syntax
    /// error and the position of the start of the token.
    fn scan_word<T, F>(&mut self, f: F) -> ScanResult<T>
                 where F: FnOnce(&[u8]) -> SyntaxResult<T>;

    /// Scans a word, processing each character of its content separatedly. 
    ///
    /// This method is similar to [scan_word()](#tymethod.scan_word) but the
    /// closure is called for each character of the content. Escape sequences
    /// are translated into the character they stand for. For each character,
    /// the closure receives the character value and a boolean
    /// indicating whether the character was in fact translated from an
    /// escape sequence. Ie., the content `b"f"` will be translated into one
    /// single closure call with `f(b'f', false)`, whereas the content
    /// `b"\102"` will also be just one call but with `f(b'f', true)`.
    ///
    /// If the closure returns `Ok(())`, the method proceeds to the next
    /// content character or, if there are no more characters, itself returns
    /// `Ok(())`. If the closure returns an error, the method returns to the
    /// start of the token and returns the error with that position.
    fn scan_word_bytes<F>(&mut self, mut f: F) -> ScanResult<()>
                       where F: FnMut(u8, bool) -> SyntaxResult<()> {
        self.scan_word_into((), |_, b, escape| f(b, escape), |_| Ok(()))
    }

    fn scan_word_into<T, U, F, G>(&mut self, target: T, f: F, g: G)
                               -> ScanResult<U>
                      where F: FnMut(&mut T, u8, bool) -> SyntaxResult<()>,
                            G: FnOnce(T) -> SyntaxResult<U>;

    /// Scans a quoted word.
    ///
    /// A quoted word starts with a double quote `"`, followed by all sorts
    /// of characters or escape sequences until the next (unescaped) double
    /// quote. It may contain line feeds. Like a regular word, a quoted word
    /// is followed by a non-empty space sequence unless it is directly
    /// followed by a [newline](#tymethod.scan_newline). This space is not
    /// part of the content but quietly skipped over.
    ///
    /// The reference to the raw content of the quoted word is given to the
    /// closure `f` which needs to decide of it fulfills its own
    /// requirements. If it does, it can translate it into a return value
    /// which is also returned by the method. Otherwise, it returns a syntax
    /// error which is reported by the method with the position of the
    /// first double quote.
    fn scan_quoted<T, F>(&mut self, f: F) -> ScanResult<T>
                   where F: FnOnce(&[u8]) -> SyntaxResult<T>;

    /// Scans a quoted word, processing the content characters separatedly. 
    ///
    /// This method is similar to [scan_quoted()](#tymethod.scan_quoted) but
    /// the closure is called for each character of the content. Escape
    /// sequences are translated into the character they stand for. For each
    /// character, the closure receives the character value and a boolean
    /// indicating whether the character was in fact translated from an
    /// escape sequence. Ie., the content `b"f"` will be translated into one
    /// single closure call with `f(b'f', false)`, whereas the content
    /// `b"\102"` will also be just one call but with `f(b'f', true)`.
    ///
    /// If the closure returns `Ok(())`, the method proceeds to the next
    /// content character or, if there are no more characters, itself returns
    /// `Ok(())`. If the closure returns an error, the method returns to the
    /// start of the token and returns the error with that position.
    fn scan_quoted_bytes<F>(&mut self, f: F) -> ScanResult<()>
                         where F: FnMut(u8, bool) -> SyntaxResult<()>;

    /// Scans phrase: a normal or quoted word.
    ///
    /// This method behaves like [scan_quoted()](#tymethod.scan_quoted) if
    /// the next character is a double quote or like
    /// [scan_word()](#tymethod.scan_word) otherwise.
    fn scan_phrase<T, F>(&mut self, f: F) -> ScanResult<T>
                   where F: FnOnce(&[u8]) -> SyntaxResult<T>;

    /// Scans a phrase and converts it into a string slice.
    ///
    /// This method is similar to [scan_phrase()](#tymethod.scan_phrase)
    /// but passes a string slice to the closure instead of a bytes slice.
    /// There are no allocations and the method syntax errors out if the
    /// content contains non-ASCII characters.
    fn scan_str_phrase<T, F>(&mut self, f: F) -> ScanResult<T>
                       where F: FnOnce(&str) -> SyntaxResult<T> {
        self.scan_phrase(|slice| {
            f(try!(str::from_utf8(slice)))
        })
    }

    /// Scans a phrase, processing the content characters separatedly.
    ///
    /// This method behaves like
    /// [scan_quoted_bytes()](#tymethod.scan_quoted_bytes) if
    /// the next character is a double quote or like
    /// [scan_word_bytes()](#tymethod.scan_word_bytes) otherwise.
    fn scan_phrase_bytes<F>(&mut self, f: F) -> ScanResult<()>
                         where F: FnMut(u8, bool) -> SyntaxResult<()>;

    /// Scans a phrase and returns a copy of it.
    ///
    /// The copy will have all escape sequences translated.
    fn scan_phrase_copy(&mut self) -> ScanResult<Vec<u8>> {
        let mut res = Vec::new();
        try!(self.scan_phrase_bytes(|ch, _| { res.push(ch); Ok(()) }));
        Ok(res)
    }

    /// Scans a newline.
    ///
    /// A newline is either an optional comment followed by either a CR or
    /// LF character or the end of file. The latter is so that a file lacking
    /// a line feed after its last line is still parsed successfully.
    fn scan_newline(&mut self) -> ScanResult<()>;

    /// Scans a non-empty sequence of space.
    ///
    /// There are two flavors of space. The simple form is any sequence
    /// of a space character `b' '` or a horizontal tab 'b`\t'`. However,
    /// a parenthesis can be used to turn [newlines](#tymethod.scan_newline)
    /// into normal space. This method recognises parentheses and acts
    /// accordingly.
    fn scan_space(&mut self) -> ScanResult<()>;

    /// Skips over an entry.
    ///
    /// Keeps reading until it successfully scans a newline. The method
    /// tries to be smart about that and considers parentheses, quotes, and
    /// escapes but also tries its best to not fail.
    fn skip_entry(&mut self) -> ScanResult<()>;

    /// # Helper Methods
    ///
    /// Scans a phrase containing a 16 bit integer in decimal representation.
    fn scan_u16(&mut self) -> ScanResult<u16> {
        self.scan_phrase(|slice| {
            let slice = match str::from_utf8(slice) {
                Ok(slice) => slice,
                Err(_) => return Err(SyntaxError::IllegalInteger)
            };
            Ok(try!(u16::from_str_radix(slice, 10)))
        })
    }

    /// Scans a phrase containing a 32 bit integer in decimal representation.
    fn scan_u32(&mut self) -> ScanResult<u32> {
        self.scan_phrase(|slice| {
            let slice = match str::from_utf8(slice) {
                Ok(slice) => slice,
                Err(_) => return Err(SyntaxError::IllegalInteger)
            };
            Ok(try!(u32::from_str_radix(slice, 10)))
        })
    }

    /// Scans a word containing a sequence of pairs of hex digits.
    ///
    /// Each pair is translated to its byte value and passed to the
    /// closure `f`.
    fn scan_hex_word<F>(&mut self, mut f: F) -> ScanResult<()>
                     where F: FnMut(u8) -> SyntaxResult<()> {
        self.scan_word(|mut slice| {
            while slice.len() >=2 {
                let (l, r) = slice.split_at(2);
                let res = try!(trans_hexdig(l[0])) << 4
                        | try!(trans_hexdig(l[1]));
                try!(f(res));
                slice = r;
            }
            if slice.len() == 1 {
                Err(SyntaxError::Unexpected(slice[0]))
            }
            else {
                Ok(())
            }
        })
    }

    /// Skips over the word with the content `literal`.
    ///
    /// The content indeed needs to be literally the literal. Escapes are
    /// not translated before comparison and case has to be as is.
    fn skip_literal(&mut self, literal: &[u8]) -> ScanResult<()> {
        self.scan_word(|s| {
            if s == literal {
                Ok(())
            }
            else {
                Err(SyntaxError::Expected(literal.into()))
            }
        })
    }

    /// Scans a domain name and returns an owned domain name.
    ///
    /// If the name is relative, it is made absolute by appending `origin`.
    /// If there is no origin given, a syntax error is returned.
    fn scan_dname(&mut self, origin: Option<&DNameSlice>)
                  -> ScanResult<DNameBuf> {
        let target = DNameBuilder::new(origin);
        self.scan_word_into(target, |target, b, escaped| {
            if b == b'.' && !escaped {
                target.end_label()
            }
            else {
                try!(target.push(b))
            }
            Ok(())
        }, |target| { Ok(try!(target.done())) })
    }

    /// Scans a domain name into a bytes vec.
    ///
    /// The name is scanned and its wire format representation is appened
    /// to the end of `target`. If the scanned name is relative, it is made
    /// absolute by appending `origin`. If there is no origin given, a
    /// syntax error is returned.
    fn scan_dname_into(&mut self, origin: Option<&DNameSlice>,
                       target: &mut Vec<u8>) -> ScanResult<()> {
        let target = DNameBuildInto::new(target, origin);
        try!(self.scan_word_into(target, |target, b, escaped| {
            if b == b'.' && !escaped {
                target.end_label()
            }
            else {
                try!(target.push(b))
            }
            Ok(())
        }, |target| { try!(target.done()); Ok(()) }));
        Ok(())
    }

    /// Scans a character string and returns it as an owned value.
    fn scan_charstr<'a>(&mut self) -> ScanResult<CharStr<'a>> {
        let mut res = Vec::new();
        try!(self.scan_charstr_into(&mut res));
        Ok(CharStr::owned(res).unwrap())
    }

    /// Scans a character string into a bytes vec.
    ///
    /// The string is scanned and its wire format representation is appened
    /// to the end of `target`.
    fn scan_charstr_into(&mut self, target: &mut Vec<u8>) -> ScanResult<()> {
        let mut len = 0;
        self.scan_phrase_bytes(|ch, _| {
            if len == 255 { Err(SyntaxError::LongCharStr) }
            else {
                target.push_u8(ch);
                len += 1;
                Ok(())
            }
        })
    }
}


//------------ Helper Functions ----------------------------------------------

fn trans_hexdig(dig: u8) -> SyntaxResult<u8> {
    match dig {
        b'0' ... b'9' => Ok(dig - b'0'),
        b'A' ... b'F' => Ok(dig - b'A' + 10),
        b'a' ... b'f' => Ok(dig - b'a' + 10),
        _ => Err(SyntaxError::Unexpected(dig))
    }
}

