//! A scanner atop a buffer atop an io::Read.

use std::fs::File;
use std::io;
use std::path::Path;
use std::str;
use super::error::{ScanError, ScanResult, SyntaxError, SyntaxResult, Pos};
use super::scanner::Scanner;


//------------ BufScanner ----------------------------------------------------

/// A scanner using a buffer atop an reader.
///
/// The strategy implemented for the buffer is to read byte by byte from the
/// underlying reader and flush it every time a successfully read token ends
/// at the buffer’s end (which should happen quite a lot). This may not be
/// the smartest way of doing this, but it is simple and memory-efficient.
#[derive(Clone, Debug)]
pub struct BufScanner<R: io::Read> {
    /// The underlying reader.
    reader: R,

    /// The buffer for rejected tokens.
    ///
    /// It will be kept short by flushing it every time we successfully
    /// read to its end.
    buf: Vec<u8>,

    /// Index in `buf` of the start of the token currently being read.
    start: usize,

    /// Index in `buf` of the next character to be read.
    cur: usize,

    /// Human-friendly position in `reader` of `start`.
    start_pos: Pos,

    /// Human-friendly position in `reader` of `cur`.
    cur_pos: Pos,

    /// Was the start of token in a parenthesized group?
    paren: bool
}

/// # Creation
///
impl<R: io::Read> BufScanner<R> {
    /// Creates a new scanner using the given reader.
    pub fn new(reader: R) -> Self {
        BufScanner::with_pos(reader, Pos::new())
    }

    /// Creates a new scanner using the given reader and position.
    ///
    /// The scanner will assume that the current position of `reader`
    /// corresponds to the human-friendly position `pos`.
    pub fn with_pos(reader: R, pos: Pos) -> Self {
        BufScanner {
            reader: reader,
            buf: Vec::new(),
            start: 0,
            cur: 0,
            start_pos: pos,
            cur_pos: pos,
            paren: false
        }
    }
}

impl BufScanner<File> {
    /// Attempts to opens a file and create a scanner for it.
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        Ok(BufScanner::new(try!(File::open(path))))
    }
}

impl<T: AsRef<[u8]>> BufScanner<io::Cursor<T>> {
    /// Wraps `t` into a cursor and creates a scanner with it.
    pub fn create(t: T) -> Self {
        BufScanner::new(io::Cursor::new(t))
    }
}


/// # Fundamental Reading, Progressing, and Back-tracking
///
impl<R: io::Read> BufScanner<R> {
    /// Tries to peek at the next byte.
    ///
    /// On success, returns the `Ok(Some(_))` byte value. It the end of the
    /// underlying reader is reached, returns `Ok(None)`. If reading on the
    /// underlying reader results in an error, returns that which is an
    /// `io::Error`.
    fn peek_byte(&mut self) -> io::Result<Option<u8>> {
        if self.buf.len() == self.cur {
            let mut buf = [0u8; 1];
            if try!(self.reader.read(&mut buf)) == 0 {
                return Ok(None)
            }
            self.buf.push(buf[0])
        }
        Ok(Some(self.buf[self.cur]))
    }

    /// Tries to read a byte.
    ///
    /// On success, returns the `Ok(Some(_))` byte value. It the end of the
    /// underlying reader is reached, returns `Ok(None)`. If reading on the
    /// underlying reader results in an error, returns that which is an
    /// `io::Error`.
    fn read_byte(&mut self) -> io::Result<Option<u8>> {
        self.peek_byte().map(|res| match res {
            Some(ch) => {
                self.cur += 1;
                self.cur_pos.update(ch);
                Some(ch)
            }
            None => None
        })
    }

    /// Progresses the scanner to the current position and returns `t`.
    fn ok<T>(&mut self, t: T) -> ScanResult<T> {
        if self.buf.len() == self.cur {
            self.buf.clear();
            self.start = 0;
            self.cur = 0;
        } else {
            self.start = self.cur;
        }
        self.start_pos = self.cur_pos;
        Ok(t)
    }

    /// Backtracks to the last token start and reports an error there.
    ///
    /// Returns a syntax error with the given error value and the position
    /// of the token start.
    ///
    /// The method is generic over whatever type `T` so it can be used to
    /// create whatever particular `ScanResult<T>` is needed.
    fn err<T>(&mut self, err: SyntaxError) -> ScanResult<T> {
        let pos = self.start_pos;
        self.err_at(err, pos)
    }

    /// Reports an error at current position and then backtracks.
    fn err_at<T>(&mut self, err: SyntaxError, pos: Pos) -> ScanResult<T> {
        self.cur = self.start;
        self.cur_pos = self.start_pos;
        Err(ScanError::Syntax(err, pos))
    }
}

/// # More Complex Internal Reading
///
impl<R: io::Read> BufScanner<R> {
    /// Reads a byte if it is accepted by a closure.
    ///
    /// The byte is passed to the closure which should return `true` if it
    /// accepts the bytes in which case the method returns `Ok(Some(_))`. If
    /// the closure returns `false` or the end of file is reached, `Ok(None)`
    /// is returned.
    ///
    /// The method does not progress or backtrack.
    fn cond_read_byte<F>(&mut self, f: F) -> io::Result<Option<u8>>
                      where F: FnOnce(u8) -> bool {
        match try!(self.peek_byte()) {
            Some(ch) if f(ch) => self.read_byte(),
            _ => Ok(None)
        }
    }

    /// Scans the inside of an escape sequence and returns the translated byte.
    ///
    /// When calling this method, you should have successfully read a
    /// backspace last. 
    ///
    /// Does not progress the scanner on success but backtracks on error,
    /// reporting the starting backslash’s position for the error.
    fn scan_escape(&mut self) -> ScanResult<u8> {
        let pos = self.cur_pos.prev();
        match try!(self.read_byte()) {
            Some(ch) if is_digit(ch) => {
                let ch2 = match try!(self.read_byte()) {
                    Some(ch) if is_digit(ch) => ch,
                    Some(_) => {
                        return self.err_at(SyntaxError::IllegalEscape, pos)
                    }
                    None => return self.err_at(SyntaxError::UnexpectedEof, pos),
                };
                let ch3 = match try!(self.read_byte()) {
                    Some(ch) if is_digit(ch) => ch,
                    Some(_) => {
                        return self.err_at(SyntaxError::IllegalEscape, pos)
                    }
                    None => return self.err_at(SyntaxError::UnexpectedEof, pos),
                };
                let res = ((ch - b'0') as u16) * 100
                        + ((ch2 - b'0') as u16) * 10
                        + ((ch3 - b'0') as u16);
                if res > 255 { self.err_at(SyntaxError::IllegalEscape, pos) }
                else { Ok(res as u8) }
            }
            Some(ch) => Ok(ch),
            None => self.err_at(SyntaxError::UnexpectedEof, pos)
        }
    }

    /// Skips over delimiting space.
    ///
    /// A delimiter is a non-empty sequence of space (which means that
    /// something like `b"foo(bar"` qualifies as the two words `b"foo"` and
    /// `b"bar".) or if the following byte is the beginning of a newline or
    /// if the scanner has reached end-of-file.
    ///
    /// Progresses the scanner on success, otherwise backtracks with an
    /// ‘unexpected space’ error.
    fn skip_delimiter(&mut self) -> ScanResult<()> {
        if try!(self.skip_space()) {
            self.ok(())
        }
        else {
            match try!(self.peek_byte()) {
                Some(ch) if is_newline_ahead(ch) => self.ok(()),
                None => self.ok(()),
                _ => self.err(SyntaxError::ExpectedSpace)
            }
        }
    }

    /// Skips over space.
    ///
    /// Normally, space is ordinary white space (`b' '` and `b'\t'`).
    /// However, an opening parenthesis can be used to make newlines appear
    /// as space, too. A closing parenthesis resets this behaviour.
    ///
    /// This method cleverly hides all of this and simply walks over whatever
    /// is space. It returns whether there was at least one byte of space.
    /// It not progress the scanner but backtracks on error.
    fn skip_space(&mut self) -> ScanResult<bool> {
        let mut res = false;
        loop {
            if self.paren {
                match try!(self.cond_read_byte(is_paren_space)) {
                    None => break,
                    Some(b'(') => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::NestedParentheses,
                                           pos)
                    }
                    Some(b')') => {
                        self.paren = false;
                    }
                    Some(b';') => {
                        while let Some(ch) = try!(self.read_byte()) {
                            if is_newline(ch) {
                                break
                            }
                        }
                    }
                    _ => { }
                }
            }
            else {
                match try!(self.cond_read_byte(is_non_paren_space)) {
                    None => break,
                    Some(b'(') => {
                        self.paren = true;
                    }
                    Some(b')') => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::Unexpected(b')'), pos)
                    }
                    _ => { }
                }
            }
            res = true;
        }
        Ok(res)
    }

    fn skip_entry(&mut self) -> ScanResult<()> {
        let mut quote = false;
        loop {
            match try!(self.read_byte()) {
                None => break,
                Some(ch) if is_newline(ch) => {
                    if !quote && !self.paren {
                        break
                    }
                }
                Some(b'"') => quote = !quote,
                Some(b'\\') => { try!(self.read_byte()); },
                Some(b'(') => {
                    if !quote {
                        if self.paren {
                            return self.err(SyntaxError::NestedParentheses)
                        }
                        self.paren = true
                    }
                }
                Some(b')') => {
                    if !quote {
                        if !self.paren {
                            return self.err(SyntaxError::Unexpected(b')'))
                        }
                        self.paren = false
                    }
                }
                _ => { }
            }
        }
        self.ok(())
    }
}

//--- Scanner
/*
impl<R: io::Read> Scanner for BufScanner<R> {
*/
impl<R: io::Read> BufScanner<R> {
    fn is_eof(&mut self) -> bool {
        match self.peek_byte() {
            Ok(Some(_)) => false,
            _ => true
        }
    }

    fn pos(&self) -> Pos {
        self.cur_pos
    }

    fn scan_word<T, F>(&mut self, f: F) -> ScanResult<T>
                 where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        let start = self.cur;
        match try!(self.read_byte()) {
            Some(ch) if is_word_char(ch) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        while let Some(_) = try!(self.cond_read_byte(is_word_char)) { }
        let res = {
            f(&self.buf[start..self.cur])
        };
        match res {
            Ok(res) => self.skip_delimiter().map(|_| res),
            Err(err) => self.err(err)
        }
    }

    fn scan_word_bytes<F>(&mut self, mut f: F) -> ScanResult<()>
                           where F: FnMut(u8, bool) -> SyntaxResult<()> {
        match try!(self.peek_byte()) {
            Some(ch) if is_word_char(ch) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        };
        while let Some(ch) = try!(self.cond_read_byte(is_word_char)) {
            if ch == b'\\' {
                // Escapes should be rare enough that copying the position
                // for possible error reporting should be fine.
                let pos = self.cur_pos;
                if let Err(err) = f(try!(self.scan_escape()), true) {
                    return self.err_at(err, pos)
                }
            }
            else if let Err(err) = f(ch, false) {
                let pos = self.cur_pos.prev();
                return self.err_at(err, pos)
            }
        }
        self.skip_delimiter()
    }

    fn scan_word_into<T, F, G>(&mut self, target: &mut T, mut f: F, g: G)
                               -> ScanResult<()>
                      where F: FnMut(&mut T, u8, bool) -> SyntaxResult<()>,
                            G: FnOnce(&mut T) -> SyntaxResult<()> {
        match try!(self.peek_byte()) {
            Some(ch) if is_word_char(ch) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        };
        while let Some(ch) = try!(self.cond_read_byte(is_word_char)) {
            if ch == b'\\' {
                // Escapes should be rare enough that copying the position
                // for possible error reporting should be fine.
                let pos = self.cur_pos;
                if let Err(err) = f(target, try!(self.scan_escape()), true) {
                    return self.err_at(err, pos)
                }
            }
            else if let Err(err) = f(target, ch, false) {
                let pos = self.cur_pos.prev();
                return self.err_at(err, pos)
            }
        }
        if let Err(err) = g(target) {
            self.err(err)
        }
        else {
            self.skip_delimiter()
        }
    }

    fn scan_quoted<T, F>(&mut self, f: F) -> ScanResult<T>
                   where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        match try!(self.read_byte()) {
            Some(b'"') => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        let start = self.cur;
        loop {
            match try!(self.read_byte()) {
                Some(b'\\') => { try!(self.scan_escape()); }
                Some(b'"') => break,
                Some(_) => { }
                None => return self.err(SyntaxError::UnexpectedEof)
            }
        }
        let res = f(&self.buf[start..self.cur - 1]);
        match res {
            Ok(res) => self.skip_delimiter().map(|_| res),
            Err(err) => self.err(err)
        }
    }

    fn scan_quoted_bytes<F>(&mut self, mut f: F) -> ScanResult<()>
                         where F: FnMut(u8, bool) -> SyntaxResult<()> {
        match try!(self.read_byte()) {
            Some(b'"') => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        loop {
            match try!(self.read_byte()) {
                Some(b'\\') => {
                    if let Err(err) = f(try!(self.scan_escape()), true) {
                        return self.err(err)
                    }
                }
                Some(b'"') => break,
                Some(ch) => {
                    if let Err(err) = f(ch, false) {
                        return self.err(err)
                    }
                }
                None => return self.err(SyntaxError::UnexpectedEof)
            }
        }
        self.skip_delimiter()
    }

    fn scan_phrase<T, F>(&mut self, f: F) -> ScanResult<T>
                   where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        if let Some(b'"') = try!(self.peek_byte()) {
            self.scan_quoted(f)
        }
        else {
            self.scan_word(f)
        }
    }

    fn scan_phrase_bytes<F>(&mut self, f: F) -> ScanResult<()>
                         where F: FnMut(u8, bool) -> SyntaxResult<()> {
        if let Some(b'"') = try!(self.peek_byte()) {
            self.scan_quoted_bytes(f)
        }
        else {
            self.scan_word_bytes(f)
        }
    }                         

    fn scan_newline(&mut self) -> ScanResult<()> {
        match try!(self.read_byte()) {
            Some(b';') => {
                while let Some(ch) = try!(self.read_byte()) {
                    if is_newline(ch) {
                        break
                    }
                }
                self.ok(())
            }
            Some(ch) if is_newline(ch) => self.ok(()),
            None => self.ok(()),
            _ => self.err(SyntaxError::ExpectedNewline)
        }
    }

    fn scan_space(&mut self) -> ScanResult<()> {
        match try!(self.skip_space()) {
            true => self.ok(()),
            false => self.err(SyntaxError::ExpectedSpace)
        }
    }
}

//------------ Tests for character classes ----------------------------------

fn is_digit(ch: u8) -> bool {
    ch >= b'0' && ch <= b'9'
}

/// Checks for space-worthy character outside a parenthesized group.
///
/// These are horizontal white space plus opening and closing parentheses
/// which need special treatment.
fn is_non_paren_space(ch: u8) -> bool {
    ch == b' ' || ch == b'\t' || ch == b'(' || ch == b')'
}

/// Checks for space-worthy character inside a parenthesized group.
///
/// These are all from `is_non_paren_space()` plus a semicolon and line
/// break characters.
fn is_paren_space(ch: u8) -> bool {
    ch == b' ' || ch == b'\t' || ch == b'(' || ch == b')' ||
    ch == b';' || ch == b'\r' || ch == b'\n'
}

fn is_newline(ch: u8) -> bool {
    ch == b'\r' || ch == b'\n'
}

fn is_newline_ahead(ch: u8) -> bool {
    ch == b'\r' || ch == b'\n' || ch == b';'
}

fn is_word_char(ch: u8) -> bool {
    ch != b' ' && ch != b'\t' && ch != b'\r' && ch != b'\n' &&
    ch != b'(' && ch != b')' && ch != b';' && ch != b'"'
}


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::io::Read;
    use std::str;
    use ::master::{Pos, ScanError, ScanResult, SyntaxError};
    use super::*;

    fn syntax_err<T: Debug>(err: Result<T, ScanError>) -> (SyntaxError, Pos) {
        match err.unwrap_err() {
            ScanError::Syntax(err, pos) => (err, pos),
            err => panic!("not a syntax error: {:?}", err),
        }
    }

    #[test]
    fn peek_and_read() {
        let mut scanner = BufScanner::create(b"bar");
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'b'));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'b'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'b'));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'a'));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'a'));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'a'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'a'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'r'));
        assert_eq!(scanner.read_byte().unwrap(), None);
        assert_eq!(scanner.peek_byte().unwrap(), None);
        assert_eq!(scanner.read_byte().unwrap(), None);
    }

    #[test]
    fn ok_and_err() {
        let mut scanner = BufScanner::create(b"12345");
        assert_eq!(scanner.read_byte().unwrap(), Some(b'1'));
        assert_eq!(syntax_err(scanner.err::<()>(SyntaxError::LongName)),
                   (SyntaxError::LongName, (1,1).into()));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'1'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'1'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'2'));
        assert_eq!(scanner.ok(0).unwrap(), 0);
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'3'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'3'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'4'));
        assert_eq!(syntax_err(scanner.err_at::<()>(SyntaxError::LongName,
                                                   (1,5).into())),
                   (SyntaxError::LongName, (1,5).into()));
        assert_eq!(scanner.peek_byte().unwrap(), Some(b'3'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'3'));
        assert_eq!(scanner.read_byte().unwrap(), Some(b'4'));
        assert_eq!(scanner.ok(0).unwrap(), 0);
        assert_eq!(scanner.read_byte().unwrap(), Some(b'5'));
        assert_eq!(scanner.read_byte().unwrap(), None);
    }

    #[test]
    fn cond_read_byte() {
        let mut scanner = BufScanner::create(b"ba");
        assert_eq!(scanner.cond_read_byte(|b| b == b'b').unwrap(), Some(b'b'));
        assert_eq!(scanner.cond_read_byte(|b| b == b'b').unwrap(), None);
        assert_eq!(scanner.cond_read_byte(|b| b == b'a').unwrap(), Some(b'a'));
        assert_eq!(scanner.cond_read_byte(|b| b == b'r').unwrap(), None);
    }

    #[test]
    fn scan_escape() {
        assert_eq!(BufScanner::create(b".").scan_escape().unwrap(), b'.');
        assert_eq!(BufScanner::create(b"032").scan_escape().unwrap(), b' ');

        fn kaputt<T: AsRef<[u8]>>(t: T, err: SyntaxError) {
            let mut scanner = BufScanner::create(t);
            assert_eq!(scanner.read_byte().unwrap(), Some(b'\\'));
            assert_eq!(syntax_err(scanner.scan_escape()),
                       (err, (1, 1).into()))
        }

        kaputt(b"\\", SyntaxError::UnexpectedEof);
        kaputt(b"\\0bb", SyntaxError::IllegalEscape);
        kaputt(b"\\400", SyntaxError::IllegalEscape);
    }

    #[test]
    fn is_eof() {
        let mut scanner = BufScanner::create(b"12");
        assert_eq!(scanner.is_eof(), false);
        assert_eq!(scanner.read_byte().unwrap(), Some(b'1'));
        assert_eq!(scanner.is_eof(), false);
        assert_eq!(scanner.read_byte().unwrap(), Some(b'2'));
        assert_eq!(scanner.is_eof(), true);
        assert_eq!(scanner.read_byte().unwrap(), None);
        assert_eq!(scanner.is_eof(), true);
    }

    fn scan_phrase<R: Read + Clone>(scanner: &mut BufScanner<R>,
                                    word: &[u8], then: Option<u8>) {
        let mut tmp = scanner.clone();
        tmp.scan_phrase(|w| {
            if word == w { Ok(()) }
            else { Err(SyntaxError::Expected(w.into())) }
        }).unwrap();
        assert_eq!(tmp.read_byte().unwrap(), then);

        /*
        let mut tmp = scanner.clone();
        tmp.scan_str_phrase(|w| {
            if str::from_utf8(word).unwrap() == w { Ok(()) }
            else { Err(SyntaxError::Expected(w.into())) }
        }).unwrap();
        assert_eq!(tmp.read_byte().unwrap(), then);
        */

        let mut tmp = scanner.clone();
        let mut left = word;
        tmp.scan_phrase_bytes(|ch, _| {
            if *left.get(0).unwrap() == ch {
                left = &left[1..];
                Ok(())
            }
            else { Err(SyntaxError::Unexpected(ch)) }
        }).unwrap();
        assert_eq!(tmp.read_byte().unwrap(), then);
    }

    #[test]
    fn scan_word() {
        fn scan<R: Read + Clone>(scanner: &mut BufScanner<R>,
                                 word: &[u8], then: Option<u8>) {
            let mut tmp = scanner.clone();
            tmp.scan_word(|w| {
                if word == w { Ok(()) }
                else { Err(SyntaxError::Expected(w.into())) }
            }).unwrap();
            assert_eq!(tmp.read_byte().unwrap(), then);

            let mut tmp = scanner.clone();
            let mut left = word;
            tmp.scan_word_bytes(|ch, _| {
                if *left.get(0).unwrap() == ch {
                    left = &left[1..];
                    Ok(())
                }
                else { Err(SyntaxError::Unexpected(ch)) }
            }).unwrap();
            assert_eq!(tmp.read_byte().unwrap(), then);

            scan_phrase(scanner, word, then)
        }

        scan(&mut BufScanner::create(b"foo \t  bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"foo( \t \n bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"foo(bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"foo\rbar"),
             b"foo", Some(b'\r'));
        scan(&mut BufScanner::create(b"foo;\rbar"),
             b"foo", Some(b';'));
        scan(&mut BufScanner::create(b"foo"),
             b"foo", None);

        let mut scanner = BufScanner::create(b"foo(bar \n ) \r");
        scanner.scan_word(|_| Ok(())).unwrap();
        scan(&mut scanner, b"bar", Some(b'\r'));
    }

    #[test]
    fn scan_quoted() {
        fn scan<R: Read + Clone>(scanner: &mut BufScanner<R>,
                                 word: &[u8], then: Option<u8>) {
            let mut tmp = scanner.clone();
            tmp.scan_quoted(|w| {
                if word == w { Ok(()) }
                else { Err(SyntaxError::Expected(w.into())) }
            }).unwrap();
            assert_eq!(tmp.read_byte().unwrap(), then);

            let mut tmp = scanner.clone();
            let mut left = word;
            tmp.scan_quoted_bytes(|ch, _| {
                if *left.get(0).unwrap() == ch {
                    left = &left[1..];
                    Ok(())
                }
                else { Err(SyntaxError::Unexpected(ch)) }
            }).unwrap();
            assert_eq!(tmp.read_byte().unwrap(), then);

            scan_phrase(scanner, word, then)
        }

        fn fail<R: Read + Clone>(scanner: &mut BufScanner<R>) {
            assert!(scanner.scan_quoted(|_| Ok(())).is_err())
        }

        scan(&mut BufScanner::create(b"\"foo\" \t  bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"\"foo\"( \t \n bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"\"foo\"(bar"),
             b"foo", Some(b'b'));
        scan(&mut BufScanner::create(b"\"foo\"\rbar"),
             b"foo", Some(b'\r'));
        scan(&mut BufScanner::create(b"\"foo\";\rbar"),
             b"foo", Some(b';'));
        scan(&mut BufScanner::create(b"\"foo\""),
             b"foo", None);

        let mut scanner = BufScanner::create(b"foo(\"bar\" \n ) \r");
        scanner.scan_word(|_| Ok(())).unwrap();
        scan(&mut scanner, b"bar", Some(b'\r'));

        fail(&mut BufScanner::create(b"\"foo\"bar"));
        fail(&mut BufScanner::create(b"\"foo\"\"bar\""));
    }

    #[test]
    fn scan_newline() {
        fn scan<B: AsRef<[u8]>>(b: B) {
            let mut scanner = BufScanner::create(b);
            scanner.scan_newline().unwrap();
            assert_eq!(scanner.read_byte().unwrap(), Some(b'b'));
        }
        scan(b"\nb");
        scan(b"\rb");
        scan(b";comment \nb");
        BufScanner::create(b"").scan_newline().unwrap();
        assert!(BufScanner::create(b" \n").scan_newline().is_err());
        assert!(BufScanner::create(b" ;\n").scan_newline().is_err());
    }

    #[test]
    fn scan_space() {
        fn scan<B: AsRef<[u8]>>(b: B) {
            let mut scanner = BufScanner::create(b);
            scanner.scan_space().unwrap();
            assert_eq!(scanner.read_byte().unwrap(), Some(b'b'));
        }
        scan(b" b");
        scan(b"   ()    b");
        scan(b"(b");
        scan(b"(  ;foo\nb");
        assert!(BufScanner::create(b"b").scan_space().is_err());
        assert!(BufScanner::create(b"").scan_space().is_err());
    }
}

