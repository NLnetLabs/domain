//! Reading tokens from a reader.

use std::io;
use std::str;
use ::master::error::{Error, Result, SyntaxError, SyntaxResult};
use ::master::Pos;


//------------ Stream ---------------------------------------------------

pub struct Stream<R: io::Read> {
    buf: Buffer<R>,
    paren: bool,
}


/// Reading.
///
impl<R: io::Read> Stream<R> {
    pub fn pos(&self) -> Pos {
        self.buf.curr_pos
    }

    /// Reads a character, if there are any left.
    pub fn read_char(&mut self) -> io::Result<Option<u8>> {
        self.buf.read_char()
    }

    pub fn peek_char(&mut self) -> io::Result<Option<u8>> {
        self.buf.peek_char()
    }

    pub fn cond_read_char<F>(&mut self, f: F) -> Result<Option<u8>>
                          where F: Fn(u8) -> bool {
        match try!(self.buf.peek_char()) {
            Some(ch) if f(ch) => {
                self.read_char().ok();
                Ok(Some(ch))
            }
            _ => Ok(None)
        }
    }

    pub fn read_word_char(&mut self) -> Result<Option<u8>> {
        self.cond_read_char(is_word_char)
    }

    pub fn scan_char(&mut self) -> Result<u8> {
        match try!(self.read_char()) {
            Some(ch) => self.ok(ch),
            None => self.err(SyntaxError::UnexpectedEof),
        }
    }

    pub fn scan_range<F>(&mut self, f: F) -> Result<u8>
                      where F: FnOnce(u8) -> bool {
        match try!(self.read_char()) {
            Some(ch) if f(ch) => self.ok(ch),
            Some(ch) => self.err(SyntaxError::Unexpected(ch)),
            None => self.err(SyntaxError::UnexpectedEof)
        }
    }

    pub fn skip_char(&mut self, ch: u8) -> Result<()> {
        if let Some(_) = try!(self.read_char()) { self.ok(()) }
        else { self.err(SyntaxError::Expected(vec![ch])) }
    }

    pub fn skip_while<F>(&mut self, f: F) -> Result<()>
                           where F: Fn(u8) -> bool {
        loop {
            match try!(self.buf.peek_char()) {
                Some(ch) if f(ch) => {
                    self.read_char().ok();
                }
                _ => return self.ok(())
            }
        }
    }

    pub fn skip_until<F>(&mut self, f: F) -> Result<u8>
                      where F: Fn(u8) -> bool {
        loop {
            match try!(self.read_char()) {
                Some(ch) if f(ch) => return self.ok(ch),
                None => return self.err(SyntaxError::UnexpectedEof),
                _ => { }
            }
        }
    }

    /// Scans the inside of an escape sequence, ie., without the leading `\`.
    pub fn scan_escape(&mut self) -> Result<u8> {
        match try!(self.read_char()) {
            Some(ch) if is_digit(ch) => {
                let ch2 = match try!(self.read_char()) {
                    Some(ch) if is_digit(ch) => ch,
                    Some(_) => {
                        return self.err(SyntaxError::IllegalEscape)
                    }
                    None => return self.eof()
                };
                let ch3 = match try!(self.read_char()) {
                    Some(ch) if is_digit(ch) => ch,
                    Some(_) => {
                        return self.err(SyntaxError::IllegalEscape)
                    }
                    None => return self.eof()
                };
                let res = ((ch - b'0') as u16) * 100
                        + ((ch2 - b'0') as u16) * 10
                        + ((ch3 - b'0') as u16);
                if res > 255 { self.err(SyntaxError::IllegalEscape) }
                else { Ok(res as u8) }
            }
            Some(ch) => Ok(ch),
            None => self.eof()
        }
    }

    pub fn skip_escape(&mut self) -> Result<()> {
        match try!(self.read_char()) {
            Some(ch) if is_digit(ch) => {
                match try!(self.read_char()) {
                    Some(ch) if is_digit(ch) => { }
                    Some(_) => return self.err(SyntaxError::IllegalEscape),
                    None => return self.eof()
                }
                match try!(self.read_char()) {
                    Some(ch) if is_digit(ch) => { }
                    Some(_) => return self.err(SyntaxError::IllegalEscape),
                    None => return self.eof()
                }
                self.ok(())
            }
            Some(_) => self.ok(()),
            None => self.eof()
        }
    }

    pub fn scan_word<T, F>(&mut self, f: F) -> Result<T>
                     where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        let curr = self.buf.curr();
        match try!(self.read_char()) {
            Some(ch) if is_word_char(ch) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        while let Some(_) = try!(self.cond_read_char(is_word_char)) { }
        let res = {
            let word = self.buf.slice_since(curr);
            f(word)
        };
        match res {
            Ok(res) => self.skip_space().map(|_| res),
            Err(err) => self.err(err)
        }
    }

    pub fn scan_word_chars<F>(&mut self, mut f: F) -> Result<()>
                           where F: FnMut(u8, bool) -> SyntaxResult<()> {
        match try!(self.peek_char()) {
            Some(ch) if is_word_char(ch) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        };
        while let Some(ch) = try!(self.cond_read_char(is_word_char)) {
            if ch == b'\\' {
                if let Err(err) = f(try!(self.scan_escape()), true) {
                    return self.err(err)
                }
            }
            else if let Err(err) = f(ch, false) {
                return self.err(err)
            }
        }
        self.ok(())
    }

    pub fn scan_quoted<T, F>(&mut self, f: F) -> Result<T>
                       where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        try!(self.skip_char(b'"'));
        let curr = self.buf.curr();
        loop {
            match try!(self.skip_until(|ch| ch == b'\\' || ch == b'"')) {
                b'\\' => try!(self.skip_escape()),
                b'"' => break,
                _ => { }
            }
        }
        let res = {
            let slice = self.buf.slice_since(curr);
            f(&slice[..slice.len() - 1])
        };
        match res {
            Ok(res) => self.skip_space().map(|_| res),
            Err(err) => self.err(err)
        }
    }

    pub fn scan_quoted_chars<F>(&mut self, mut f: F) -> Result<()>
                             where F: FnMut(u8, bool) -> SyntaxResult<()> {
        try!(self.skip_char(b'"'));
        loop {
            match try!(self.read_char()) {
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
        self.ok(())
    }

    pub fn scan_phrase<T, F>(&mut self, f: F) -> Result<T>
                       where F: FnOnce(&[u8]) -> SyntaxResult<T> {
        if let Some(b'"') = try!(self.buf.peek_char()) {
            self.scan_quoted(f)
        }
        else {
            self.scan_word(f)
        }
    }

    pub fn scan_str_phrase<T, F>(&mut self, f: F) -> Result<T>
                           where F: FnOnce(&str) -> SyntaxResult<T> {
        self.scan_phrase(|slice| {
            f(try!(str::from_utf8(slice)))
        })
    }

    pub fn scan_phrase_chars<F>(&mut self, f: F) -> Result<()>
                             where F: FnMut(u8, bool) -> SyntaxResult<()> {
        if let Some(b'"') = try!(self.peek_char()) {
            self.scan_quoted_chars(f)
        }
        else {
            self.scan_word_chars(f)
        }
    }

    pub fn scan_phrase_copy(&mut self) -> Result<Vec<u8>> {
        let mut res = Vec::new();
        try!(self.scan_phrase_chars(|ch, _| { res.push(ch); Ok(()) }));
        Ok(res)
    }

    pub fn scan_u16(&mut self) -> Result<u16> {
        self.scan_phrase(|slice| {
            let slice = match str::from_utf8(slice) {
                Ok(slice) => slice,
                Err(_) => return Err(SyntaxError::IllegalInteger)
            };
            Ok(try!(u16::from_str_radix(slice, 10)))
        })
    }

    pub fn scan_u32(&mut self) -> Result<u32> {
        self.scan_phrase(|slice| {
            let slice = match str::from_utf8(slice) {
                Ok(slice) => slice,
                Err(_) => return Err(SyntaxError::IllegalInteger)
            };
            Ok(try!(u32::from_str_radix(slice, 10)))
        })
    }

    /// Skips the word (!) in `literal` followed by space.
    ///
    /// Does not decode escapes.
    pub fn skip_literal(&mut self, literal: &[u8]) -> Result<()> {
        try!(self.scan_word(|s| {
            if s == literal {
                Ok(())
            }
            else {
                Err(SyntaxError::Expected(literal.into()))
            }
        }));
        self.skip_space()
    }

    pub fn scan_hex_word<F>(&mut self, mut f: F) -> Result<()>
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


    pub fn skip_space(&mut self) -> Result<()> {
        if try!(self.skip_opt_space()) {
            Ok(())
        }
        else {
            self.err(SyntaxError::ExpectedSpace)
        }
    }

    pub fn skip_opt_space(&mut self) -> Result<bool> {
        // This hides the parentheses madness, so it is slightly more complex
        // than it seems at first.
        let mut res = false;
        loop {
            if self.paren {
                match try!(self.cond_read_char(is_paren_space)) {
                    None => return self.ok(res),
                    Some(b'(') => {
                        return self.err(SyntaxError::NestedParentheses)
                    }
                    Some(b')') => {
                        self.paren = false
                    }
                    Some(b';') => {
                        if let Newline::Eof = try!(self.skip_comment()) {
                            return self.ok(true)
                        }
                    }
                    _ => { }
                }
            }
            else {
                match try!(self.cond_read_char(is_non_paren_space)) {
                    None => return self.ok(res),
                    Some(b'(') => {
                        self.paren = true
                    }
                    Some(b')') => {
                        return self.err(SyntaxError::Unexpected(b')'))
                    }
                    _ => { }
                }
            }
            res = true;
        }
    }

    fn skip_comment(&mut self) -> Result<Newline> {
        match self.skip_until(is_newline) {
            Ok(_) => self.ok(Newline::Real),
            Err(ref err) if err.is_eof() => self.ok(Newline::Eof),
            Err(err) => Err(err)
        }
    }

    pub fn scan_newline(&mut self) -> Result<Newline> {
        try!(self.skip_opt_space());
        match try!(self.read_char()) {
            Some(b';') => {
                self.skip_comment()
            }
            Some(ch) if is_newline(ch) => self.ok(Newline::Real),
            None => self.ok(Newline::Eof),
            _ => self.err(SyntaxError::ExpectedNewline)
        }
    }

    pub fn skip_entry(&mut self) -> Result<Newline> {
        // We try to skip over space, then break if we find a newline
        // or try to scan a phrase and start again.
        //
        // XXX This may not actually be the right thing to do, but then,
        //     this case should be really, really rare, so it may be good
        //     enough.
        loop {
            try!(self.skip_opt_space());
            match try!(self.read_char()) {
                Some(b';') => return self.skip_comment(),
                Some(ch) if is_newline(ch) => return self.ok(Newline::Real),
                None => return self.ok(Newline::Eof),
                _ => { }
            }
            try!(self.scan_phrase(|_| Ok(())));
        }
    }
}


impl<R: io::Read> Stream<R> {
    pub fn ok<T>(&mut self, t: T) -> Result<T> {
        self.buf.ok();
        Ok(t)
    }

    pub fn err<T>(&mut self, err: SyntaxError) -> Result<T> {
        let pos = self.buf.err();
        Err(Error::Syntax(err, pos))
    }

    pub fn eof<T>(&mut self) -> Result<T> {
        self.err(SyntaxError::UnexpectedEof)
    }

    pub fn ignore(&mut self) -> Pos {
        self.buf.err()
    }
}


//------------ Newline -------------------------------------------------------

pub enum Newline {
    Real,
    Eof
}


//------------ Buffer --------------------------------------------------------

pub struct Buffer<R: io::Read> {
    reader: R,
    buf: Vec<u8>,
    start: usize,
    curr: usize,
    start_pos: Pos,
    curr_pos: Pos
}

impl<R: io::Read> Buffer<R> {
    pub fn ok(&mut self) {
        if self.buf.len() == self.curr {
            self.buf.clear();
            self.start = 0;
            self.curr = 0;
            self.start_pos = self.curr_pos;
        }
    }

    pub fn err(&mut self) -> Pos {
        self.curr = self.start;
        self.curr_pos = self.start_pos;
        self.start_pos
    }

    pub fn read_char(&mut self) -> io::Result<Option<u8>> {
        self.peek_char().map(|res| match res {
            Some(ch) => {
                self.curr += 1;
                self.curr_pos.update(ch);
                Some(ch)
            }
            None => None
        })
    }

    pub fn peek_char(&mut self) -> io::Result<Option<u8>> {
        if self.buf.len() == self.curr {
            let mut buf = [0u8; 1];
            if try!(self.reader.read(&mut buf)) == 0 {
                return Ok(None)
            }
            self.buf.push(buf[0])
        }
        Ok(Some(self.buf[self.curr]))
    }

    pub fn curr(&self) -> usize {
        self.curr
    }

    pub fn slice_since(&self, since: usize) -> &[u8] {
        &self.buf[since..self.curr]
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

fn is_word_char(ch: u8) -> bool {
    ch != b' ' && ch != b'\t' && ch != b'\r' && ch != b'\n' &&
    ch != b'(' && ch != b')' && ch != b';' && ch != b'"'
}


//------------ Translation Functions ----------------------------------------

fn trans_hexdig(dig: u8) -> SyntaxResult<u8> {
    match dig {
        b'0' ... b'9' => Ok(dig - b'0'),
        b'A' ... b'F' => Ok(dig - b'A' + 10),
        b'a' ... b'f' => Ok(dig - b'a' + 10),
        _ => Err(SyntaxError::Unexpected(dig))
    }
}

