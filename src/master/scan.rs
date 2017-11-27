//! Scanning master file tokens.

use std::io;
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes, BytesMut};

// XXX Move these here for more compact imports.
pub use super::error::{ScanError, SyntaxError, Pos};


//------------ CharSource ----------------------------------------------------

pub trait CharSource {
    fn next(&mut self) -> Result<Option<char>, io::Error>;
}


//------------ Scanner -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Scanner<C: CharSource> {
    /// The underlying character source.
    chars: C,

    /// The buffer for rejected tokens.
    ///
    /// It will be kept short by flushing it every time we successfully read
    /// to its end.
    buf: Vec<Symbol>,

    /// Index in `buf` of the start of the token currently being read.
    start: usize,

    /// Index in `buf` of the next character to be read.
    cur: usize,

    /// Human-friendly position in `reader` of `start`.
    start_pos: Pos,

    /// Human-friendly position in `reader` of `cur`.
    cur_pos: Pos,

    /// Was the start of token in a parenthesized group?
    paren: bool,

    /// Our newline mode
    newline: NewlineMode,
}


/// # Creation
///
impl<C: CharSource> Scanner<C> {
    /// Creates a new scanner.
    pub fn new(chars: C) -> Self {
        Scanner::with_pos(chars, Pos::new())
    }

    /// Creates a new scanner using the given character source and position.
    ///
    /// The scanner will assume that the current position of `chars`
    /// corresponds to the human-friendly position `pos`.
    pub fn with_pos(chars: C, pos: Pos) -> Self {
        Scanner {
            chars,
            buf: Vec::new(),
            start: 0,
            cur: 0,
            start_pos: pos,
            cur_pos: pos,
            paren: false,
            newline: NewlineMode::Unknown,
        }
    }
}


/// # Fundamental Scanning
///
impl<C: CharSource> Scanner<C> {
    /// Returns whether the scanner has reached the end of data.
    pub fn is_eof(&mut self) -> bool {
        match self.peek() {
            Ok(Some(_)) => false,
            _ => true
        }
    }

    /// Returns the current position of the scanner.
    pub fn pos(&self) -> Pos {
        self.cur_pos
    }

    pub fn try_scan<T, U, F, G>(&mut self, scanop: F, finalop: G)
                                -> Result<U, ScanError>
                    where F: FnOnce(&mut Self) -> Result<T, ScanError>,
                          G: FnOnce(T) -> Result<U, SyntaxError> {
        let res = scanop(self)?;
        finalop(res).or_else(|err| self.err(err))
    }


    /// Scans a word token.
    ///
    /// A word is a sequence of non-special characters and escape sequences
    /// followed by a non-empty sequence of space unless it is followed
    /// directly by a [newline](#tymethod.scan_newline). If successful, the
    /// method will position at the end of the space sequence if it is
    /// required. That is, you can scan for two subsequent word tokens
    /// without worrying about the space between them.
    ///
    /// The method starts out with a `target` value and two closures. The
    /// first closure, `symbolop`, is being fed symbols of the word one by one
    /// and should feed them into the target. Once the word ended, the
    /// second closure is called to convert the target into the final result.
    /// Both can error out at any time stopping processing and leading the
    /// scanner to revert to the beginning of the token.
    pub fn scan_word<T, U, F, G>(&mut self, mut target: T, mut symbolop: F,
                                 finalop: G) -> Result<U, ScanError>
                     where F: FnMut(&mut T, Symbol)
                                    -> Result<(), SyntaxError>,
                           G: FnOnce(T) -> Result<U, SyntaxError> {
        match self.peek()? {
            Some(ch) if ch.is_word_char() => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        };
        while let Some(ch) = self.cond_read(Symbol::is_word_char)? {
            if let Err(err) = symbolop(&mut target, ch) {
                return self.err_cur(err)
            }
        }
        let res = match finalop(target) {
            Ok(res) => res,
            Err(err) => return self.err(err)
        };
        self.skip_delimiter()?;
        Ok(res)
    }

    /// Scans a quoted word.
    ///
    /// A quoted word starts with a double quote `"`, followed by all sorts
    /// of characters or escape sequences until the next (unescaped) double
    /// quote. It may contain line feeds. Like a regular word, a quoted word
    /// is followed by a non-empty space sequence unless it is directly
    /// followed by a [newline](#tymethod.scan_newline). This space is not
    /// part of the content but quietly skipped over.
    ///
    /// The method starts out with a `target` value and two closures. The
    /// first closure, `symbolop`, is being fed symbols of the word one by one
    /// and should feed them into the target. Once the word ended, the
    /// second closure is called to convert the target into the final result.
    /// Both can error out at any time stopping processing and leading the
    /// scanner to revert to the beginning of the token.
    pub fn scan_quoted<T, U, F, G>(&mut self, mut target: T, mut symbolop: F,
                                   finalop: G) -> Result<U, ScanError>
                       where F: FnMut(&mut T, Symbol)
                                    -> Result<(), SyntaxError>,
                             G: FnOnce(T) -> Result<U, SyntaxError> {
        match self.read()? {
            Some(Symbol::Char('"')) => { }
            Some(ch) => return self.err(SyntaxError::Unexpected(ch)),
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        loop {
            match self.read()? {
                Some(Symbol::Char('"')) => break,
                Some(ch) => {
                    if let Err(err) = symbolop(&mut target, ch) {
                        return self.err(err)
                    }
                }
                None => return self.err(SyntaxError::UnexpectedEof),
            }
        }
        let res = match finalop(target) {
            Ok(res) => res,
            Err(err) => return self.err(err)
        };
        self.skip_delimiter()?;
        Ok(res)
    }

    /// Scans a phrase: a normal word or a quoted word.
    ///
    /// This method behaves like [scan_quoted()](#tymethod.scan_quoted) if
    /// the next character is a double quote or like
    /// [scan_word()](#tymethod.scan_word) otherwise.
    pub fn scan_phrase<T, U, F, G>(&mut self, target: T, symbolop: F,
                                   finalop: G) -> Result<U, ScanError>
                       where F: FnMut(&mut T, Symbol)
                                    -> Result<(), SyntaxError>,
                             G: FnOnce(T) -> Result<U, SyntaxError> {
        if let Some(Symbol::Char('"')) = self.peek()? {
            self.scan_quoted(target, symbolop, finalop)
        }
        else {
            self.scan_word(target, symbolop, finalop)
        }
    }

    /// Scans a phrase with byte content into a `Bytes` value.
    ///
    /// The method scans a phrase that consists of byte only and puts these
    /// bytes into a `Bytes` value. Once the word ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
    pub fn scan_byte_phrase<U, G>(&mut self, finalop: G)
                                  -> Result<U, ScanError>
                            where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        self.scan_phrase(
            BytesMut::new(),
            |buf, symbol| symbol.push_to_buf(buf),
            |buf| finalop(buf.freeze())
        )
    }

    /// Scans a phrase with Unicode text into a `String`.
    pub fn scan_string_phrase<U, G>(&mut self, finalop: G)
                                    -> Result<U, ScanError>
                              where G: FnOnce(String)
                                              -> Result<U, SyntaxError> {
        self.scan_phrase(
            String::new(),
            |res, ch| {
                let ch = match ch {
                    Symbol::Char(ch) | Symbol::SimpleEscape(ch) => ch,
                    Symbol::DecimalEscape(ch) => ch as char,
                    Symbol::Newline => unreachable!(),
                };
                res.push(ch);
                Ok(())
            },
            |res| finalop(res)
        )
    }

    /// Scans over a mandatory newline.
    ///
    /// A newline is either an optional comment followed by a newline sequence
    /// or the end of file. The latter is so that a file lacking a line feed
    /// after its last line is still parsed successfully.
    pub fn scan_newline(&mut self) -> Result<(), ScanError> {
        match self.read()? {
            Some(Symbol::Char(';')) => {
                while let Some(ch) = self.read()? {
                    if ch.is_newline() {
                        break
                    }
                }
                self.ok(())
            }
            Some(Symbol::Newline) => self.ok(()),
            None => self.ok(()),
            _ => self.err(SyntaxError::ExpectedNewline)
        }
    }

    /// Scans over a mandatory sequence of space.
    ///
    /// There are two flavors of space. The simple form is any sequence
    /// of a space character `' '` or a horizontal tab '`\t'`. However,
    /// a parenthesis can be used to turn [newlines](#tymethod.scan_newline)
    /// into normal space. This method recognises parentheses and acts
    /// accordingly.
    pub fn scan_space(&mut self) -> Result<(), ScanError> {
        if self.skip_space()? {
            self.ok(())
        }
        else {
            self.err(SyntaxError::ExpectedSpace)
        }
    }

    /// Scans over an optional sequence of space.
    pub fn scan_opt_space(&mut self) -> Result<(), ScanError> {
        self.skip_space()?;
        Ok(())
    }

    /// Skips over an entry.
    ///
    /// Keeps reading until it successfully scans a newline. The method
    /// tries to be smart about that and considers parentheses, quotes, and
    /// escapes but also tries its best to not fail.
    pub fn skip_entry(&mut self) -> Result<(), ScanError> {
        let mut quote = false;
        loop {
            match self.read()? {
                None => break,
                Some(Symbol::Newline) => {
                    if !quote && !self.paren {
                        break
                    }
                }
                Some(Symbol::Char('"')) => quote = !quote,
                Some(Symbol::Char('(')) => {
                    if !quote {
                        if self.paren {
                            return self.err(SyntaxError::NestedParentheses)
                        }
                        self.paren = true
                    }
                }
                Some(Symbol::Char(')')) => {
                    if !quote {
                        if !self.paren {
                            return self.err(SyntaxError::Unexpected(')'.into()))
                        }
                        self.paren = false
                    }
                }
                _ => { }
            }
        }
        self.ok(())
    }

    /// Skips over the word with the content `literal`.
    ///
    /// The content indeed needs to be literally the literal. Escapes are
    /// not translated before comparison and case has to be as is.
    pub fn skip_literal(&mut self, literal: &str) -> Result<(), ScanError> {
        self.scan_word(
            literal,
            |left, symbol| {
                let first = match left.chars().next() {
                    Some(ch) => ch,
                    None => return Err(SyntaxError::Expected(literal.into()))
                };
                match symbol {
                    Symbol::Char(ch) if ch == first => {
                        *left = &left[ch.len_utf8()..];
                        Ok(())
                    }
                    _ => Err(SyntaxError::Expected(literal.into()))
                }
            },
            |left| {
                if left.is_empty() {
                    Ok(())
                }
                else {
                    Err(SyntaxError::Expected(literal.into()))
                }
            }
        )
    }
}

/// # Complex Scanning
///
impl<C: CharSource> Scanner<C> {
    /// Scans a word containing a sequence of pairs of hex digits.
    ///
    /// The word is returned as a `Bytes` value with each byte representing
    /// the decoded value of one hex digit pair.
    pub fn scan_hex_word<U, G>(&mut self, finalop: G) -> Result<U, ScanError>
                         where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        self.scan_word(
            (BytesMut::new(), None), // result and optional first char.
            |&mut (ref mut res, ref mut first), symbol | {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        match ch.to_digit(16) {
                            Some(ch) => ch,
                            _ => return Err(SyntaxError::Unexpected(symbol)),
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol))
                };
                if let Some(ch1) = *first {
                    if res.remaining_mut() == 0 {
                        res.reserve(1)
                    }
                    res.put_u8((ch1 as u8) << 4 | (ch as u8));
                }
                else {
                    *first = Some(ch)
                }
                Ok(())
            },
            |(res, first)| {
                if let Some(ch) = first {
                    Err(SyntaxError::Unexpected(
                            Symbol::Char(::std::char::from_digit(ch, 16)
                                                                .unwrap())))
                }
                else {
                    finalop(res.freeze())
                }
            }
        )
    }
}


/// # Fundamental Reading, Processing, and Back-tracking
///
impl<C: CharSource> Scanner<C> {
    /// Reads a char from the source.
    ///
    /// This function is here to for error conversion only.
    fn chars_next(&mut self) -> Result<Option<char>, ScanError> {
        self.chars.next().map_err(|err| {
            let mut pos = self.cur_pos.clone();
            for ch in &self.buf {
                pos.update(*ch)
            }
            ScanError::Source(err, pos)
        })
    }

    /// Tries to read at least one additional character into the buffer.
    ///
    /// Returns whether that succeeded.
    fn source_symbol(&mut self) -> Result<bool, ScanError> {
        let ch = match self.chars_next()? {
            Some(ch) => ch,
            None => return Ok(false),
        };
        if ch == '\\' {
            self.source_escape()
        }
        else {
            self.source_normal(ch)
        }
    }

    /// Tries to read and return the content of an escape sequence.
    fn source_escape(&mut self) -> Result<bool, ScanError> {
        let ch = match self.chars_next()? {
            Some(ch) if ch.is_digit(10) => {
                let ch = ch.to_digit(10).unwrap() * 100;
                let ch2 = match self.chars_next()? {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch * 10,
                        None => {
                            return self.err_cur(SyntaxError::IllegalEscape)
                        }
                    }
                    None => {
                        return self.err_cur(SyntaxError::UnexpectedEof)
                    }
                };
                let ch3 = match self.chars_next()? {
                    Some(ch)  => match ch.to_digit(10) {
                        Some(ch) => ch,
                        None => {
                            return self.err_cur(SyntaxError::IllegalEscape)
                        }
                    }
                    None => {
                        return self.err_cur(SyntaxError::UnexpectedEof)
                    }
                };
                let res = ch + ch2 + ch3;
                if res > 255 {
                    return self.err_cur(SyntaxError::IllegalEscape)
                }
                else {
                    Symbol::DecimalEscape(res as u8)
                }
            }
            Some(ch) => Symbol::SimpleEscape(ch),
            None => {
                return self.err_cur(SyntaxError::UnexpectedEof)
            }
        };
        self.buf.push(ch);
        Ok(true)
    }

    /// Tries to source a normal character.
    ///
    fn source_normal(&mut self, ch: char) -> Result<bool, ScanError> {
        match self.newline {
            NewlineMode::Single(sep) => {
                if ch == sep {
                    self.buf.push(Symbol::Newline)
                }
                else {
                    self.buf.push(Symbol::Char(ch))
                }
                Ok(true)
            }
            NewlineMode::Double(first, second) => {
                if ch != first {
                    self.buf.push(Symbol::Char(ch));
                    Ok(true)
                }
                else {
                    match self.chars_next()? {
                        Some(ch) if ch == second => {
                            self.buf.push(Symbol::Newline);
                            Ok(true)
                        }
                        Some(ch) => {
                            self.buf.push(Symbol::Char(first));
                            self.buf.push(Symbol::Char(ch));
                            Ok(true)
                        }
                        None => {
                            // Half a newline is still EOF.
                            Ok(false)
                        }
                    }
                }
            }
            NewlineMode::Unknown => {
                if ch != '\r' && ch != '\n' {
                    self.buf.push(Symbol::Char(ch));
                    Ok(true)
                }
                else if let Some(second) = self.chars_next()? {
                    match (ch, second) {
                        ('\r', '\n') | ('\n', '\r') => {
                            self.newline = NewlineMode::Double(ch, second);
                            self.buf.push(Symbol::Newline);
                        }
                        ('\r', '\r') | ('\n', '\n')  => {
                            self.newline = NewlineMode::Single(ch);
                            self.buf.push(Symbol::Newline);
                            self.buf.push(Symbol::Newline);
                        }
                        ('\r', _) | ('\n', _) => {
                            self.newline = NewlineMode::Single(ch);
                            self.buf.push(Symbol::Newline);
                            self.buf.push(Symbol::Char(second));
                        }
                        _ => {
                            self.buf.push(Symbol::Char(ch));
                            self.buf.push(Symbol::Char(second));
                        }
                    }
                    Ok(true)
                }
                else {
                    if ch == '\r' || ch == '\n' {
                        self.buf.push(Symbol::Newline);
                    }
                    else {
                        self.buf.push(Symbol::Char(ch))
                    }
                    Ok(true)
                }
            }
        }
    }
    
    /// Tries to peek at the next symbol.
    ///
    /// On success, returns the symbol. It the end of the
    /// underlying source is reached, returns `Ok(None)`. If reading on the
    /// underlying source results in an error, returns that.
    fn peek(&mut self) -> Result<Option<Symbol>, ScanError> {
        if self.buf.len() == self.cur {
            if !self.source_symbol()? {
                return Ok(None)
            }
        }
        Ok(Some(self.buf[self.cur]))
    }

    /// Tries to read a symbol.
    ///
    /// On success, returns the `Ok(Some(_))` character. It the end of the
    /// underlying source is reached, returns `Ok(None)`. If reading on the
    /// underlying source results in an error, returns that.
    fn read(&mut self) -> Result<Option<Symbol>, ScanError> {
        self.peek().map(|res| match res {
            Some(ch) => {
                self.cur += 1;
                self.cur_pos.update(ch);
                Some(ch)
            }
            None => None
        })
    }

    /// Progresses the scanner to the current position and returns `t`.
    fn ok<T>(&mut self, t: T) -> Result<T, ScanError> {
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
    /// create whatever particular result is needed.
    fn err<T>(&mut self, err: SyntaxError) -> Result<T, ScanError> {
        let pos = self.start_pos;
        self.err_at(err, pos)
    }

    fn err_cur<T>(&mut self, err: SyntaxError) -> Result<T, ScanError> {
        let pos = self.cur_pos;
        self.err_at(err, pos)
    }

    /// Reports an error at current position and then backtracks.
    fn err_at<T>(&mut self, err: SyntaxError, pos: Pos)
                 -> Result<T, ScanError> {
        self.cur = self.start;
        self.cur_pos = self.start_pos;
        Err(ScanError::Syntax(err, pos))
    }
}

/// # More Complex Internal Reading
///
impl<C: CharSource> Scanner<C> {
    /// Reads a symbol if it is accepted by a closure.
    ///
    /// The symbol is passed to the closure which should return `true` if
    /// it accepts it in which case the method returns `Ok(Some(_))`. If
    /// the closure returns `false` or the end of file is reached, `Ok(None)`
    /// is returned.
    ///
    /// The method does not progress or backtrack.
    fn cond_read<F>(&mut self, f: F)
                         -> Result<Option<Symbol>, ScanError>
                      where F: FnOnce(Symbol) -> bool {
        match self.peek()? {
            Some(ch) if f(ch) => self.read(),
            _ => Ok(None)
        }
    }

    /// Skips over delimiting space.
    ///
    /// A delimiter is a non-empty sequence of space (which means that
    /// something like `"foo(bar"` qualifies as the two words `"foo"` and
    /// `"bar".) or if the following byte is the beginning of a newline or
    /// if the scanner has reached end-of-file.
    ///
    /// Progresses the scanner on success, otherwise backtracks with an
    /// ‘unexpected space’ error.
    fn skip_delimiter(&mut self) -> Result<(), ScanError> {
        if self.skip_space()? {
            self.ok(())
        }
        else {
            match self.peek()? {
                Some(ch) if ch.is_newline_ahead() => self.ok(()),
                None => self.ok(()),
                _ => self.err(SyntaxError::ExpectedSpace)
            }
        }
    }

    /// Skips over space.
    ///
    /// Normally, space is ordinary white space (`' '` and `'\t'`).
    /// However, an opening parenthesis can be used to make newlines appear
    /// as space, too. A closing parenthesis resets this behaviour.
    ///
    /// This method cleverly hides all of this and simply walks over whatever
    /// is space. It returns whether there was at least one character of
    /// space.  It does not progress the scanner but backtracks on error.
    fn skip_space(&mut self) -> Result<bool, ScanError> {
        let mut res = false;
        loop {
            if self.paren {
                match self.cond_read(Symbol::is_paren_space)? {
                    None => break,
                    Some(Symbol::Char('(')) => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::NestedParentheses,
                                           pos)
                    }
                    Some(Symbol::Char(')')) => {
                        self.paren = false;
                    }
                    Some(Symbol::Char(';')) => {
                        while let Some(ch) = self.read()? {
                            if ch.is_newline() {
                                break
                            }
                        }
                    }
                    _ => { }
                }
            }
            else {
                match self.cond_read(Symbol::is_non_paren_space)? {
                    None => break,
                    Some(Symbol::Char('(')) => {
                        self.paren = true;
                    }
                    Some(Symbol::Char(')')) => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::Unexpected(
                                                    Symbol::Char(')')), pos)
                    }
                    _ => { }
                }
            }
            res = true;
        }
        Ok(res)
    }
}


//------------ Scannable -----------------------------------------------------

pub trait Scannable: Sized {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError>;
}

impl Scannable for u32 {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u32,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value
                        }
                        else {
                            return Err(SyntaxError::Unexpected(symbol))
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol))
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                Ok(())
            },
            |res| Ok(res)
        )
    }
}

impl Scannable for u16 {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u16,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value as u16
                        }
                        else {
                            return Err(SyntaxError::Unexpected(symbol))
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol))
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                Ok(())
            },
            |res| Ok(res)
        )
    }
}


impl Scannable for u8 {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_phrase(
            0u8,
            |res, symbol| {
                let ch = match symbol {
                    Symbol::Char(ch) => {
                        if let Some(value) = ch.to_digit(10) {
                            value as u8
                        }
                        else {
                            return Err(SyntaxError::Unexpected(symbol))
                        }
                    }
                    _ => return Err(SyntaxError::Unexpected(symbol))
                };
                *res = match res.checked_mul(10) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                *res = match res.checked_add(ch) {
                    Some(res) => res,
                    None => return Err(SyntaxError::IllegalInteger)
                };
                Ok(())
            },
            |res| Ok(res)
        )
    }
}


//------------ Symbol --------------------------------------------------------

/// A single symbol parsed from a master file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// An unescaped Unicode character.
    Char(char),

    /// An escape character by simply being backslashed.
    SimpleEscape(char),

    /// An escaped character using the decimal escape sequence.
    DecimalEscape(u8),

    /// A new line.
    ///
    /// This needs special treatment because of the varying encoding of
    /// newlines on different systems.
    Newline,
}

impl Symbol {
    /// Converts the symbol into a byte if it represents one.
    ///
    /// Both domain names and character strings operate on bytes instead of
    /// (Unicode) characters. These bytes can be represented by ASCII
    /// characters, both plain or through a simple escape, or by a decimal
    /// escape.
    ///
    /// This method returns such a byte or a `SyntaxError::Unexpected(_)` if
    /// the symbol isn’t such a byte.
    pub fn into_byte(self) -> Result<u8, SyntaxError> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                if ch.is_ascii() {
                    Ok(ch as u8)
                }
                else {
                    Err(SyntaxError::Unexpected(self))
                }
            }
            Symbol::DecimalEscape(ch) => Ok(ch),
            _ => Err(SyntaxError::Unexpected(self))
        }
    }

    pub fn into_digit(self, base: u32) -> Result<u32, SyntaxError> {
        if let Symbol::Char(ch) = self {
            match ch.to_digit(base) {
                Some(ch) => Ok(ch),
                None => Err(SyntaxError::Unexpected(self))
            }
        }
        else {
            Err(SyntaxError::Unexpected(self))
        }
    }

    /// Pushes a symbol that is a byte to the end of a byte buffer.
    ///
    /// If the symbol is a byte as per the rules described in `into_byte`,
    /// it will be pushed to the end of `buf`, reserving additional space
    /// if there isn’t enough space remaining.
    pub fn push_to_buf(self, buf: &mut BytesMut) -> Result<(), SyntaxError> {
        self.into_byte().map(|ch| {
            if buf.remaining_mut() == 0 {
                buf.reserve(1);
            }
            buf.put_u8(ch)
        })
    }

    /// Checks for space-worthy character outside a parenthesized group.
    ///
    /// These are horizontal white space plus opening and closing parentheses
    /// which need special treatment.
    fn is_non_paren_space(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch == ' ' || ch == '\t' || ch == '(' || ch == ')'
            }
            _ => false
        }
    }

    /// Checks for space-worthy character inside a parenthesized group.
    ///
    /// These are all from `is_non_paren_space()` plus a semicolon and line
    /// break characters.
    fn is_paren_space(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch == ' ' || ch == '\t' || ch == '(' || ch == ')' ||
                ch == ';'
            }
            Symbol::Newline => true,
            _ => false
        }
    }

    fn is_newline(self) -> bool {
        match self {
            Symbol::Newline => true,
            _ => false,
        }
    }

    fn is_newline_ahead(self) -> bool {
        match self {
            Symbol::Char(';') => true,
            Symbol::Newline => true,
            _ => false,
        }
    }

    fn is_word_char(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch != ' ' && ch != '\t' && 
                ch != '(' && ch != ')' && ch != ';' && ch != '"'
            }
            Symbol::Newline => false,
            _ => true
        }
    }
}

impl From<char> for Symbol {
    fn from(ch: char) -> Self {
        Symbol::Char(ch)
    }
}


//------------ NewLineMode ---------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NewlineMode {
    /// Each occurence of the content is a newline.
    Single(char),

    /// Each combination of the two chars is a newline.
    Double(char, char),

    /// We don’t know yet.
    Unknown,
}

