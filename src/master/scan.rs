//! Scanning master file tokens.

use std::{fmt, io};
use std::net::AddrParseError;
use bytes::{BufMut, Bytes, BytesMut};
use failure::Fail;
use ::bits::name;
use ::bits::name::Dname;
use ::utils::{base32, base64};


//------------ CharSource ----------------------------------------------------

/// A source of master file characters.
///
/// This is very similar to an iterator except that `next`’s return value has
/// the result outside for easier error handling.
pub trait CharSource {
    /// Provides the next character in the source.
    ///
    /// If the source runs out of characters, returns `Ok(None)`.
    fn next(&mut self) -> Result<Option<char>, io::Error>;
}


//------------ Scanner -------------------------------------------------------

/// Reader of master file tokens.
///
/// A scanner reads characters from a source and converts them into tokens or
/// errors.
#[derive(Clone, Debug)]
pub struct Scanner<C: CharSource> {
    /// The underlying character source.
    chars: C,

    /// The buffer for rejected tokens.
    ///
    /// It will be kept short by flushing it every time we successfully read
    /// to its end.
    buf: Vec<Token>,

    /// Index in `buf` of the start of the token currently being read.
    start: usize,

    /// Index in `buf` of the next character to be read.
    cur: usize,

    /// Human-friendly position in `chars` of `start`.
    start_pos: Pos,

    /// Human-friendly position in `chars` of `cur`.
    cur_pos: Pos,

    /// Was the start of token in a parenthesized group?
    paren: bool,

    /// Our newline mode
    newline: NewlineMode,

    /// The current origin for domain names, if any.
    origin: Option<Dname>,
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
            origin: None,
        }
    }
}

/// # Access to Origin
///
/// Domain names in a master file that do not end in a dot are relative to
/// some origin. This origin is simply appened to them to form an absolute
/// name.
///
/// Since domain names can appear all over the place and we don’t want to
/// have to pass around the origin all the time, it is part of the scanner
/// and can be set and retrieved any time.
impl<C: CharSource> Scanner<C> {
    /// Returns the current origin if any.
    pub fn origin(&self) -> &Option<Dname> {
        &self.origin
    }

    /// Sets the origin to the given value.
    pub fn set_origin(&mut self, origin: Option<Dname>) {
        self.origin = origin
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

    /// Scans a word token.
    ///
    /// A word is a sequence of non-special characters and escape sequences
    /// followed by a non-empty sequence of space unless it is followed
    /// directly by a [newline](#method.scan_newline). If successful, the
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
            Some(Token::Symbol(ch)) => {
                if !ch.is_word_char() {
                    return self.err(SyntaxError::Unexpected(ch))
                }
            }
            Some(Token::Newline) => {
                return self.err(SyntaxError::UnexpectedNewline)
            }
            None => return self.err(SyntaxError::UnexpectedEof)
        };
        while let Some(ch) = self.cond_read_symbol(Symbol::is_word_char)? {
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

    /// Scans a word with Unicode text into a `String`.
    ///
    /// The method scans a word that consists of characters and puts these
    /// into a `String`. Once the word ends, the caller is given a chance
    /// to convert the value into something else via the closure `finalop`.
    /// This closure can fail, resulting in an error and back-tracking to
    /// the beginning of the phrase.
    pub fn scan_string_word<U, G>(&mut self, finalop: G)
           -> Result<U, ScanError>
    where G: FnOnce(String) -> Result<U, SyntaxError> {
        self.scan_word(
            String::new(),
            |res, ch| {
                let ch = match ch {
                    Symbol::Char(ch) | Symbol::SimpleEscape(ch) => ch,
                    Symbol::DecimalEscape(ch) => ch as char,
                };
                res.push(ch);
                Ok(())
            },
            |res| finalop(res)
        )
    }

    /// Scans a quoted word.
    ///
    /// A quoted word starts with a double quote `"`, followed by all sorts
    /// of characters or escape sequences until the next (unescaped) double
    /// quote. It may contain line feeds. Like a regular word, a quoted word
    /// is followed by a non-empty space sequence unless it is directly
    /// followed by a [newline](#method.scan_newline). This space is not
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
            Some(Token::Symbol(Symbol::Char('"'))) => { }
            Some(Token::Symbol(ch)) => {
                return self.err(SyntaxError::Unexpected(ch))
            }
            Some(Token::Newline) => {
                return self.err(SyntaxError::UnexpectedNewline)
            }
            None => return self.err(SyntaxError::UnexpectedEof)
        }
        loop {
            match self.read()? {
                Some(Token::Symbol(Symbol::Char('"'))) => break,
                Some(Token::Symbol(ch)) => {
                    if let Err(err) = symbolop(&mut target, ch) {
                        return self.err(err)
                    }
                }
                Some(Token::Newline) => {
                    return self.err(SyntaxError::UnexpectedNewline)
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
    /// This method behaves like [scan_quoted()](#method.scan_quoted) if
    /// the next character is a double quote or like
    /// [scan_word()](#method.scan_word) otherwise.
    pub fn scan_phrase<T, U, F, G>(&mut self, target: T, symbolop: F,
                                   finalop: G) -> Result<U, ScanError>
                       where F: FnMut(&mut T, Symbol)
                                    -> Result<(), SyntaxError>,
                             G: FnOnce(T) -> Result<U, SyntaxError> {
        if let Some(Token::Symbol(Symbol::Char('"'))) = self.peek()? {
            self.scan_quoted(target, symbolop, finalop)
        }
        else {
            self.scan_word(target, symbolop, finalop)
        }
    }

    /// Scans a phrase with byte content into a `Bytes` value.
    ///
    /// The method scans a phrase that consists of byte only and puts these
    /// bytes into a `Bytes` value. Once the phrase ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
    pub fn scan_byte_phrase<U, G>(&mut self, finalop: G)
                                  -> Result<U, ScanError>
                            where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        self.scan_phrase(
            BytesMut::new(),
            |buf, symbol| symbol.push_to_buf(buf).map_err(Into::into),
            |buf| finalop(buf.freeze())
        )
    }

    /// Scans a phrase with Unicode text into a `String`.
    ///
    /// The method scans a phrase that consists of characters and puts these
    /// into a `String`. Once the phrase ends, the caller is given
    /// a chance to convert the value into something else via the closure
    /// `finalop`. This closure can fail, resulting in an error and
    /// back-tracking to the beginning of the phrase.
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
            Some(Token::Symbol(Symbol::Char(';'))) => {
                while let Some(ch) = self.read()? {
                    if ch.is_newline() {
                        break
                    }
                }
                self.ok(())
            }
            Some(Token::Newline) => self.ok(()),
            None => self.ok(()),
            _ => self.err(SyntaxError::ExpectedNewline)
        }
    }

    /// Scans over a mandatory sequence of space.
    ///
    /// There are two flavors of space. The simple form is any sequence
    /// of a space character `' '` or a horizontal tab '`\t'`. However,
    /// a parenthesis can be used to turn [newlines](#method.scan_newline)
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
                Some(Token::Newline) => {
                    if !quote && !self.paren {
                        break
                    }
                }
                Some(Token::Symbol(Symbol::Char('"'))) => quote = !quote,
                Some(Token::Symbol(Symbol::Char('('))) => {
                    if !quote {
                        if self.paren {
                            return self.err(SyntaxError::NestedParentheses)
                        }
                        self.paren = true
                    }
                }
                Some(Token::Symbol(Symbol::Char(')'))) => {
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
                hex_symbolop(res, first, symbol)
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

    pub fn scan_hex_words<U, G>(&mut self, finalop: G) -> Result<U, ScanError>
    where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        let start_pos = self.pos();
        let mut buf = BytesMut::new();
        let mut first = true;
        loop {
            let res = self.scan_word(
                (&mut buf, None),
                |&mut (ref mut buf, ref mut first), symbol| {
                    hex_symbolop(buf, first, symbol)
                },
                |(_, first)| {
                    if let Some(ch) = first {
                        Err(SyntaxError::Unexpected(
                            Symbol::Char(
                                ::std::char::from_digit(ch, 16).unwrap()
                            )
                        ))
                    }
                    else {
                        Ok(())
                    }
                }
            );
            if first {
                if let Err(err) = res {
                    return Err(err)
                }
                first = false;
            }
            else {
                if let Err(_) = res {
                    break
                }
            }
        }
        finalop(buf.freeze()).map_err(|err| (err, start_pos).into())
    }

    /// Scans a phrase containing base32hex encoded data.
    ///
    /// In particular, this decodes the “base32hex” decoding definied in
    /// RFC 4648 without padding.
    pub fn scan_base32hex_phrase<U, G>(
        &mut self,
        finalop: G
    ) -> Result<U, ScanError>
    where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        self.scan_phrase(
            base32::Decoder::new_hex(),
            |decoder, symbol| {
                decoder.push(symbol.into_char()?)
                       .map_err(SyntaxError::content)
            },
            |decoder| {
                finalop(decoder.finalize().map_err(SyntaxError::content)?)
            }
        )
    }

    /// Scans a sequence of phrases containing base64 encoded data.
    pub fn scan_base64_phrases<U, G>(
        &mut self,
        finalop: G
    ) -> Result<U, ScanError>
    where G: FnOnce(Bytes) -> Result<U, SyntaxError> {
        let start_pos = self.pos();
        let mut decoder = base64::Decoder::new();
        let mut first = true;
        loop {
            let res = self.scan_phrase(
                &mut decoder, 
                |decoder, symbol| {
                    decoder.push(symbol.into_char()?)
                           .map_err(SyntaxError::content)
                },
                Ok
            );
            if first {
                if let Err(err) = res {
                    return Err(err)
                }
                first = false;
            }
            else {
                if let Err(_) = res {
                    break
                }
            }
        }
        let bytes = decoder.finalize().map_err(|err| {
            (SyntaxError::content(err), self.pos())
        })?;
        finalop(bytes).map_err(|err| (err, start_pos).into())
    }
}

fn hex_symbolop(
    buf: &mut BytesMut,
    first: &mut Option<u32>,
    symbol: Symbol
) -> Result<(), SyntaxError> {
    let ch = match symbol {
        Symbol::Char(ch) => {
            match ch.to_digit(16) {
                Some(ch) => ch,
                _ => return Err(SyntaxError::Unexpected(symbol))
            }
        }
        _ => return Err(SyntaxError::Unexpected(symbol))
    };
    if let Some(ch1) = first.take() {
        if buf.remaining_mut() == 0 {
            buf.reserve(1)
        }
        buf.put_u8((ch1 as u8) << 4 | (ch as u8));
    }
    else {
        *first = Some(ch)
    }
    Ok(())
}


/// # Fundamental Reading, Processing, and Back-tracking
///
impl<C: CharSource> Scanner<C> {
    /// Reads a char from the source.
    ///
    /// This function is here to for error conversion only and updating the
    /// human-friendly position.
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
    fn source_token(&mut self) -> Result<bool, ScanError> {
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
        self.buf.push(Token::Symbol(ch));
        Ok(true)
    }

    /// Tries to source a normal character.
    fn source_normal(&mut self, ch: char) -> Result<bool, ScanError> {
        match self.newline {
            NewlineMode::Single(sep) => {
                if ch == sep {
                    self.buf.push(Token::Newline)
                }
                else {
                    self.buf.push(Token::Symbol(Symbol::Char(ch)))
                }
                Ok(true)
            }
            NewlineMode::Double(first, second) => {
                if ch != first {
                    self.buf.push(Token::Symbol(Symbol::Char(ch)));
                    Ok(true)
                }
                else {
                    match self.chars_next()? {
                        Some(ch) if ch == second => {
                            self.buf.push(Token::Newline);
                            Ok(true)
                        }
                        Some(ch) => {
                            self.buf.push(Token::Symbol(Symbol::Char(first)));
                            self.buf.push(Token::Symbol(Symbol::Char(ch)));
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
                    self.buf.push(Token::Symbol(Symbol::Char(ch)));
                    Ok(true)
                }
                else if let Some(second) = self.chars_next()? {
                    match (ch, second) {
                        ('\r', '\n') | ('\n', '\r') => {
                            self.newline = NewlineMode::Double(ch, second);
                            self.buf.push(Token::Newline);
                        }
                        ('\r', '\r') | ('\n', '\n')  => {
                            self.newline = NewlineMode::Single(ch);
                            self.buf.push(Token::Newline);
                            self.buf.push(Token::Newline);
                        }
                        ('\r', _) | ('\n', _) => {
                            self.newline = NewlineMode::Single(ch);
                            self.buf.push(Token::Newline);
                            self.buf.push(Token::Symbol(Symbol::Char(second)));
                        }
                        _ => {
                            self.buf.push(Token::Symbol(Symbol::Char(ch)));
                            self.buf.push(Token::Symbol(Symbol::Char(second)));
                        }
                    }
                    Ok(true)
                }
                else {
                    if ch == '\r' || ch == '\n' {
                        self.buf.push(Token::Newline);
                    }
                    else {
                        self.buf.push(Token::Symbol(Symbol::Char(ch)))
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
    fn peek(&mut self) -> Result<Option<Token>, ScanError> {
        if self.buf.len() == self.cur {
            if !self.source_token()? {
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
    fn read(&mut self) -> Result<Option<Token>, ScanError> {
        self.peek().map(|res| match res {
            Some(ch) => {
                self.cur += 1;
                self.cur_pos.update(ch);
                Some(ch)
            }
            None => None
        })
    }

    /// Skip the first token.
    ///
    /// Only ever call this if you called `peek` before and it did return
    /// `Some(ch)`.
    ///
    /// This is an optimization.
    fn skip(&mut self, ch: Token) {
        self.cur += 1;
        self.cur_pos.update(ch)
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
                         -> Result<Option<Token>, ScanError>
                      where F: FnOnce(Token) -> bool {
        match self.peek()? {
            Some(ch) if f(ch) => self.read(),
            _ => Ok(None)
        }
    }

    fn cond_read_symbol<F>(&mut self, f: F)
                           -> Result<Option<Symbol>, ScanError>
                        where F: FnOnce(Symbol) -> bool {
        match self.peek()? {
            Some(Token::Symbol(ch)) if f(ch) => {
                self.skip(Token::Symbol(ch));
                Ok(Some(ch))
            }
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
                match self.cond_read(Token::is_paren_space)? {
                    None => break,
                    Some(Token::Symbol(Symbol::Char('('))) => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::NestedParentheses,
                                           pos)
                    }
                    Some(Token::Symbol(Symbol::Char(')'))) => {
                        self.paren = false;
                    }
                    Some(Token::Symbol(Symbol::Char(';'))) => {
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
                match self.cond_read(Token::is_non_paren_space)? {
                    None => break,
                    Some(Token::Symbol(Symbol::Char('('))) => {
                        self.paren = true;
                    }
                    Some(Token::Symbol(Symbol::Char(')'))) => {
                        let pos = self.cur_pos.prev();
                        return self.err_at(SyntaxError::Unexpected(
                                                             ')'.into()), pos)
                    }
                    _ => { }
                }
            }
            res = true;
        }
        Ok(res)
    }
}


//------------ Scan ----------------------------------------------------------

/// A type that can by scanned from a master file.
pub trait Scan: Sized {
    /// Scans a value from a master file.
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError>;
}

impl Scan for u32 {
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

impl Scan for u16 {
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


impl Scan for u8 {
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

/// The master file representation of a single character.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Symbol {
    /// An unescaped Unicode character.
    Char(char),

    /// An escape character by simply being backslashed.
    SimpleEscape(char),

    /// An escaped character using the decimal escape sequence.
    DecimalEscape(u8),
}

impl Symbol {
    /// Reads a symbol from a character source.
    ///
    /// Returns the next symbol in the source, `Ok(None)` if the source has
    /// been exhausted, or an error if there wasn’t a valid symbol.
    pub fn from_chars<C>(chars: C) -> Result<Option<Self>, SymbolError>
                      where C: IntoIterator<Item=char> {
        let mut chars = chars.into_iter();
        let ch = match chars.next() {
            Some(ch) => ch,
            None => return Ok(None),
        };
        if ch != '\\' {
            return Ok(Some(Symbol::Char(ch)))
        }
        match chars.next() {
            Some(ch) if ch.is_digit(10) => {
                let ch = ch.to_digit(10).unwrap() * 100;
                let ch2 = match chars.next() {
                    Some(ch) => match ch.to_digit(10) {
                        Some(ch) => ch * 10,
                        None => return Err(SymbolError::BadEscape)
                    }
                    None => return Err(SymbolError::ShortInput)
                };
                let ch3 = match chars.next() {
                    Some(ch)  => match ch.to_digit(10) {
                        Some(ch) => ch,
                        None => return Err(SymbolError::BadEscape)
                    }
                    None => return Err(SymbolError::ShortInput)
                };
                let res = ch + ch2 + ch3;
                if res > 255 {
                    return Err(SymbolError::BadEscape)
                }
                Ok(Some(Symbol::DecimalEscape(res as u8)))
            }
            Some(ch) => Ok(Some(Symbol::SimpleEscape(ch))),
            None => Err(SymbolError::ShortInput)
        }
    }

    /// Provides the best symbol for a byte.
    ///
    /// The function will use simple escape sequences for spaces, quotes,
    /// backslashs, and semicolons. It will leave all other printable ASCII
    /// characters unescaped and decimal escape all remaining byte value.
    pub fn from_byte(ch: u8) -> Self {
        if ch == b' ' || ch == b'"' || ch == b'\\' || ch == b';' {
            Symbol::SimpleEscape(ch as char)
        }
        else if ch < 0x20 || ch > 0x7E {
            Symbol::DecimalEscape(ch)
        }
        else {
            Symbol::Char(ch as char)
        }
    }

    /// Converts the symbol into a byte if it represents one.
    ///
    /// Both domain names and character strings operate on bytes instead of
    /// (Unicode) characters. These bytes can be represented by printable
    /// ASCII characters (that is, U+0020 to U+007E), both plain or through
    /// a simple escape, or by a decimal escape.
    ///
    /// This method returns such a byte or an error otherwise. Note that it
    /// will succeed for an ASCII space character U+0020 which may be used
    /// as a word separator in some cases.
    pub fn into_byte(self) -> Result<u8, BadSymbol> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => {
                if ch.is_ascii() && ch >= '\u{20}' && ch <= '\u{7E}' {
                    Ok(ch as u8)
                }
                else {
                    Err(BadSymbol(self))
                }
            }
            Symbol::DecimalEscape(ch) => Ok(ch),
        }
    }

    /// Converts the symbol into a `char`.
    pub fn into_char(self) -> Result<char, BadSymbol> {
        match self {
            Symbol::Char(ch) | Symbol::SimpleEscape(ch) => Ok(ch),
            Symbol::DecimalEscape(_) => Err(BadSymbol(self))
        }
    }

    /// Converts the symbol representing a digit into its integer value.
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
    pub fn push_to_buf(self, buf: &mut BytesMut) -> Result<(), BadSymbol> {
        self.into_byte().map(|ch| {
            if buf.remaining_mut() == 0 {
                buf.reserve(1);
            }
            buf.put_u8(ch)
        })
    }

    /// Returns whether the symbol can occur as part of a word.
    pub fn is_word_char(self) -> bool {
        match self {
            Symbol::Char(ch) => {
                ch != ' ' && ch != '\t' && ch != '(' && ch != ')' &&
                ch != ';' && ch != '"'
            }
            _ => true
        }
    }
}


//--- From

impl From<char> for Symbol {
    fn from(ch: char) -> Symbol {
        Symbol::Char(ch)
    }
}


//--- Display

impl fmt::Display for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Symbol::Char(ch) => write!(f, "{}", ch),
            Symbol::SimpleEscape(ch) => write!(f, "\\{}", ch),
            Symbol::DecimalEscape(ch) => write!(f, "\\{:03}", ch),
        }
    }
}


//------------ Token ---------------------------------------------------------

/// A single symbol parsed from a master file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Token {
    /// A regular symbol.
    Symbol(Symbol),

    /// A new line.
    ///
    /// This needs special treatment because of the varying encoding of
    /// newlines on different systems.
    Newline,
}

impl Token {
    /// Checks for space-worthy character outside a parenthesized group.
    ///
    /// These are horizontal white space plus opening and closing parentheses
    /// which need special treatment.
    fn is_non_paren_space(self) -> bool {
        match self {
            Token::Symbol(Symbol::Char(ch)) => {
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
            Token::Symbol(Symbol::Char(ch)) => {
                ch == ' ' || ch == '\t' || ch == '(' || ch == ')' ||
                ch == ';'
            }
            Token::Newline => true,
            _ => false
        }
    }

    /// Returns whether the token is a newline.
    fn is_newline(self) -> bool {
        match self {
            Token::Newline => true,
            _ => false,
        }
    }

    /// Returns whether the token starts a newline sequence.
    ///
    /// This happens if the token is either a newline itself or an unescaped
    /// semicolon which starts a comment until line’s end.
    fn is_newline_ahead(self) -> bool {
        match self {
            Token::Symbol(Symbol::Char(';')) => true,
            Token::Newline => true,
            _ => false,
        }
    }
}


//------------ NewlineMode ---------------------------------------------------

/// The newline mode used by a file.
///
/// Files can use different characters or character combinations to signal a
/// line break. Since line breaks are significant in master files, we need to
/// use the right mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NewlineMode {
    /// Each occurence of the content is a newline.
    Single(char),

    /// Each combination of the two chars is a newline.
    Double(char, char),

    /// We don’t know yet.
    Unknown,
}


//------------ SymbolError ---------------------------------------------------

/// An error happened when reading a symbol.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum SymbolError {
    #[fail(display="illegal escape sequence")]
    BadEscape,

    #[fail(display="unexpected end of input")]
    ShortInput
}


//------------ BadSymbol -----------------------------------------------------

/// A symbol of unexepected value was encountered. 
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="bad symbol '{}'", _0)]
pub struct BadSymbol(pub Symbol);


//------------ SyntaxError ---------------------------------------------------

/// A syntax error happened while scanning master data.
#[derive(Debug, Fail)]
pub enum SyntaxError {
    #[fail(display="expected '{}'", _0)]
    Expected(String),

    #[fail(display="expected a new line")]
    ExpectedNewline,

    #[fail(display="expected white space")]
    ExpectedSpace,

    #[fail(display="invalid escape sequence")]
    IllegalEscape,

    #[fail(display="invalid integer value")]
    IllegalInteger, // TODO Add kind

    #[fail(display="invalid address: {}", _0)]
    IllegalAddr(AddrParseError),

    #[fail(display="illegal domain name: {}", _0)]
    IllegalName(name::FromStrError),

    #[fail(display="character string too long")]
    LongCharStr,

    #[fail(display="hex string with an odd number of characters")]
    UnevenHexString,

    #[fail(display="more data given than in the length byte")]
    LongGenericData,

    #[fail(display="nested parentheses")]
    NestedParentheses,

    #[fail(display="omitted TTL but no default TTL given")]
    NoDefaultTtl,

    #[fail(display="omitted class but no previous class given")]
    NoLastClass,

    #[fail(display="omitted owner but no previous owner given")]
    NoLastOwner,

    #[fail(display="owner @ without preceding $ORIGIN")]
    NoOrigin,

    #[fail(display="relative domain name")]
    RelativeName,

    #[fail(display="unexpected '{}'", _0)]
    Unexpected(Symbol),

    #[fail(display="unexpected newline")]
    UnexpectedNewline,

    #[fail(display="unexpected end of file")]
    UnexpectedEof,

    #[fail(display="unknown mnemonic")]
    UnknownMnemonic,

    /// Used when converting some other content fails.
    #[fail(display="{}", _0)]
    Content(Box<Fail>),
}

impl SyntaxError {
    pub fn content<E: Fail>(err: E) -> Self {
        SyntaxError::Content(Box::new(err))
    }
}


impl From<BadSymbol> for SyntaxError {
    fn from(err: BadSymbol) -> SyntaxError {
        SyntaxError::Unexpected(err.0)
    }
}

impl From<AddrParseError> for SyntaxError {
    fn from(err: AddrParseError) -> SyntaxError {
        SyntaxError::IllegalAddr(err)
    }
}

impl From<name::FromStrError> for SyntaxError {
    fn from(err: name::FromStrError) -> SyntaxError {
        SyntaxError::IllegalName(err)
    }
}

impl From<name::PushNameError> for SyntaxError {
    fn from(err: name::PushNameError) -> SyntaxError {
        SyntaxError::from(name::FromStrError::from(err))
    }
}


//------------ ScanError -----------------------------------------------------

/// An error happened while scanning master data.
#[derive(Debug)]
pub enum ScanError {
    Source(io::Error, Pos),
    Syntax(SyntaxError, Pos),
}

impl From<(io::Error, Pos)> for ScanError {
    fn from(err: (io::Error, Pos)) -> ScanError {
        ScanError::Source(err.0, err.1)
    }
}

impl From<(SyntaxError, Pos)> for ScanError {
    fn from(err: (SyntaxError, Pos)) -> ScanError {
        ScanError::Syntax(err.0, err.1)
    }
}


//------------ Pos -----------------------------------------------------------

/// The human-friendly position in a reader.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Pos {
    line: usize,
    col: usize
}

impl Pos {
    pub fn new() -> Pos {
        Pos { line: 1, col: 1 }
    }

    pub fn line(&self) -> usize { self.line }
    pub fn col(&self) -> usize { self.col }

    pub fn update(&mut self, ch: Token) {
        match ch {
            Token::Symbol(Symbol::Char(_)) => self.col += 1,
            Token::Symbol(Symbol::SimpleEscape(_)) => self.col += 2,
            Token::Symbol(Symbol::DecimalEscape(_)) => self.col += 4,
            Token::Newline => { self.line += 1; self.col = 1 }
        }
    }

    pub fn prev(&self) -> Pos {
        Pos { line: self.line,
              col: if self.col <= 1 { 1 } else { self.col - 1 }
        }
    }
}

impl From<(usize, usize)> for Pos {
    fn from(src: (usize, usize)) -> Pos {
        Pos { line: src.0, col: src.1 }
    }
}

impl PartialEq<(usize, usize)> for Pos {
    fn eq(&self, other: &(usize, usize)) -> bool {
        self.line == other.0 && self.col == other.1
    }
}


//============ Test ==========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn scan_word() {
        let mut scanner = Scanner::new("one two three\nfour");
        assert_eq!(scanner.scan_string_word(Ok).unwrap(), "one");
    }
}
