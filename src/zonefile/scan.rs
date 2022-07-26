//! Reading zone files.

use std::{error, fmt, io, mem};
use std::convert::TryFrom;
use std::str::FromStr;
use bytes::{Buf, Bytes, BytesMut};
use crate::base::charstr::CharStr;
use crate::base::iana::{Class, Rtype};
use crate::base::name::{Chain, Dname, RelativeDname, ToDname};
use crate::base::record::Record;
use crate::base::scan::{
    BadSymbol, ConvertSymbols, EntrySymbol, Scan, Scanner, ScannerError,
    Symbol, SymbolOctetsError,
};
use crate::base::str::String;
use crate::rdata::{A, ZoneRecordData};


//------------ Type Aliases --------------------------------------------------

pub type ScannedDname = Chain<RelativeDname<Bytes>, Dname<Bytes>>;
pub type ScannedRecord = Record<
    ScannedDname, ZoneRecordData<Bytes, ScannedDname>
>;


//------------ Zonefile ------------------------------------------------------

pub struct Zonefile {
    /// This is where we keep the data of the next entry.
    buf: SourceBuf,

    /// Have we been marked as complete?
    complete: bool,

    /// The current origin.
    origin: Option<Dname<Bytes>>,

    /// The last owner.
    last_owner: Option<ScannedDname>,

    /// The last TTL.
    last_ttl: Option<u32>,

    /// The last class.
    last_class: Option<Class>,
}

impl Zonefile {
    pub fn new() -> Self {
        Zonefile::with_buf(Default::default())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Zonefile::with_buf(BytesMut::with_capacity(capacity))
    }

    pub fn with_buf(buf: BytesMut) -> Self {
        Zonefile {
            buf: SourceBuf::with_buf(buf),
            complete: false,
            origin: None,
            last_owner: None,
            last_ttl: None,
            last_class: None,
        }
    }

    /// Extends the buffer with additional data.
    ///
    /// The caller gains access to the buffer itself via the provided
    /// closure. They should be aware of their power and not mess up the
    /// buffer.
    ///
    /// The closure should return `Ok(true)` if there is more data to be
    /// added later and `Ok(false)` if there is no more data.
    pub fn extend<Op>(&mut self, op: Op) -> Result<(), io::Error>
    where Op: FnOnce(&mut BytesMut) -> Result<bool, io::Error> {
        self.complete = !op(&mut self.buf.buf)?;
        Ok(())
    }

    /// Returns the next entry.
    ///
    /// If there isn’t a complete entry available, returns `None`. In this
    /// case, you can add more data via [`Zonefile::extend`].
    pub fn next_entry(&mut self) -> Result<Option<Entry>, EntryError> {
        let start = self.buf.start;
        while let Some(token) = self.buf.next_item()? {
            if matches!(token, ItemRef::LineFeed) {
                let buf = self.buf.get_entry(start);
                return Ok(Some(Entry::new(buf, self.origin.clone())))
            }
        }

        if self.complete {
            let buf = self.buf.get_entry(start);
            Ok(Some(Entry::new(buf, self.origin.clone())))
        }
        else {
            Ok(None)
        }
    }

    pub fn scan_record(
        &mut self
    ) -> Result<Option<ScannedRecord>, EntryError> {
        loop {
            match self.scan_entry()? {
                Some(ScannedEntry::Record(record)) => return Ok(Some(record)),
                Some(ScannedEntry::Control(ctrl, entry)) => {
                    self.process_control(ctrl, entry)?;
                }
                None => {
                    eprintln!("empty");
                    if self.buf.start == self.buf.buf.len() {
                        return Ok(None)
                    }
                }
            }
        }
    }

    fn scan_entry(
        &mut self
    ) -> Result<Option<ScannedEntry>, EntryError> {
        let mut entry = match self.next_entry()? {
            Some(entry) => entry,
            None => return Ok(None)
        };

        let owner = if entry.has_space() {
            // Indented entry, we need to use the last owner.
            match self.last_owner.as_ref() {
                Some(last_owner) => last_owner.clone(),
                None => return Err(EntryError::missing_last_owner())
            }
        }
        else {
            let token = match entry.next_token() {
                Some(token) => token,
                None => return Ok(None),
            };

            if token.peek() == Some(Symbol::Char('$')) {
                return Ok(Some(ScannedEntry::Control(
                    token.into_string()?, entry
                )))
            }

            let owner = token.into_dname(entry.origin())?;
            self.last_owner = Some(owner.clone());
            owner
        };

        let (class, ttl, rtype) = entry.scan_ctr()?;

        let class = match class {
            Some(class) => {
                self.last_class = Some(class);
                class
            }
            None => {
                match self.last_class {
                    Some(class) => class,
                    None => return Err(EntryError::missing_last_class())
                }
            }
        };

        let ttl = match ttl {
            Some(ttl) => {
                self.last_ttl = Some(ttl);
                ttl
            }
            None => {
                match self.last_ttl {
                    Some(ttl) => ttl,
                    None => return Err(EntryError::missing_last_ttl())
                }
            }
        };

        let data = match ZoneRecordData::scan(rtype, &mut entry) {
            Ok(data) => data,
            Err(_) => {
                // XXX
                A::from_octets(0,0,0,0).into()
            }
        };
        Ok(Some(ScannedEntry::Record(Record::new(owner, class, ttl, data))))
    }

    fn process_control(
        &mut self, ctrl: String<Bytes>, mut entry: Entry
    ) -> Result<(), EntryError> {
        if ctrl.eq_ignore_ascii_case("$ORIGIN") {
            self.origin = Some(entry.scan_dname()?.ok_or_else(||
                EntryError::unexpected_end_of_entry()
            )?.to_dname().unwrap());
            Ok(())
        }
        else if ctrl.eq_ignore_ascii_case("$INCLUDE") {
            // XXX
            Ok(())
        }
        else if ctrl.eq_ignore_ascii_case("$TTL") {
            self.last_ttl = Some(u32::scan(&mut entry)?);
            Ok(())
        }
        else {
            Err(EntryError::unknown_control())
        }
    }
}


//------------ Entry ---------------------------------------------------------

#[derive(Clone)]
pub struct Entry {
    /// The buffer to take tokens from.
    buf: SourceBuf,

    /// The location of the next token.
    ///
    /// We need to know so we can answer `Scanner::has_space`.
    ///
    /// If this is `None`, we’ve reached the end of the entry.
    next_token: Option<TokenRef>,

    /// The origin for relative domain names.
    origin: Option<Dname<Bytes>>,
}

impl Entry {
    fn new(mut buf: SourceBuf, origin: Option<Dname<Bytes>>) -> Self {
        let next_token = buf.next_token();
        Entry { buf, next_token, origin }
    }

    /// Returns the next token in the entry.
    fn next_token(&mut self) -> Option<Token> {
        if let Some(token) = self.next_token.take() {
            let res = token.apply(&mut self.buf);
            self.next_token = self.buf.next_token();
            Some(res)
        }
        else {
            None
        }
   }

    /// Returns the rest of the entry.
    ///
    /// After calling this method, there will be nothing left in `self`.
    fn next_tail(&mut self) -> Tail {
        Tail::new(
            mem::replace(&mut self.buf, SourceBuf::default()),
            self.next_token.take()
        )
    }

    fn origin(&self) -> Option<&Dname<Bytes>> {
        self.origin.as_ref()
    }

    fn scan_ctr(
        &mut self
    ) -> Result<(Option<Class>, Option<u32>, Rtype), EntryError> {
        // Possible options are:
        //
        //   [<TTL>] [<class>] <type>
        //   [<class>] [<TTL>] <type>
        let first = self.scan_mandatory_string()?;
        if let Ok(ttl) = u32::from_str(&first) {
            // We have a TTL. Now there may be a class.
            let second = self.scan_mandatory_string()?;
            if let Ok(class) = Class::from_str(&second) {
                // We also have class. Now for the rtype.
                Ok((Some(class), Some(ttl), Rtype::scan(self)?))
            }
            else if let Ok(rtype) = Rtype::from_str(&second) {
                Ok((None, Some(ttl), rtype))
            }
            else {
                Err(EntryError::expected_rtype())
            }
        }
        else if let Ok(class) = Class::from_str(&first) {
            // We have a class. A ttl may be next.
            let second = self.scan_mandatory_string()?;
            if let Ok(ttl) = u32::from_str(&second) {
                // We also have a TTL. Then rtype must be next.
                Ok((Some(class), Some(ttl), Rtype::scan(self)?))
            }
            else if let Ok(rtype) = Rtype::from_str(&second) {
                Ok((Some(class), None, rtype))
            }
            else {
                Err(EntryError::expected_rtype())
            }
        }
        else if let Ok(rtype) = Rtype::from_str(&first) {
            Ok((None, None, rtype))
        }
        else {
            Err(EntryError::expected_rtype())
        }
    }

    fn scan_mandatory_string(&mut self) -> Result<String<Bytes>, EntryError> {
        match self.scan_string()? {
            Some(res) => Ok(res),
            None => Err(EntryError::unexpected_end_of_entry())
        }
    }
}

impl Scanner for Entry {
    type Symbols = Symbols;
    type EntrySymbols = EntrySymbols;
    type Octets = Bytes;
    type OctetsBuilder = BytesMut;
    type Dname = ScannedDname;
    type Error = EntryError;

    fn has_space(&self) -> bool {
        self.next_token.map(|tok| tok.has_space).unwrap_or(false)
    }

    fn scan_symbols(&mut self) -> Result<Option<Symbols>, EntryError> {
        Ok(self.next_token().map(Symbols))
    }

    fn scan_entry_symbols(
        &mut self
    ) -> Result<EntrySymbols, EntryError> {
        Ok(EntrySymbols(self.next_tail()))
    }

    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Option<Self::Octets>, Self::Error> {
        self.next_token().map(|tok| tok.convert(convert)).transpose()
    }

    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        self.next_tail().convert(convert)
    }

    /// Scans a token into an octets sequence.
    fn scan_octets(&mut self) -> Result<Option<Self::Octets>, Self::Error> {
        self.next_token().map(Token::into_octets).transpose()
    }

    /// Scans a token into a domain name.
    fn scan_dname(&mut self) -> Result<Option<Self::Dname>, Self::Error> {
        self.next_token().map(|tok| {
            tok.into_dname(self.origin())
        }).transpose()
    }

    /// Scans a token into a character string.
    ///
    /// Note that character strings have a length limit.  If you want a
    /// sequence of indefinite length, use [`scan_octets`][Self::scan_octets]
    /// instead.
    fn scan_charstr(
        &mut self
    ) -> Result<Option<CharStr<Self::Octets>>, Self::Error> {
        self.next_token().map(Token::into_charstr).transpose()
    }

    /// Scans a token as a UTF-8 string.
    fn scan_string(
        &mut self
    ) -> Result<Option<String<Self::Octets>>, Self::Error> {
        self.next_token().map(Token::into_string).transpose()
    }

    /// Scans a sequence of character strings until the end of the entry.
    ///
    /// The returned octets will contain the sequence of character string in
    /// wire format.
    ///
    /// Returns `Ok(None)` if there are no more tokens.
    fn scan_charstr_entry(
        &mut self
    ) -> Result<Option<Self::Octets>, Self::Error> {
        Err(EntryError::custom("unimplemented"))
        //unimplemented!()
    }

    /// Returns an empty octets builder.
    ///
    /// This builder can be used to create octets sequences in cases where
    /// the other methods can’t be used.
    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error> {
        Ok(BytesMut::new())
    }
}


//------------ SourceBuf -----------------------------------------------------

#[derive(Clone, Debug, Default)]
struct SourceBuf {
    buf: BytesMut,
    start: usize,
    parens: usize,
}

impl SourceBuf {
    fn with_buf(buf: BytesMut) -> Self {
        SourceBuf {
            buf,
            start: 0,
            parens: 0,
        }
    }

    /// Returns the next item.
    fn next_item(&mut self) -> Result<Option<ItemRef>, EntryError> {
        let ws = self.skip_leading_ws()?;

        match self.buf.get(self.start) {
            Some(b'\n') => self.lf_token(),
            Some(b'"') => self.next_quoted_token(ws),
            Some(_) => self.next_unquoted_token(ws),
            None => Ok(None),
        }
    }

    /// Returns the next token.
    ///
    /// This should only every be called on a source buffer that has been
    /// limited to a single entry and was cleaned via calls to
    /// `SourceBuf::next_item` before.
    ///
    /// Returns `None` if it encounters end-of-entry or end-of-data.
    ///
    /// # Panics
    ///
    /// This method panics if it encounters invalid data in the buffer.
    fn next_token(&mut self) -> Option<TokenRef> {
        self.next_item().unwrap().and_then(|item| match item {
            ItemRef::Token(token) => Some(token),
            ItemRef::LineFeed => None,
        })
    }

    fn skip_leading_ws(&mut self) -> Result<bool, EntryError> {
        let mut ws = false;

        while let Some(&ch) = self.buf.get(self.start) {
            // Skip and mark actual white space.
            if matches!(ch, b' ' | b'\t' | b'\r') {
                ws = true;
                self.start += 1;
            }
            // CR: ignore for compatibility with Windows-style line endings.
            else if ch == b'\r' {
                self.start += 1;
            }
            // Opening parenthesis: increase group level.
            else if ch == b'(' {
                self.parens += 1;
                self.start += 1;
            }
            // Closing parenthesis: decrease group level or error out.
            else if ch == b')' {
                if self.parens > 0 {
                    self.parens -= 1;
                    self.start += 1;
                }
                else {
                    return Err(EntryError::unbalanced_parens())
                }
            }
            // Semicolon: comment -- skip to line end.
            else if ch == b';' {
                self.start += 1;
                while let Some(true) = self.buf.get(self.start).map(|ch| {
                    *ch != b'\n'
                }) {
                    self.start += 1;
                }
            }
            // Line end: skip only if we are inside a paren group.
            else if ch == b'\n' && self.parens > 0 {
                self.start += 1;
            }
            // Otherwise we found the end of the white space.
            else {
                break;
            }
        }
        Ok(ws)
    }

    fn lf_token(&mut self) -> Result<Option<ItemRef>, EntryError> {
        self.start += 1;
        Ok(Some(ItemRef::LineFeed))
    }

    fn next_quoted_token(
        &mut self, has_space: bool,
    ) -> Result<Option<ItemRef>, EntryError> {
        let start = self.start + 1;
        let mut end = start;
        let mut escapes = false;

        loop {
            let (sym, sym_end) = match Symbol::from_slice_index(
                &self.buf, end
            ) {
                Ok(Some((sym, sym_end))) => (sym, sym_end),
                Ok(None) => return Err(EntryError::short_buf()),
                Err(err) => return Err(EntryError::bad_symbol(err)),
            };

            if sym == Symbol::Char('"') {
                self.start = sym_end;
                return Ok(Some(ItemRef::Token(TokenRef {
                    start, end, has_space, escapes,
                })))
            }

            if !matches!(sym, Symbol::Char(_)) {
                escapes = true
            }
            end = sym_end;
        }
    }

    fn next_unquoted_token(
        &mut self, has_space: bool,
    ) -> Result<Option<ItemRef>, EntryError> {
        let start = self.start;
        let mut end = start;
        let mut escapes = false;

        loop {
            let (sym, sym_end) = match Symbol::from_slice_index(
                &self.buf, end
            ) {
                Ok(Some((sym, sym_end))) => (sym, sym_end),
                Ok(None) => break,
                Err(err) => return Err(EntryError::bad_symbol(err)),
            };
            if !sym.is_word_char() {
                break;
            }

            if !matches!(sym, Symbol::Char(_)) {
                escapes = true
            }
            end = sym_end;
        }

        self.start = end;
        Ok(Some(ItemRef::Token(TokenRef { start, end, has_space, escapes })))
    }

    /// Returns an entry from the data before the current position.
    ///
    /// This will only produce a legit entry if the last token looked at was
    /// a line feed token or if the end of the buffer was reached.
    ///
    /// Return the source buffer to be used with the entry, not the entry
    /// itself.
    pub fn get_entry(&mut self, start: usize) -> SourceBuf {
        // The last character was a line feed. It needs to go into the next
        // entry as the prefix space for converting domain names.
        let res = SourceBuf {
            buf: self.buf.split_to(self.start - 1),
            start,
            parens: 0,
        };
        self.start = 1;
        res
    }
}


//------------ ItemRef -------------------------------------------------------

/// Information about the next item in a buffer.
#[derive(Clone, Copy, Debug)]
enum ItemRef {
    Token(TokenRef),
    LineFeed
}


//------------ TokenRef ------------------------------------------------------

/// Reference to a token within a buffer.
#[derive(Clone, Copy, Debug)]
struct TokenRef {
    /// The index of the start of the token’s content.
    start: usize,

    /// The index of the first octet that is not part of the content.
    end: usize,

    /// Is the token preceded by white space?
    has_space: bool,

    /// Does the token contain escape sequences?
    escapes: bool,
}

impl TokenRef {
    fn apply(self, source: &mut SourceBuf) -> Token {
        let mut buf = source.buf.split_to(source.start);
        source.start = 0;
        buf.truncate(self.end);
        Token::new(buf, self.start, self.escapes)
    }
}


//------------ Token ---------------------------------------------------------

#[derive(Clone, Debug)]
struct Token {
    /// The buffer we work on.
    ///
    /// The end of the buffer is also the end of the token.
    buf: BytesMut,

    /// The index of the current read position.
    ///
    /// This is the index in `buf` of the first octet of the next symbol.
    read: usize,

    /// The index of the current write position.
    ///
    /// This is the index where the next octet should go. We can only write
    /// to this index if it is smaller than `read` or if `read == end`, in
    /// which case we can freely write to the remainder of the buffer.
    write: usize,

    /// Are there any escaped symbols in the buffer?
    escapes: bool,
}

impl Token {
    fn new(
        buf: BytesMut, start: usize, escapes: bool
    ) -> Self {
        Token {
            buf,
            read: start,
            write: 0,
            escapes,
        }
    }

    /// Removes any leading space before `self.read`.
    fn trim(&mut self) {
        self.buf.advance(self.read);
        self.write = 0;
        self.read = 0;
    }

    fn peek(&self) -> Option<Symbol> {
        Symbol::from_slice_index(&self.buf, self.read).unwrap().map(|s| s.0)
    }

    fn next_symbol(&mut self) -> Option<Symbol> {
        let (sym, pos) = match Symbol::from_slice_index(
            &self.buf, self.read
        ).unwrap() {
            Some(some) => some,
            None => return None
        };
        self.read = pos;
        Some(sym)
    }

    fn write(&mut self, ch: u8) {
        self.buf[self.write] = ch;
        self.write += 1;
    }

    fn append_data(&mut self, data: &[u8], alt: &mut Option<BytesMut>) {
        if let Some(ref mut buf) = alt.as_mut() {
            buf.extend_from_slice(data);
            return
        }

        let len = data.len();
        if self.read - self.write < len {
            *alt = Some(BytesMut::new());
            self.append_data(data, alt)
        }
        else {
            let new_write = self.write + len;
            self.buf[self.write..new_write].copy_from_slice(data);
            self.write = new_write;
        }
    }

    /// Converts the token into a charstr.
    fn into_charstr(
        mut self
    ) -> Result<CharStr<Bytes>, EntryError> {
        // Since the representation format of a charstr is never shorter than
        // the wire format, we only need the actual content.
        self.trim();

        // If there are no escape sequences in the token, the content is the
        // content and we can just return.
        if !self.escapes {
            return CharStr::from_octets(self.buf.freeze()).map_err(|_| {
                EntryError::bad_charstr()
            })
        }

        // We can skip over all symbols that are unescaped ASCII
        // characters at the beginning of the charstr since they don’t
        // need to be moved. Remember the length limit of the charstr.
        let mut len = 0;
        let mut symbol = loop {
            match self.next_symbol() {
                Some(Symbol::Char(ch)) => {
                    let ch = u8::try_from(ch).map_err(|_| {
                        EntryError::bad_charstr()
                    })?;
                    if ch > 0x7F {
                        return Err(EntryError::bad_charstr())
                    }
                    len += 1;
                    self.write += 1;
                }
                symbol => break symbol,
            }

            if len > 255 {
                return Err(EntryError::bad_charstr())
            }
        };

        // If we encountered any other symbol, we need to copy things.
        while let Some(val) = symbol {
            let val = val.into_octet().map_err(|_| {
                EntryError::bad_charstr()
            })?;
            self.buf[self.write] = val;
            len += 1;
            self.write += 1;
            if len > 255 {
                return Err(EntryError::bad_charstr())
            }

            symbol = self.next_symbol();
        }

        self.buf.truncate(self.write);
        Ok(unsafe {
            CharStr::from_octets_unchecked(self.buf.freeze())
        })
    }

    fn convert<C: ConvertSymbols<Symbol, EntryError>>(
        mut self, mut convert: C,
    ) -> Result<Bytes, EntryError> {
        let mut buf = None;
        while let Some(sym) = self.next_symbol() {
            if let Some(data) = convert.process_symbol(sym)? {
                self.append_data(data, &mut buf);
            }
        }
        if let Some(data) = convert.process_tail()? {
            self.append_data(data, &mut buf);
        }
        match buf {
            Some(buf) => Ok(buf.freeze()),
            None => {
                self.buf.truncate(self.write);
                Ok(self.buf.freeze())
            }
        }
    }

    fn into_octets(mut self) -> Result<Bytes, EntryError> {
        if self.escapes {
            while let Some(sym) = self.next_symbol() {
                self.write(sym.into_octet()?);
            }
            self.buf.truncate(self.write);
            Ok(self.buf.freeze())
        }
        else {
            self.trim();
            Ok(self.buf.freeze())
        }
    }

    fn into_dname(
        mut self, origin: Option<&Dname<Bytes>>,
    ) -> Result<Chain<RelativeDname<Bytes>, Dname<Bytes>>, EntryError> {
        // If we flip the last byte of the prefix into a dot, we can treat
        // this as a sequence of labels prefixed by a dot.
        match self.read {
            0 => panic!("missing token prefix space"),
            1 => {},
            pos => {
                let _ = self.buf.advance(pos - 1);
            }
        }
        self.buf[0] = b'.';

        // If there are no escape sequences, we don’t need to convert symbols
        // so a special version is warranted.
        if self.escapes {
            self.escaped_into_dname(origin)
        }
        else {
            self.unescaped_into_dname(origin)
        }
    }

    fn unescaped_into_dname(
        mut self, origin: Option<&Dname<Bytes>>,
    ) -> Result<Chain<RelativeDname<Bytes>, Dname<Bytes>>, EntryError> {
        let mut start = 0;
        while start < self.buf.len() {
            if start + 1 == self.buf.len() {
                self.buf.truncate(start);
                return self.into_absolute_dname()
            }

            // Find the next dot, it must be in the range [1..65] for the
            // name to be valid.
            let mut dot = None;
            for i in (start + 1)..(start + 65) {
                match self.buf.get(i) {
                    Some(ch) if *ch == b'.' => {
                        dot = Some(i);
                        break;
                    }
                    // The end of token can be treated as if there was a
                    // dot. This gets dealt with by the outer loop.
                    None => {
                        dot = Some(i);
                        break;
                    }
                    Some(_) => { }
                }
            }
            let dot = match dot {
                Some(dot) => dot,
                None => {
                    return Err(EntryError::bad_dname())
                }
            };

            // Replace the start position with the length.
            self.buf[start] = (dot - start - 1) as u8;

            start = dot;
        }

        self.into_relative_dname(origin)
    }

    fn escaped_into_dname(
        mut self, origin: Option<&Dname<Bytes>>,
    ) -> Result<Chain<RelativeDname<Bytes>, Dname<Bytes>>, EntryError> {
        // This works similarly to the unescaped version. The only difference
        // is that we convert symbols while searching for the next dot.
        let mut start = 0;
        self.read = 1;
        while start < self.buf.len() {
            if start + 1 == self.buf.len() {
                self.buf.truncate(start);
                return self.into_absolute_dname()
            }

            let mut dot = None;
            for i in (start + 1)..(start + 65) {
                match self.next_symbol().map(Symbol::into_octet) {
                    Some(Ok(ch)) => {
                        self.write(ch);
                        if ch == b'.' {
                            dot = Some(i);
                            break;
                        }
                    }
                    Some(Err(_)) => {
                        return Err(EntryError::bad_dname())
                    }
                    None => {
                        dot = Some(i);
                        self.buf.truncate(self.write);
                        break;
                    }
                }
            }

            let dot = match dot {
                Some(dot) => dot,
                None => {
                    return Err(EntryError::bad_dname())
                }
            };

            self.buf[start] = (dot - start - 1) as u8;

            start = self.write;
        }

        self.into_relative_dname(origin)
    }

    fn into_absolute_dname(
        self
    ) -> Result<Chain<RelativeDname<Bytes>, Dname<Bytes>>, EntryError> {
        if self.buf.len() > 254 {
            return Err(EntryError::bad_dname())
        }
        return Ok(
            unsafe {
                RelativeDname::from_octets_unchecked(
                    self.buf.freeze()
                )
            }.chain(Dname::root_bytes()).unwrap()
        )
    }

    fn into_relative_dname(
        self, origin: Option<&Dname<Bytes>>,
    ) -> Result<Chain<RelativeDname<Bytes>, Dname<Bytes>>, EntryError> {
        if self.buf.len() > 254 {
            return Err(EntryError::bad_dname())
        }
        let origin = origin.ok_or_else(|| EntryError::missing_origin())?;
        unsafe {
            RelativeDname::from_octets_unchecked(self.buf.freeze())
        }.chain(origin.clone()).map_err(|_| EntryError::bad_dname())
    }


    fn into_string(mut self) -> Result<String<Bytes>, EntryError> {
        let buf = if self.escapes {
            while let Some(sym) = self.next_symbol() {
                let ch = sym.into_char()?;
                if let Ok(ch) = u8::try_from(ch) {
                    self.write(ch);
                }
                else {
                    let buf = &mut self.buf[self.write..(self.write + 4)];
                    let len = ch.encode_utf8(buf).len();
                    self.write += len;
                    debug_assert!(self.write <= self.read);
                }
            }
            self.buf.truncate(self.write);
            self.buf.freeze()
        }
        else {
            self.buf.split_off(self.read).freeze()
        };

        unsafe {
            Ok(String::from_utf8_unchecked(buf))
        }
    }
}


//------------ Symbols ------------------------------------------------------

pub struct Symbols(Token);

impl Iterator for Symbols {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_symbol()
    }
}


//------------ Tail ----------------------------------------------------------

/// All the remaining tokens of an entry.
///
/// This is very similar to  [`Token`] but the buffer contains multiple
/// tokens.
#[derive(Clone, Debug)]
struct Tail {
    /// The buffer we work on.
    ///
    /// The end of the buffer is also the end of the entry.
    buf: SourceBuf,

    /// Information about the current token.
    ///
    /// If this is `None`, we’ve reached the end of the entry.
    token: Option<TokenRef>,

    /// The index of the current read position.
    ///
    /// This is the index in `buf` of the first octet of the next symbol. It
    /// also is somewhere within the indexes indicated by `self.token`.
    read: usize,

    /// Where to write data to.
    ///
    /// If this is `Ok(n)`, then n is an index into `buf`. In this case, we
    /// can write more data into the slice `self.buf[n..self.read]`. if that
    /// isn’t enough space, we need to switch to a newly allocated buffer.
    /// This buffer will be in `Err(buf)` and if that is what is in this
    /// attribute, new data is simply appened to it.
    write: Result<usize, BytesMut>,
}

impl Tail {
    fn new(buf: SourceBuf, token: Option<TokenRef>) -> Self {
        Tail {
            read: token.map(|tok| tok.start).unwrap_or(buf.start),
            buf,
            token,
            write: Ok(0)
        }
    }

    fn convert<C: ConvertSymbols<EntrySymbol, EntryError>>(
        mut self, mut convert: C,
    ) -> Result<Bytes, EntryError> {
        while let Some(sym) = self.next_symbol() {
            if let Some(data) = convert.process_symbol(sym)? {
                self.append_data(data);
            }
        }
        if let Some(data) = convert.process_tail()? {
            self.append_data(data);
        }
        match self.write {
            Ok(write) => {
                self.buf.buf.truncate(write);
                Ok(self.buf.buf.freeze())
            }
            Err(buf) => Ok(buf.freeze()),
        }
    }

    fn next_symbol(&mut self) -> Option<EntrySymbol> {
        let token = self.token?;

        if self.read < token.end {
            // There must be a symbol or else this is all very kaputt.
            let (sym, pos) = Symbol::from_slice_index(
                &self.buf.buf, self.read
            ).unwrap().unwrap();
            self.read = pos;
            return Some(sym.into())
        }

        match self.buf.next_item().unwrap() {
            Some(ItemRef::Token(token)) => {
                self.read = token.start;
                self.token = Some(token);
            }
            Some(ItemRef::LineFeed) | None => {
                self.token = None;
            }
        }
        Some(EntrySymbol::EndOfToken)
    }

    fn append_data(&mut self, data: &[u8]) {
        match self.write {
            Ok(write) => {
                let len = data.len();
                if self.read - write < len {
                    self.write = Err(BytesMut::new());
                    self.append_data(data)
                }
                else {
                    let new_write = write + len;
                    self.buf.buf[write..new_write].copy_from_slice(data);
                    self.write = Ok(new_write);
                }
            }
            Err(ref mut buf) => {
                buf.extend_from_slice(data)
            }
        }
    }
}


//------------ EntrySymbols --------------------------------------------------

pub struct EntrySymbols(Tail);

impl Iterator for EntrySymbols {
    type Item = EntrySymbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_symbol()
    }
}


//------------ ScannedEntry -------------------------------------------------

enum ScannedEntry {
    Record(ScannedRecord),
    Control(String<Bytes>, Entry),
}


//------------ EntryError ---------------------------------------------------

#[derive(Debug)]
pub struct EntryError(std::string::String);

impl EntryError {
    fn string(s: impl Into<std::string::String>) -> Self {
        EntryError(s.into())
    }

    fn bad_symbol(_: SymbolOctetsError) -> Self {
        EntryError::string("bad symbol")
    }

    fn bad_charstr() -> Self {
        EntryError::string("bad charstr")
    }

    fn bad_dname() -> Self {
        EntryError::string("bad dname")
    }

    fn unbalanced_parens() -> Self {
        EntryError::string("unbalanced parens")
    }

    fn missing_last_owner() -> Self {
        EntryError::string("missing last owner")
    }

    fn missing_last_class() -> Self {
        EntryError::string("missing last class")
    }

    fn missing_last_ttl() -> Self {
        EntryError::string("missing last ttl")
    }

    fn missing_origin() -> Self {
        EntryError::string("missing origin")
    }

    fn expected_rtype() -> Self {
        EntryError::string("expected rtype")
    }

    fn unknown_control() -> Self {
        EntryError::string("unknown control")
    }
}

impl ScannerError for EntryError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        EntryError::string(format!("{}", msg))
    }

    fn unexpected_end_of_entry() -> Self {
        Self::string("unexpected end of entry")
    }

    fn short_buf() -> Self {
        Self::string("short buffer")
    }

    fn trailing_tokens() -> Self {
        Self::string("trailing tokens")
    }
}

impl From<SymbolOctetsError> for EntryError {
    fn from(_: SymbolOctetsError) -> Self {
        EntryError::string("symbol octets error")
    }
}

impl From<BadSymbol> for EntryError {
    fn from(_: BadSymbol) -> Self {
        EntryError::string("bad symbol")
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

impl error::Error for EntryError { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn example_com() {
        let mut zone = Zonefile::with_buf(
            include_str!("../../test-data/zonefiles/example.com.txt").into()
        );
        while let Some(record) = zone.scan_record().unwrap() {
            println!("{}", record)
        }
    }
}

