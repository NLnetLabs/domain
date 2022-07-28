//! Reading zone files.

use core::convert::TryFrom;
use core::str::FromStr;
use std::{error, fmt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use bytes::buf::UninitSlice;
use crate::base::charstr::CharStr;
use crate::base::iana::{Class, Rtype};
use crate::base::name::{Chain, Dname, RelativeDname, ToDname};
use crate::base::record::Record;
use crate::base::scan::{
    BadSymbol, ConvertSymbols, EntrySymbol, Scan, Scanner, ScannerError,
    Symbol, SymbolOctetsError,
};
use crate::base::str::String;
use crate::rdata::ZoneRecordData;


//------------ Type Aliases --------------------------------------------------

pub type ScannedDname = Chain<RelativeDname<Bytes>, Dname<Bytes>>;
pub type ScannedRecordData = ZoneRecordData<Bytes, ScannedDname>;
pub type ScannedRecord = Record<ScannedDname, ScannedRecordData>;
pub type ScannedString = String<Bytes>;


//------------ Zonefile ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Zonefile {
    /// This is where we keep the data of the next entry.
    buf: SourceBuf,

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
        Self::with_buf(SourceBuf::default())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_buf(SourceBuf::with_capacity(capacity))
    }

    pub fn with_buf(buf: SourceBuf) -> Self {
        Zonefile {
            buf,
            origin: None,
            last_owner: None,
            last_ttl: None,
            last_class: None,
        }
    }

    pub fn buf_mut(&mut self) -> &mut SourceBuf {
        &mut self.buf
    }

    pub fn set_origin(&mut self, origin: Dname<Bytes>) {
        self.origin = Some(origin)
    }

    pub fn set_class(&mut self, class: Class) {
        self.last_class = Some(class)
    }

    pub fn set_ttl(&mut self, ttl: u32) {
        self.last_ttl = Some(ttl)
    }

    pub fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        loop {
            match EntryScanner::new(self)?.scan()? {
                ScannedEntry::Entry(entry) => return Ok(Some(entry)),
                ScannedEntry::Origin(origin) => self.origin = Some(origin),
                ScannedEntry::Ttl(ttl) => self.last_ttl = Some(ttl),
                ScannedEntry::Empty => { }
                ScannedEntry::Eof => return Ok(None),
            }
        }
    }
}


//------------ EntryScanner --------------------------------------------------

#[derive(Debug)]
struct EntryScanner<'a> {
    /// The zonefile we are working on.
    zonefile: &'a mut Zonefile,

    /// The next item to be processed.
    next_item: ItemRef,
}

impl<'a> EntryScanner<'a> {
    fn new(zonefile: &'a mut Zonefile) -> Result<Self, Error> {
        Ok(EntryScanner {
            next_item: zonefile.buf.next_item().map_err(|err| {
                zonefile.buf.error(err)
            })?,
            zonefile,
        })
    }

    fn scan(&mut self) -> Result<ScannedEntry, Error> {
        self._scan().map_err(|err| self.zonefile.buf.error(err))
    }

    fn _scan(&mut self) -> Result<ScannedEntry, EntryError> {
        match self.next_item {
            ItemRef::Token(_) => {
                if self.has_space() {
                    // Indented entry: a record with the last owner as the
                    // owner.
                    self.scan_record(
                        match self.zonefile.last_owner.as_ref() {
                            Some(owner) => owner.clone(),
                            None => {
                                return Err( EntryError::missing_last_owner())
                            }
                        }
                    )
                }
                else {
                    // We know this is a token so unwrap is fine. But we need
                    // to call the method to progress to the next token
                    // internally.
                    let token = self.next_token().unwrap();
                    
                    if token.peek() == Some(Symbol::Char('$')) {
                        self.scan_control(token)
                    }
                    else {
                        self.scan_record(
                            token.into_dname(
                                self.zonefile.origin.as_ref()
                            )?
                        )
                    }
                }
            }
            ItemRef::LineFeed => Ok(ScannedEntry::Empty),
            ItemRef::Eof => Ok(ScannedEntry::Eof),
        }
    }

    fn scan_record(
        &mut self, owner: ScannedDname,
    ) -> Result<ScannedEntry, EntryError> {
        let (class, ttl, rtype) = self.scan_ctr()?;

        self.zonefile.last_owner = Some(owner.clone());

        let class = match class {
            Some(class) => {
                self.zonefile.last_class = Some(class);
                class
            }
            None => {
                match self.zonefile.last_class {
                    Some(class) => class,
                    None => return Err(EntryError::missing_last_class())
                }
            }
        };

        let ttl = match ttl {
            Some(ttl) => {
                self.zonefile.last_ttl = Some(ttl);
                ttl
            }
            None => {
                match self.zonefile.last_ttl {
                    Some(ttl) => ttl,
                    None => return Err(EntryError::missing_last_ttl())
                }
            }
        };

        let data = ZoneRecordData::scan(rtype, self)?;

        // There shouldn’t be any tokens left now.
        if matches!(self.next_item, ItemRef::Token(_)) {
            return Err(EntryError::trailing_tokens())
        }
        
        Ok(ScannedEntry::Entry(Entry::Record(
            Record::new(owner, class, ttl, data)
        )))
    }

    fn scan_ctr(
        &mut self
    ) -> Result<(Option<Class>, Option<u32>, Rtype), EntryError> {
        // Possible options are:
        //
        //   [<TTL>] [<class>] <type>
        //   [<class>] [<TTL>] <type>
        let first = self.scan_string()?;
        if let Ok(ttl) = u32::from_str(&first) {
            // We have a TTL. Now there may be a class.
            let second = self.scan_string()?;
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
            let second = self.scan_string()?;
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

    fn scan_control(
        &mut self, ctrl: Token,
    ) -> Result<ScannedEntry, EntryError> {
        let ctrl = ctrl.into_string()?;
        if ctrl.eq_ignore_ascii_case("$ORIGIN") {
            Ok(ScannedEntry::Origin(
                self.next_token()?.into_origin_dname()?
            ))
        }
        else if ctrl.eq_ignore_ascii_case("$INCLUDE") {
            Ok(ScannedEntry::Entry(Entry::Include {
                path: self.scan_string()?,
                origin:  if self.continues() {
                Some(self.next_token()?.into_origin_dname()?)
                }
                else {
                    None
                },
            }))
        }
        else if ctrl.eq_ignore_ascii_case("$TTL") {
            Ok(ScannedEntry::Ttl(u32::scan(self)?))
        }
        else {
            Err(EntryError::unknown_control())
        }
    }
}

impl<'a> EntryScanner<'a> {
    fn next_token(&mut self) -> Result<Token, EntryError> {
        let res = self.zonefile.buf.item_to_token(self.next_item)?;
        self.next_item = self.zonefile.buf.next_item()?;
        Ok(res)
    }

    fn tail(&mut self) -> Result<Tail, EntryError> {
        let first = match self.next_item {
            ItemRef::Token(token) => token,
            ItemRef::LineFeed | ItemRef::Eof => {
                return Err(EntryError::end_of_entry());
            }
        };
        let mut last = None;
        while matches!(self.next_item, ItemRef::Token(_)) {
            self.next_item = self.zonefile.buf.next_item()?;
            if let ItemRef::Token(token) = self.next_item {
                last = Some(token)
            }
        }
        let last = last.unwrap_or(first);
        self.zonefile.buf.tokens_to_tail(first, last)
    }
}

impl<'a> Scanner for EntryScanner<'a> {
    type Symbols = Symbols;
    type EntrySymbols = EntrySymbols;
    type Octets = Bytes;
    type OctetsBuilder = BytesMut;
    type Dname = ScannedDname;
    type Error = EntryError;

    fn has_space(&self) -> bool {
        match self.next_item {
            ItemRef::Token(tok) => tok.has_space,
            ItemRef::LineFeed | ItemRef::Eof => false,
        }
    }

    fn continues(&self) -> bool {
        match self.next_item {
            ItemRef::Token(_) => true,
            ItemRef::LineFeed | ItemRef::Eof => false,
        }
    }

    fn scan_symbols(&mut self) -> Result<Self::Symbols, Self::Error> {
        self.next_token().and_then(Token::into_symbols)
    }

    fn scan_entry_symbols(
        &mut self
    ) -> Result<Self::EntrySymbols, Self::Error> {
        self.tail().and_then(Tail::into_symbols)
    }

    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        self.next_token().and_then(|tok| tok.convert(convert))
    }

    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self, convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        let res = self.tail().and_then(|tail| tail.convert(convert));
        res
    }

    fn scan_octets(&mut self) -> Result<Self::Octets, Self::Error> {
        self.next_token().and_then(Token::into_octets)
    }

    fn scan_dname(&mut self) -> Result<Self::Dname, Self::Error> {
        self.next_token().and_then(|tok| {
            tok.into_dname(self.zonefile.origin.as_ref())
        })
    }

    fn scan_charstr(&mut self) -> Result<CharStr<Self::Octets>, Self::Error> {
        self.next_token().and_then(Token::into_charstr)
    }

    fn scan_string(&mut self) -> Result<String<Self::Octets>, Self::Error> {
        self.next_token().and_then(Token::into_string)
    }

    fn scan_charstr_entry(&mut self) -> Result<Self::Octets, Self::Error> {
        self.tail().and_then(Tail::into_charstrs)
    }

    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error> {
        Ok(BytesMut::new())
    }
}


//------------ Entry ---------------------------------------------------------

#[derive(Clone, Debug)]
pub enum Entry {
    Record(ScannedRecord),
    Include {
        path: ScannedString,
        origin: Option<Dname<Bytes>>,
    }
}


//------------ ScannedEntry --------------------------------------------------

#[allow(dead_code)] // XXX
#[derive(Clone, Debug)]
enum ScannedEntry {
    Entry(Entry),
    Origin(Dname<Bytes>),
    Ttl(u32),
    Empty,
    Eof,
}


//------------ SourceBuf -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SourceBuf {
    /// The underlying real buffer.
    buf: BytesMut,

    /// Where in `buf` are we currently?
    start: usize,

    /// The line number of the current line.
    line_num: usize,

    /// The position of the first character of the current line.
    ///
    /// This may be negative if we cut off bits of the current line.
    line_start: isize,

    /// How many unclosed opening parentheses did we see at `start`?
    parens: usize,
}

impl Default for SourceBuf {
    fn default() -> Self {
        Self::with_empty_buf(BytesMut::default())
    }
}

impl<'a> From<&'a str> for SourceBuf {
    fn from(src: &'a str) -> Self {
        Self::from(src.as_bytes())
    }
}

impl<'a> From<&'a [u8]> for SourceBuf {
    fn from(src: &'a [u8]) -> Self {
        let mut buf = BytesMut::with_capacity(src.len() + 1);
        buf.put_u8(0);
        buf.extend_from_slice(src);
        SourceBuf {
            buf,
            start: 1,
            line_num: 1,
            line_start: 1,
            parens: 0
        }
    }
}

impl SourceBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_empty_buf(BytesMut::with_capacity(capacity + 1))
    }

    fn with_empty_buf(mut buf: BytesMut) -> Self {
        buf.put_u8(0);
        SourceBuf {
            buf,
            start: 1,
            line_num: 1,
            line_start: 1,
            parens: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

impl SourceBuf {
    fn error(&self, err: EntryError) -> Error {
        Error {
            err,
            line: self.line_num,
            col: ((self.start as isize) + 1 - self.line_start) as usize,
        }
    }

    fn next_item(&mut self) -> Result<ItemRef, EntryError> {
        let ws = self.skip_leading_ws()?;

        match self.buf.get(self.start) {
            Some(b'\n') => self.lf_token(),
            Some(b'"') => self.next_quoted_token(ws),
            Some(_) => self.next_unquoted_token(ws),
            None => Ok(ItemRef::Eof),
        }
    }

    fn item_to_token(&mut self, item: ItemRef) -> Result<Token, EntryError> {
        match item {
            ItemRef::Token(token) => {
                let buf = self.buf.split_to(token.end);
                self.start -= token.end;
                Ok(Token::new(buf, token.start, token.escapes))
            }
            ItemRef::LineFeed | ItemRef::Eof => {
                Err(EntryError::end_of_entry())
            }
        }
    }

    fn tokens_to_tail(
        &mut self, first: TokenRef, last: TokenRef
    ) -> Result<Tail, EntryError> {
        let buf = SourceBuf {
            buf: self.buf.split_to(last.end),
            start: first.end,
            line_num: self.line_num,
            line_start: self.line_start,
            parens: first.parens,
        };
        self.start -= last.end;
        self.line_start -= last.end as isize;
        Ok(Tail::new(buf, first))
    }
}

impl SourceBuf {
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
                self.line_num += 1;
                self.line_start = self.start as isize;
            }
            // Otherwise we found the end of the white space.
            else {
                break;
            }
        }
        Ok(ws)
    }

    fn lf_token(&mut self) -> Result<ItemRef, EntryError> {
        self.start += 1;
        self.line_num += 1;
        self.line_start = self.start as isize;
        Ok(ItemRef::LineFeed)
    }

    fn next_quoted_token(
        &mut self, has_space: bool,
    ) -> Result<ItemRef, EntryError> {
        let start = self.start + 1;
        let parens = self.parens;
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
                return Ok(ItemRef::Token(TokenRef {
                    start, end, has_space, escapes, parens,
                }))
            }

            if !matches!(sym, Symbol::Char(_)) {
                escapes = true
            }
            end = sym_end;
        }
    }

    fn next_unquoted_token(
        &mut self, has_space: bool,
    ) -> Result<ItemRef, EntryError> {
        let start = self.start;
        let parens = self.parens;
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
        Ok(ItemRef::Token(TokenRef {
            start, end, has_space, escapes, parens
        }))
    }
}

unsafe impl BufMut for SourceBuf {
    fn remaining_mut(&self) -> usize {
        self.buf.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.advance_mut(cnt)
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.buf.chunk_mut()
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
    fn new(buf: BytesMut, start: usize, escapes: bool) -> Self {
        Token {
            buf,
            read: start,
            write: 0,
            escapes,
        }
    }

    fn peek(&self) -> Option<Symbol> {
        Symbol::from_slice_index(&self.buf, self.read).unwrap().map(|s| s.0)
    }

    fn into_symbols(self) -> Result<Symbols, EntryError> {
        Ok(Symbols(self))
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
        mut self, origin: Option<&Dname<Bytes>>
    ) -> Result<ScannedDname, EntryError> {
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

    fn into_origin_dname(self) -> Result<Dname<Bytes>, EntryError> {
        // XXX This should probably have a better impl.
        self.into_dname(None).map(|name| name.to_dname().unwrap())
    }

    fn into_charstr(mut self) -> Result<CharStr<Bytes>, EntryError> {
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
}

impl Token {
    /// Removes any leading space before `self.read`.
    ///
    /// This wipes out anything before `self.read` so should probably only
    /// be called while `self.write` is still 0.
    fn trim(&mut self) {
        self.buf.advance(self.read);
        self.write = 0;
        self.read = 0;
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
}


//------------ Tail ----------------------------------------------------------

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
    fn new(buf: SourceBuf, first: TokenRef) -> Self {
        Tail {
            read: first.start,
            buf,
            token: Some(first),
            write: Ok(0),
        }
    }

    fn into_symbols(self) -> Result<EntrySymbols, EntryError> {
        Ok(EntrySymbols(self))
    }

    fn into_charstrs(mut self) -> Result<Bytes, EntryError> {
        // Because char-strings are never longer than their representation
        // format, we can definitely do this in place. Specifically, we move
        // the content around in such a way that by the end we have the result
        // in the space of buf before buf.start.

        // Reminder: char-string are one length byte followed by that many
        // content bytes. We use the byte just before self.read as the length
        // byte of the first char-string. This way, if there is only one and
        // it isn’t escaped, we don’t need to move anything at all.

        let start = self.read - 1;
        let mut write = start;
        while self.process_charstr(&mut write)? {
            match self.buf.next_item()? {
                ItemRef::Token(token) => self.token = Some(token),
                ItemRef::LineFeed | ItemRef::Eof => self.token = None,
            }
        }
        self.buf.buf.truncate(write);
        self.buf.buf.advance(start);
        Ok(self.buf.buf.freeze())
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
}

impl Tail {
    fn next_symbol(&mut self) -> Option<EntrySymbol> {
        let token = match self.token {
            Some(token) => token,
            None => return None
        };

        if self.read < token.end {
            // There must be a symbol or else this is all very kaputt.
            let (sym, pos) = Symbol::from_slice_index(
                &self.buf.buf, self.read
            ).unwrap().unwrap();
            self.read = pos;
            return Some(sym.into())
        }

        match self.buf.next_item().unwrap() {
            ItemRef::Token(token) => {
                self.read = token.start;
                self.token = Some(token);
            }
            ItemRef::LineFeed | ItemRef::Eof => {
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

    fn process_charstr(
        &mut self, write: &mut usize
    ) -> Result<bool, EntryError> {
        let token = match self.token {
            Some(token) => token,
            None => return Ok(false),
        };

        if !token.escapes {
            if token.start == *write + 1 {
                // The content is already where it should be. We don’t need
                // to do anything other than check and fill out the length.
                match u8::try_from(token.end - token.start) {
                    Ok(len) => self.buf.buf[*write] = len,
                    Err(_) => return Err(EntryError::bad_charstr()),
                }
                *write = token.end;
            }
            else {
                // The content is not escaped so we can just
                // move it .. move it.
                let len = u8::try_from(token.end - token.start).map_err(|_| {
                    EntryError::bad_charstr()
                })?;
                self.buf.buf.copy_within(
                    token.start..token.end,
                    *write + 1,
                );
                self.buf.buf[*write] = len;
                *write += (len as usize) + 1;
            }
        }
        else {
            let start = *write;
            *write += 1;
            let mut read = token.start;
            let mut len = 0u8;
            loop {
                let (sym, sym_len) = match Symbol::from_slice_index(
                    &self.buf.buf, read
                )? {
                    Some(some) => some,
                    None => break,
                };
                let sym = sym.into_octet()?;

                self.buf.buf[*write] = sym;
                *write += 1;
                read += sym_len;
                len = len.checked_add(1).ok_or_else(|| {
                    EntryError::bad_charstr()
                })?;
            }
            self.buf.buf[start] = len;
        }
        Ok(true)
    }
}


//------------ ItemRef -------------------------------------------------------

/// Information about the next item in a buffer.
#[derive(Clone, Copy, Debug)]
enum ItemRef {
    Token(TokenRef),
    LineFeed,
    Eof,
}


//------------ TokenRef ------------------------------------------------------

/// Reference to a token within a buffer.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // XXX
struct TokenRef {
    /// The index of the start of the token’s content.
    start: usize,

    /// The index of the first octet that is not part of the content.
    end: usize,

    /// Is the token preceded by white space?
    has_space: bool,

    /// Does the token contain escape sequences?
    escapes: bool,

    /// Number of unclosed opening parentheses at the start.
    parens: usize,
}


//------------ Symbols ------------------------------------------------------

struct Symbols(Token);

impl Iterator for Symbols {
    type Item = Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_symbol()
    }
}


//------------ EntrySymbols --------------------------------------------------

struct EntrySymbols(Tail);

impl Iterator for EntrySymbols {
    type Item = EntrySymbol;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_symbol()
    }
}


//------------ EntryError ----------------------------------------------------

#[derive(Debug)]
struct EntryError(std::string::String);

impl EntryError {
    fn string(s: impl Into<std::string::String>) -> Self {
        EntryError(s.into())
    }

    fn bad_symbol(err: SymbolOctetsError) -> Self {
        EntryError::string(format!("{}", err))
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

    fn end_of_entry() -> Self {
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


//------------ Error ---------------------------------------------------------

#[derive(Debug)]
pub struct Error {
    err: EntryError,
    line: usize,
    col: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.err)
    }
}

impl error::Error for Error { }


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn example_com() {
        let mut zone = Zonefile::with_buf(
            SourceBuf::from(
                include_str!("../../test-data/zonefiles/example.com.txt")
            )
        );
        while zone.next_entry().unwrap().is_some() {
        }
    }

    #[test]
    fn giant_zone() {
        use std::time::SystemTime;

        let start = SystemTime::now();
        let mut buf = SourceBuf::new().writer();
        std::io::copy(
            &mut std::fs::File::open(
                "/home/m/dns-test-data/com.zone"
            ).unwrap(),
            &mut buf
        ).unwrap();

        eprintln!("Data loaded ({:.03}s).",
            start.elapsed().unwrap().as_secs_f32()
        );
        let mut zone = Zonefile::with_buf(buf.into_inner());
        let mut i = 0;
        while let Some(_) = zone.next_entry().unwrap() {
            i += 1;
            if i % 1_000_000 == 0 {
                eprintln!("Processed {} records ({:.03}s)",
                    i, start.elapsed().unwrap().as_secs_f32()
                );
            }
        }
        eprintln!("Complete with {} records ({:.03}s)",
            i, start.elapsed().unwrap().as_secs_f32()
        );
    }
}

