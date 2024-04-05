//! A zonefile scanner keeping data in place.
//!
//! The zonefile scanner provided by this module reads the entire zonefile
//! into memory and tries as much as possible to modify re-use this memory
//! when scanning data. It uses the `Bytes` family of types for safely
//! storing, manipulating, and returning the data and thus requires the
//! `bytes` feature to be enabled.
//!
//! This may or may not be a good strategy. It was primarily implemented to
//! see that the [`Scan`] trait is powerful enough to build such an
//! implementation.
#![cfg(feature = "bytes")]
#![cfg_attr(docsrs, doc(cfg(feature = "bytes")))]

use crate::base::charstr::CharStr;
use crate::base::iana::{Class, Rtype};
use crate::base::name::{Chain, Name, RelativeName, ToName};
use crate::base::record::Record;
use crate::base::scan::{
    BadSymbol, ConvertSymbols, EntrySymbol, Scan, Scanner, ScannerError,
    Symbol, SymbolOctetsError,
};
use crate::base::Ttl;
use crate::rdata::ZoneRecordData;
use bytes::buf::UninitSlice;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::str::FromStr;
use core::{fmt, str};
use octseq::str::Str;

//------------ Type Aliases --------------------------------------------------

/// The type used for scanned domain names.
pub type ScannedDname = Chain<RelativeName<Bytes>, Name<Bytes>>;

/// The type used for scanned record data.
pub type ScannedRecordData = ZoneRecordData<Bytes, ScannedDname>;

/// The type used for scanned records.
pub type ScannedRecord = Record<ScannedDname, ScannedRecordData>;

/// The type used for scanned strings.
pub type ScannedString = Str<Bytes>;

//------------ Zonefile ------------------------------------------------------

/// A zonefile to be scanned.
///
/// A value of this types holds data to be scanned in memory and allows
/// fetching entries by acting as an iterator.
///
/// The type implements the `bytes::BufMut` trait for appending data directly
/// into the memory buffer. The function [`load`][Self::load] can be used to
/// create a value directly from a reader.
///
/// Once data has been added, you can simply iterate over the value to
/// get entries. The [`next_entry`][Self::next_entry] method provides an
/// alternative with a more question mark friendly signature.
#[derive(Clone, Debug)]
pub struct Zonefile {
    /// This is where we keep the data of the next entry.
    buf: SourceBuf,

    /// The current origin.
    origin: Option<Name<Bytes>>,

    /// The last owner.
    last_owner: Option<ScannedDname>,

    /// The last TTL.
    last_ttl: Option<Ttl>,

    /// The last class.
    last_class: Option<Class>,
}

impl Zonefile {
    /// Creates a new, empty value.
    pub fn new() -> Self {
        Self::with_buf(SourceBuf::with_empty_buf(BytesMut::new()))
    }

    /// Creates a new, empty value with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_buf(SourceBuf::with_empty_buf(BytesMut::with_capacity(
            capacity + 1,
        )))
    }

    /// Creates a new value using the given buffer.
    fn with_buf(buf: SourceBuf) -> Self {
        Zonefile {
            buf,
            origin: None,
            last_owner: None,
            last_ttl: None,
            last_class: None,
        }
    }

    /// Creates a value by loading the data from the given reader.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn load(
        read: &mut impl std::io::Read,
    ) -> Result<Self, std::io::Error> {
        let mut buf = Self::new().writer();
        std::io::copy(read, &mut buf)?;
        Ok(buf.into_inner())
    }
}

impl Default for Zonefile {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> From<&'a str> for Zonefile {
    fn from(src: &'a str) -> Self {
        Self::from(src.as_bytes())
    }
}

impl<'a> From<&'a [u8]> for Zonefile {
    fn from(src: &'a [u8]) -> Self {
        let mut res = Self::with_capacity(src.len() + 1);
        res.extend_from_slice(src);
        res
    }
}

impl Zonefile {
    /// Reserves at least `len` additional bytes in the buffer.
    pub fn reserve(&mut self, len: usize) {
        self.buf.buf.reserve(len);
    }

    /// Appends the given slice to the end of the buffer.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.buf.buf.extend_from_slice(slice)
    }
}

unsafe impl BufMut for Zonefile {
    fn remaining_mut(&self) -> usize {
        self.buf.buf.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        self.buf.buf.advance_mut(cnt);
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.buf.buf.chunk_mut()
    }
}

impl Zonefile {
    /// Sets the origin of the zonefile.
    ///
    /// The origin is append to relative domain names encountered in the
    /// data. Ininitally, there is no origin set. If relative names are
    /// encountered, an error happenes.
    pub fn set_origin(&mut self, origin: Name<Bytes>) {
        self.origin = Some(origin)
    }

    /// Returns the next entry in the zonefile.
    ///
    /// Returns `Ok(None)` if the end of the file has been reached. Returns
    /// an error if scanning the next entry failed.
    ///
    /// This method is identical to the `next` method of the iterator
    /// implementation but has the return type transposed for easier use
    /// with the question mark operator.
    pub fn next_entry(&mut self) -> Result<Option<Entry>, Error> {
        loop {
            match EntryScanner::new(self)?.scan_entry()? {
                ScannedEntry::Entry(entry) => return Ok(Some(entry)),
                ScannedEntry::Origin(origin) => self.origin = Some(origin),
                ScannedEntry::Ttl(ttl) => self.last_ttl = Some(ttl),
                ScannedEntry::Empty => {}
                ScannedEntry::Eof => return Ok(None),
            }
        }
    }

    /// Returns the origin name of the zonefile.
    fn get_origin(&self) -> Result<Name<Bytes>, EntryError> {
        self.origin
            .as_ref()
            .cloned()
            .ok_or_else(EntryError::missing_origin)
    }
}

impl Iterator for Zonefile {
    type Item = Result<Entry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_entry().transpose()
    }
}

//------------ Entry ---------------------------------------------------------

/// An entry of a zonefile.
#[derive(Clone, Debug)]
pub enum Entry {
    /// A DNS record.
    Record(ScannedRecord),

    /// An include directive.
    ///
    /// When this entry is encountered, the referenced file should be scanned
    /// next. If `origin` is given, this file should be scanned with it as the
    /// initial origin name,
    Include {
        /// The path to the file to be included.
        path: ScannedString,

        /// The initial origin name of the included file, if provided.
        origin: Option<Name<Bytes>>,
    },
}

//------------ ScannedEntry --------------------------------------------------

/// A raw scanned entry of a zonefile.
///
/// This includes all the entry types that we can handle internally and don’t
/// have to bubble up to the user.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
enum ScannedEntry {
    /// An entry that should be handed to the user.
    Entry(Entry),

    /// An `$ORIGIN` directive changing the origin name.
    Origin(Name<Bytes>),

    /// A `$TTL` directive changing the default TTL if it isn’t given.
    Ttl(Ttl),

    /// An empty entry.
    Empty,

    /// The end of file was reached.
    Eof,
}

//------------ EntryScanner --------------------------------------------------

/// The entry scanner for a zonefile.
///
/// A value of this type is created for each entry. It implements the
/// [`Scanner`] interface.
#[derive(Debug)]
struct EntryScanner<'a> {
    /// The zonefile we are working on.
    zonefile: &'a mut Zonefile,
}

impl<'a> EntryScanner<'a> {
    /// Creates a new entry scanner using the given zonefile.
    fn new(zonefile: &'a mut Zonefile) -> Result<Self, Error> {
        Ok(EntryScanner { zonefile })
    }

    /// Scans a single entry from the zone file.
    fn scan_entry(&mut self) -> Result<ScannedEntry, Error> {
        self._scan_entry()
            .map_err(|err| self.zonefile.buf.error(err))
    }

    /// Scans a single entry from the zone file.
    ///
    /// This is identical to `scan_entry` but with a more convenient error
    /// type.
    fn _scan_entry(&mut self) -> Result<ScannedEntry, EntryError> {
        self.zonefile.buf.next_item()?;
        match self.zonefile.buf.cat {
            ItemCat::None => Ok(ScannedEntry::Eof),
            ItemCat::LineFeed => Ok(ScannedEntry::Empty),
            ItemCat::Unquoted | ItemCat::Quoted => {
                if self.zonefile.buf.has_space {
                    // Indented entry: a record with the last owner as the
                    // owner.
                    self.scan_owner_record(
                        match self.zonefile.last_owner.as_ref() {
                            Some(owner) => owner.clone(),
                            None => {
                                return Err(EntryError::missing_last_owner())
                            }
                        },
                        false,
                    )
                } else if self.zonefile.buf.peek_symbol()
                    == Some(Symbol::Char('$'))
                {
                    self.scan_control()
                } else if self.zonefile.buf.skip_at_token()? {
                    self.scan_at_record()
                } else {
                    self.scan_record()
                }
            }
        }
    }

    /// Scans a regular record.
    fn scan_record(&mut self) -> Result<ScannedEntry, EntryError> {
        let owner = ScannedDname::scan(self)?;
        self.scan_owner_record(owner, true)
    }

    /// Scans a regular record with an owner name of `@`.
    fn scan_at_record(&mut self) -> Result<ScannedEntry, EntryError> {
        let owner = RelativeName::empty_bytes()
            .chain(match self.zonefile.origin.as_ref().cloned() {
                Some(origin) => origin,
                None => return Err(EntryError::missing_origin()),
            })
            .unwrap(); // Chaining an empty name will always work.
        self.scan_owner_record(owner, true)
    }

    /// Scans a regular record with an explicit owner name.
    fn scan_owner_record(
        &mut self,
        owner: ScannedDname,
        new_owner: bool,
    ) -> Result<ScannedEntry, EntryError> {
        let (class, ttl, rtype) = self.scan_ctr()?;

        if new_owner {
            self.zonefile.last_owner = Some(owner.clone());
        }

        let class = match class {
            Some(class) => {
                self.zonefile.last_class = Some(class);
                class
            }
            None => match self.zonefile.last_class {
                Some(class) => class,
                None => return Err(EntryError::missing_last_class()),
            },
        };

        let ttl = match ttl {
            Some(ttl) => {
                self.zonefile.last_ttl = Some(ttl);
                ttl
            }
            None => match self.zonefile.last_ttl {
                Some(ttl) => ttl,
                None => return Err(EntryError::missing_last_ttl()),
            },
        };

        let data = ZoneRecordData::scan(rtype, self)?;

        self.zonefile.buf.require_line_feed()?;

        Ok(ScannedEntry::Entry(Entry::Record(Record::new(
            owner, class, ttl, data,
        ))))
    }

    /// Scans the TTL, class, and type portions of a regular record.
    fn scan_ctr(
        &mut self,
    ) -> Result<(Option<Class>, Option<Ttl>, Rtype), EntryError> {
        // Possible options are:
        //
        //   [<TTL>] [<class>] <type>
        //   [<class>] [<TTL>] <type>

        enum Ctr {
            Class(Class),
            Ttl(Ttl),
            Rtype(Rtype),
        }

        let first = self.scan_ascii_str(|s| {
            if let Ok(ttl) = u32::from_str(s) {
                Ok(Ctr::Ttl(Ttl::from_secs(ttl)))
            } else if let Ok(rtype) = Rtype::from_str(s) {
                Ok(Ctr::Rtype(rtype))
            } else if let Ok(class) = Class::from_str(s) {
                Ok(Ctr::Class(class))
            } else {
                Err(EntryError::expected_rtype())
            }
        })?;

        match first {
            Ctr::Ttl(ttl) => {
                // We have a TTL. Now there may be a class or an rtype. We can
                // abuse Result<Rtype, Class> for that.
                let second = self.scan_ascii_str(|s| {
                    if let Ok(rtype) = Rtype::from_str(s) {
                        Ok(Ok(rtype))
                    } else if let Ok(class) = Class::from_str(s) {
                        Ok(Err(class))
                    } else {
                        Err(EntryError::expected_rtype())
                    }
                })?;

                match second {
                    Err(class) => {
                        // Rtype is next.
                        let rtype = self.scan_ascii_str(|s| {
                            Rtype::from_str(s)
                                .map_err(|_| EntryError::expected_rtype())
                        })?;

                        Ok((Some(class), Some(ttl), rtype))
                    }
                    Ok(rtype) => Ok((None, Some(ttl), rtype)),
                }
            }
            Ctr::Class(class) => {
                // We have a class. Now there may be a TTL or an rtype. We can
                // abuse Result<Rtype, TTL> for that.
                let second = self.scan_ascii_str(|s| {
                    if let Ok(ttl) = u32::from_str(s) {
                        Ok(Err(Ttl::from_secs(ttl)))
                    } else if let Ok(rtype) = Rtype::from_str(s) {
                        Ok(Ok(rtype))
                    } else {
                        Err(EntryError::expected_rtype())
                    }
                })?;

                match second {
                    Err(ttl) => {
                        // Rtype is next.
                        let rtype = self.scan_ascii_str(|s| {
                            Rtype::from_str(s)
                                .map_err(|_| EntryError::expected_rtype())
                        })?;

                        Ok((Some(class), Some(ttl), rtype))
                    }
                    Ok(rtype) => Ok((Some(class), None, rtype)),
                }
            }
            Ctr::Rtype(rtype) => Ok((None, None, rtype)),
        }
    }

    /// Scans a control directive.
    fn scan_control(&mut self) -> Result<ScannedEntry, EntryError> {
        let ctrl = self.scan_string()?;
        if ctrl.eq_ignore_ascii_case("$ORIGIN") {
            let origin = self.scan_name()?.to_name();
            self.zonefile.buf.require_line_feed()?;
            Ok(ScannedEntry::Origin(origin))
        } else if ctrl.eq_ignore_ascii_case("$INCLUDE") {
            let path = self.scan_string()?;
            let origin = if !self.zonefile.buf.is_line_feed() {
                Some(self.scan_name()?.to_name())
            } else {
                None
            };
            self.zonefile.buf.require_line_feed()?;
            Ok(ScannedEntry::Entry(Entry::Include { path, origin }))
        } else if ctrl.eq_ignore_ascii_case("$TTL") {
            let ttl = u32::scan(self)?;
            self.zonefile.buf.require_line_feed()?;
            Ok(ScannedEntry::Ttl(Ttl::from_secs(ttl)))
        } else {
            Err(EntryError::unknown_control())
        }
    }
}

impl<'a> Scanner for EntryScanner<'a> {
    type Octets = Bytes;
    type OctetsBuilder = BytesMut;
    type Name = ScannedDname;
    type Error = EntryError;

    fn has_space(&self) -> bool {
        self.zonefile.buf.has_space
    }

    fn continues(&mut self) -> bool {
        !matches!(self.zonefile.buf.cat, ItemCat::None | ItemCat::LineFeed)
    }

    fn scan_symbols<F>(&mut self, mut op: F) -> Result<(), Self::Error>
    where
        F: FnMut(Symbol) -> Result<(), Self::Error>,
    {
        self.zonefile.buf.require_token()?;
        while let Some(sym) = self.zonefile.buf.next_symbol()? {
            op(sym)?;
        }
        self.zonefile.buf.next_item()
    }

    fn scan_entry_symbols<F>(&mut self, mut op: F) -> Result<(), Self::Error>
    where
        F: FnMut(EntrySymbol) -> Result<(), Self::Error>,
    {
        loop {
            self.zonefile.buf.require_token()?;
            while let Some(sym) = self.zonefile.buf.next_symbol()? {
                op(sym.into())?;
            }
            op(EntrySymbol::EndOfToken)?;
            self.zonefile.buf.next_item()?;
            if self.zonefile.buf.is_line_feed() {
                break;
            }
        }
        Ok(())
    }

    fn convert_token<C: ConvertSymbols<Symbol, Self::Error>>(
        &mut self,
        mut convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        let mut write = 0;
        let mut builder = None;
        self.convert_one_token(&mut convert, &mut write, &mut builder)?;
        if let Some(data) = convert.process_tail()? {
            self.append_data(data, &mut write, &mut builder);
        }
        match builder {
            Some(builder) => Ok(builder.freeze()),
            None => Ok(self.zonefile.buf.split_to(write).freeze()),
        }
    }

    fn convert_entry<C: ConvertSymbols<EntrySymbol, Self::Error>>(
        &mut self,
        mut convert: C,
    ) -> Result<Self::Octets, Self::Error> {
        let mut write = 0;
        let mut builder = None;
        loop {
            self.convert_one_token(&mut convert, &mut write, &mut builder)?;
            if self.zonefile.buf.is_line_feed() {
                break;
            }
        }
        if let Some(data) = convert.process_tail()? {
            self.append_data(data, &mut write, &mut builder);
        }
        match builder {
            Some(builder) => Ok(builder.freeze()),
            None => Ok(self.zonefile.buf.split_to(write).freeze()),
        }
    }

    fn scan_octets(&mut self) -> Result<Self::Octets, Self::Error> {
        self.zonefile.buf.require_token()?;

        // The result will never be longer than the encoded form, so we can
        // trim off everything to the left already.
        self.zonefile.buf.trim_to(self.zonefile.buf.start);

        // Skip over symbols that don’t need converting at the beginning.
        while self.zonefile.buf.next_ascii_symbol()?.is_some() {}

        // If we aren’t done yet, we have escaped characters to replace.
        let mut write = self.zonefile.buf.start;
        while let Some(sym) = self.zonefile.buf.next_symbol()? {
            self.zonefile.buf.buf[write] = sym.into_octet()?;
            write += 1;
        }

        // Done. `write` marks the end.
        self.zonefile.buf.next_item()?;
        Ok(self.zonefile.buf.split_to(write).freeze())
    }

    fn scan_ascii_str<F, T>(&mut self, op: F) -> Result<T, Self::Error>
    where
        F: FnOnce(&str) -> Result<T, Self::Error>,
    {
        self.zonefile.buf.require_token()?;

        // The result will never be longer than the encoded form, so we can
        // trim off everything to the left already.
        self.zonefile.buf.trim_to(self.zonefile.buf.start);
        let mut write = 0;

        // Skip over symbols that don’t need converting at the beginning.
        while self.zonefile.buf.next_ascii_symbol()?.is_some() {
            write += 1;
        }

        //  If we not reached the end of the token, we have escaped characters
        //  to replace.
        if !matches!(self.zonefile.buf.cat, ItemCat::None) {
            while let Some(sym) = self.zonefile.buf.next_symbol()? {
                self.zonefile.buf.buf[write] = sym.into_ascii()?;
                write += 1;
            }
        }

        // Done. `write` marks the end. Process via op and return.
        let res = op(unsafe {
            str::from_utf8_unchecked(&self.zonefile.buf.buf[..write])
        })?;
        self.zonefile.buf.next_item()?;
        Ok(res)
    }

    fn scan_name(&mut self) -> Result<Self::Name, Self::Error> {
        // Because the labels in a domain name have their content preceeded
        // by the length octet, an unescaped domain name can be almost as is
        // if we have one extra octet to the left. Luckily, we always do
        // (SourceBuf makes sure of it).
        self.zonefile.buf.require_token()?;

        // Let’s prepare everything. We cut off the bits we don’t need with
        // the result that the buffer’s start will be 1 and we set `write`
        // to be 0, i.e., the start of the buffer. This also means that write
        // will contain the length of the domain name assembled so far, so we
        // can easily check if it has gotten too long.
        assert!(self.zonefile.buf.start > 0, "missing token prefix space");
        self.zonefile.buf.trim_to(self.zonefile.buf.start - 1);
        let mut write = 0;

        // Now convert label by label.
        loop {
            let start = write;
            match self.convert_label(&mut write)? {
                None => {
                    // End of token right after a dot, so this is an absolute
                    // name. Unless we have not done anything yet, then we
                    // have an empty domain name which is just the origin.
                    self.zonefile.buf.next_item()?;
                    if start == 0 {
                        return RelativeName::empty_bytes()
                            .chain(self.zonefile.get_origin()?)
                            .map_err(|_| EntryError::bad_name());
                    } else {
                        return unsafe {
                            RelativeName::from_octets_unchecked(
                                self.zonefile.buf.split_to(write).freeze(),
                            )
                            .chain(Name::root())
                            .map_err(|_| EntryError::bad_name())
                        };
                    }
                }
                Some(true) => {
                    // Last symbol was a dot. If it is was the very first
                    // symbol, this can only be the root name. Check for that
                    // and, if so, return. Otherwise, check length and
                    // continue to the next label.
                    if write == 1 {
                        if self.zonefile.buf.next_symbol()?.is_some() {
                            return Err(EntryError::bad_name());
                        } else {
                            self.zonefile.buf.next_item()?;
                            return Ok(RelativeName::empty()
                                .chain(Name::root())
                                .expect("failed to make root name"));
                        }
                    }
                    if write > 254 {
                        return Err(EntryError::bad_name());
                    }
                }
                Some(false) => {
                    // Reached end of token. This means we have a relative
                    // name.
                    self.zonefile.buf.next_item()?;
                    return unsafe {
                        RelativeName::from_octets_unchecked(
                            self.zonefile.buf.split_to(write).freeze(),
                        )
                        .chain(self.zonefile.get_origin()?)
                        .map_err(|_| EntryError::bad_name())
                    };
                }
            }
        }
    }

    fn scan_charstr(&mut self) -> Result<CharStr<Self::Octets>, Self::Error> {
        self.scan_octets().and_then(|octets| {
            CharStr::from_octets(octets)
                .map_err(|_| EntryError::bad_charstr())
        })
    }

    fn scan_string(&mut self) -> Result<Str<Self::Octets>, Self::Error> {
        self.zonefile.buf.require_token()?;

        // The result will never be longer than the encoded form, so we can
        // trim off everything to the left already.
        self.zonefile.buf.trim_to(self.zonefile.buf.start);

        // Skip over symbols that don’t need converting at the beginning.
        while self.zonefile.buf.next_char_symbol()?.is_some() {}

        // If we aren’t done yet, we have escaped characters to replace.
        let mut write = self.zonefile.buf.start;
        while let Some(sym) = self.zonefile.buf.next_symbol()? {
            write += sym
                .into_char()?
                .encode_utf8(
                    &mut self.zonefile.buf.buf
                        [write..self.zonefile.buf.start],
                )
                .len();
        }

        // Done. `write` marks the end.
        self.zonefile.buf.next_item()?;
        Ok(unsafe {
            Str::from_utf8_unchecked(
                self.zonefile.buf.split_to(write).freeze(),
            )
        })
    }

    fn scan_charstr_entry(&mut self) -> Result<Self::Octets, Self::Error> {
        // Because char-strings are never longer than their representation
        // format, we can definitely do this in place. Specifically, we move
        // the content around in such a way that by the end we have the result
        // in the space of buf before buf.start.

        // Reminder: char-string are one length byte followed by that many
        // content bytes. We use the byte just before self.read as the length
        // byte of the first char-string. This way, if there is only one and
        // it isn’t escaped, we don’t need to move anything at all.

        // Let’s prepare everything. We cut off the bits we don’t need with
        // the result that the buffer’s start will be 1 and we set `write`
        // to be 0, i.e., the start of the buffer. This also means that write
        // will contain the length of the domain name assembled so far, so we
        // can easily check if it has gotten too long.
        assert!(self.zonefile.buf.start > 0, "missing token prefix space");
        self.zonefile.buf.trim_to(self.zonefile.buf.start - 1);
        let mut write = 0;

        // Now convert token by token.
        loop {
            self.convert_charstr(&mut write)?;
            if self.zonefile.buf.is_line_feed() {
                break;
            }
        }

        Ok(self.zonefile.buf.split_to(write).freeze())
    }

    fn scan_opt_unknown_marker(&mut self) -> Result<bool, Self::Error> {
        self.zonefile.buf.skip_unknown_marker()
    }

    fn octets_builder(&mut self) -> Result<Self::OctetsBuilder, Self::Error> {
        Ok(BytesMut::new())
    }
}

impl<'a> EntryScanner<'a> {
    /// Converts a single token using a token converter.
    fn convert_one_token<
        S: From<Symbol>,
        C: ConvertSymbols<S, EntryError>,
    >(
        &mut self,
        convert: &mut C,
        write: &mut usize,
        builder: &mut Option<BytesMut>,
    ) -> Result<(), EntryError> {
        self.zonefile.buf.require_token()?;
        while let Some(sym) = self.zonefile.buf.next_symbol()? {
            if let Some(data) = convert.process_symbol(sym.into())? {
                self.append_data(data, write, builder);
            }
        }
        self.zonefile.buf.next_item()
    }

    /// Appends output data.
    ///
    /// If the data fits into the portion of the buffer before the current
    /// read positiion, puts it there. Otherwise creates a new builder. If
    /// it created a new builder or if one was passed in via `builder`,
    /// appends the data to that.
    fn append_data(
        &mut self,
        data: &[u8],
        write: &mut usize,
        builder: &mut Option<BytesMut>,
    ) {
        if let Some(builder) = builder.as_mut() {
            builder.extend_from_slice(data);
            return;
        }

        let new_write = *write + data.len();
        if new_write > self.zonefile.buf.start {
            let mut new_builder = BytesMut::with_capacity(new_write);
            new_builder.extend_from_slice(&self.zonefile.buf.buf[..*write]);
            new_builder.extend_from_slice(data);
            *builder = Some(new_builder);
        } else {
            self.zonefile.buf.buf[*write..new_write].copy_from_slice(data);
            *write = new_write;
        }
    }

    /// Converts a single label of a domain name.
    ///
    /// The next symbol of the buffer should be the first symbol of the
    /// label’s content. The method reads symbols from the buffer and
    /// constructs a single label complete with length octets starting at
    /// `write`.
    ///
    /// If it reaches the end of the token before making a label, returns
    /// `None`. Otherwise returns whether it encountered a dot at the end of
    /// the label. I.e., `Some(true)` means a dot was read as the last symbol
    /// and `Some(false)` means the end of token was encountered right after
    /// the label.
    fn convert_label(
        &mut self,
        write: &mut usize,
    ) -> Result<Option<bool>, EntryError> {
        let start = *write;
        *write += 1;
        let latest = *write + 64; // If write goes here, the label is too long
        if *write == self.zonefile.buf.start {
            // Reading and writing position is equal, so we don’t need to
            // convert char symbols. Read char symbols until the end of label
            // or an escape sequence.
            loop {
                match self.zonefile.buf.next_ascii_symbol()? {
                    Some(b'.') => {
                        // We found an unescaped dot, ie., end of label.
                        // Update the length octet and return.
                        self.zonefile.buf.buf[start] =
                            (*write - start - 1) as u8;
                        return Ok(Some(true));
                    }
                    Some(_) => {
                        // A char symbol. Just increase the write index.
                        *write += 1;
                        if *write >= latest {
                            return Err(EntryError::bad_name());
                        }
                    }
                    None => {
                        // Either we got an escape sequence or we reached the
                        // end of the token. Break out of the loop and decide
                        // below.
                        break;
                    }
                }
            }
        }

        // Now we need to process the label with potential escape sequences.
        loop {
            match self.zonefile.buf.next_symbol()? {
                None => {
                    // We reached the end of the token.
                    if *write > start + 1 {
                        self.zonefile.buf.buf[start] =
                            (*write - start - 1) as u8;
                        return Ok(Some(false));
                    } else {
                        // There’s been nothing. Reset the write position
                        // and return.
                        *write = start;
                        return Ok(None);
                    }
                }
                Some(Symbol::Char('.')) => {
                    // We found an unescaped dot, ie., end of label.
                    // Update the length octet and return.
                    self.zonefile.buf.buf[start] = (*write - start - 1) as u8;
                    return Ok(Some(true));
                }
                Some(sym) => {
                    // Any other symbol: Decode it and proceed to the next
                    // route.
                    self.zonefile.buf.buf[*write] = sym.into_octet()?;
                    *write += 1;
                    if *write >= latest {
                        return Err(EntryError::bad_name());
                    }
                }
            }
        }
    }

    /// Converts a character string.
    fn convert_charstr(
        &mut self,
        write: &mut usize,
    ) -> Result<(), EntryError> {
        let start = *write;
        *write += 1;
        let latest = *write + 255; // If write goes here, charstr is too long
        if *write == self.zonefile.buf.start {
            // Reading and writing position is equal, so we don’t need to
            // convert char symbols. Read char symbols until the end of label
            // or an escape sequence.
            while self.zonefile.buf.next_ascii_symbol()?.is_some() {
                *write += 1;
                if *write > latest {
                    return Err(EntryError::bad_charstr());
                }
            }
        }

        // Now we need to process the charstr with potential escape sequences.
        loop {
            match self.zonefile.buf.next_symbol()? {
                None => {
                    self.zonefile.buf.next_item()?;
                    self.zonefile.buf.buf[start] = (*write - start - 1) as u8;
                    return Ok(());
                }
                Some(sym) => {
                    self.zonefile.buf.buf[*write] = sym.into_octet()?;
                    *write += 1;
                    if *write > latest {
                        return Err(EntryError::bad_charstr());
                    }
                }
            }
        }
    }
}

//------------ SourceBuf -----------------------------------------------------

/// The buffer to read data from and also into if possible.
#[derive(Clone, Debug)]
struct SourceBuf {
    /// The underlying ‘real’ buffer.
    ///
    /// This buffer contains the data we still need to process. This contains
    /// the white space and other octets just before the start of the next
    /// token as well since that can be used as extra space for in-place
    /// manipulations.
    buf: BytesMut,

    /// Where in `buf` is the next symbol to read.
    start: usize,

    /// The category of the current item.
    cat: ItemCat,

    /// Is the token preceeded by white space?
    has_space: bool,

    /// How many unclosed opening parentheses did we see at `start`?
    parens: usize,

    /// The line number of the current line.
    line_num: usize,

    /// The position of the first character of the current line.
    ///
    /// This may be negative if we cut off bits of the current line.
    line_start: isize,
}

impl SourceBuf {
    /// Create a new empty buffer.
    ///
    /// Assumes that `buf` is empty. Adds a single byte to the buffer which
    /// we would need for parsing if the first token is a domain name.
    fn with_empty_buf(mut buf: BytesMut) -> Self {
        buf.put_u8(0);
        SourceBuf {
            buf,
            start: 1,
            cat: ItemCat::None,
            has_space: false,
            parens: 0,
            line_num: 1,
            line_start: 1,
        }
    }

    /// Enriches an entry error with position information.
    fn error(&self, err: EntryError) -> Error {
        Error {
            err,
            line: self.line_num,
            col: ((self.start as isize) + 1 - self.line_start) as usize,
        }
    }

    /// Checks whether the current item is a token.
    fn require_token(&self) -> Result<(), EntryError> {
        match self.cat {
            ItemCat::None => Err(EntryError::short_buf()),
            ItemCat::LineFeed => Err(EntryError::end_of_entry()),
            ItemCat::Quoted | ItemCat::Unquoted => Ok(()),
        }
    }

    /// Returns whether the current item is a line feed.
    fn is_line_feed(&self) -> bool {
        matches!(self.cat, ItemCat::LineFeed)
    }

    /// Requires that we have reached a line feed.
    fn require_line_feed(&self) -> Result<(), EntryError> {
        if self.is_line_feed() {
            Ok(())
        } else {
            Err(EntryError::trailing_tokens())
        }
    }

    /// Returns the next symbol but doesn’t advance the buffer.
    ///
    /// Returns `None` if the current item is a line feed or end-of-file
    /// or if we have reached the end of token or if it is not a valid symbol.
    fn peek_symbol(&self) -> Option<Symbol> {
        match self.cat {
            ItemCat::None | ItemCat::LineFeed => None,
            ItemCat::Unquoted => {
                let sym =
                    match Symbol::from_slice_index(&self.buf, self.start) {
                        Ok(Some((sym, _))) => sym,
                        Ok(None) | Err(_) => return None,
                    };

                if sym.is_word_char() {
                    Some(sym)
                } else {
                    None
                }
            }
            ItemCat::Quoted => {
                let sym =
                    match Symbol::from_slice_index(&self.buf, self.start) {
                        Ok(Some((sym, _))) => sym,
                        Ok(None) | Err(_) => return None,
                    };

                if sym == Symbol::Char('"') {
                    None
                } else {
                    Some(sym)
                }
            }
        }
    }

    /// Skips over the current token if it contains only an `@` symbol.
    ///
    /// Returns whether it did skip the token.
    fn skip_at_token(&mut self) -> Result<bool, EntryError> {
        if self.peek_symbol() != Some(Symbol::Char('@')) {
            return Ok(false);
        }

        let (sym, sym_end) =
            match Symbol::from_slice_index(&self.buf, self.start + 1) {
                Ok(Some((sym, sym_end))) => (sym, sym_end),
                Ok(None) => return Err(EntryError::short_buf()),
                Err(err) => return Err(EntryError::bad_symbol(err)),
            };

        match self.cat {
            ItemCat::None | ItemCat::LineFeed => unreachable!(),
            ItemCat::Unquoted => {
                if !sym.is_word_char() {
                    self.start += 1;
                    self.cat = ItemCat::None;
                    self.next_item()?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ItemCat::Quoted => {
                if sym == Symbol::Char('"') {
                    self.start = sym_end;
                    self.cat = ItemCat::None;
                    self.next_item()?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Skips over the unknown marker token.
    ///
    /// Returns whether it didskip the token.
    fn skip_unknown_marker(&mut self) -> Result<bool, EntryError> {
        if !matches!(self.cat, ItemCat::Unquoted) {
            return Ok(false);
        }

        let (sym, sym_end) =
            match Symbol::from_slice_index(&self.buf, self.start) {
                Ok(Some(some)) => some,
                _ => return Ok(false),
            };

        if sym != Symbol::SimpleEscape(b'#') {
            return Ok(false);
        }

        let (sym, sym_end) =
            match Symbol::from_slice_index(&self.buf, sym_end) {
                Ok(Some(some)) => some,
                _ => return Ok(false),
            };
        if sym.is_word_char() {
            return Ok(false);
        }

        self.start = sym_end;
        self.cat = ItemCat::None;
        self.next_item()?;
        Ok(true)
    }

    /// Returns the next symbol of the current token.
    ///
    /// Returns `None` if the current item is a line feed or end-of-file
    /// or if we have reached the end of token.
    ///
    /// If it returns `Some(_)`, advances `self.start` to the start of the
    /// next symbol.
    fn next_symbol(&mut self) -> Result<Option<Symbol>, EntryError> {
        self._next_symbol(|sym| Ok(Some(sym)))
    }

    /// Returns the next symbol if it is an unescaped ASCII symbol.
    ///
    /// Returns `None` if the symbol is escaped or not a printable ASCII
    /// character or `self.next_symbol` would return `None`.
    ///
    /// If it returns `Some(_)`, advances `self.start` to the start of the
    /// next symbol.
    #[allow(clippy::manual_range_contains)] // Hard disagree.
    fn next_ascii_symbol(&mut self) -> Result<Option<u8>, EntryError> {
        if matches!(self.cat, ItemCat::None | ItemCat::LineFeed) {
            return Ok(None);
        }

        let ch = match self.buf.get(self.start) {
            Some(ch) => *ch,
            None => return Ok(None),
        };

        match self.cat {
            ItemCat::Unquoted => {
                if ch < 0x21
                    || ch > 0x7F
                    || ch == b'"'
                    || ch == b'('
                    || ch == b')'
                    || ch == b';'
                    || ch == b'\\'
                {
                    return Ok(None);
                }
            }
            ItemCat::Quoted => {
                if ch == b'"' {
                    self.start += 1;
                    self.cat = ItemCat::None;
                    return Ok(None);
                } else if ch < 0x21 || ch > 0x7F || ch == b'\\' {
                    return Ok(None);
                }
            }
            _ => unreachable!(),
        }
        self.start += 1;
        Ok(Some(ch))
    }

    /// Returns the next symbol if it is unescaped.
    ///
    /// Returns `None` if the symbol is escaped or `self.next_symbol` would
    /// return `None`.
    ///
    /// If it returns `Some(_)`, advances `self.start` to the start of the
    /// next symbol.
    fn next_char_symbol(&mut self) -> Result<Option<char>, EntryError> {
        self._next_symbol(|sym| {
            if let Symbol::Char(ch) = sym {
                Ok(Some(ch))
            } else {
                Ok(None)
            }
        })
    }

    /// Internal helper for `next_symbol` and friends.
    ///
    /// This only exists so we don’t have to copy and paste the fiddely part
    /// of the logic. It behaves like `next_symbol` but provides an option
    /// for the called to decide whether they want the symbol or not.
    #[inline]
    fn _next_symbol<F, T>(&mut self, want: F) -> Result<Option<T>, EntryError>
    where
        F: Fn(Symbol) -> Result<Option<T>, EntryError>,
    {
        match self.cat {
            ItemCat::None | ItemCat::LineFeed => Ok(None),
            ItemCat::Unquoted => {
                let (sym, sym_end) =
                    match Symbol::from_slice_index(&self.buf, self.start) {
                        Ok(Some((sym, sym_end))) => (sym, sym_end),
                        Ok(None) => return Err(EntryError::short_buf()),
                        Err(err) => return Err(EntryError::bad_symbol(err)),
                    };

                if !sym.is_word_char() {
                    self.cat = ItemCat::None;
                    Ok(None)
                } else {
                    match want(sym)? {
                        Some(some) => {
                            self.start = sym_end;
                            Ok(Some(some))
                        }
                        None => Ok(None),
                    }
                }
            }
            ItemCat::Quoted => {
                let (sym, sym_end) =
                    match Symbol::from_slice_index(&self.buf, self.start) {
                        Ok(Some((sym, sym_end))) => (sym, sym_end),
                        Ok(None) => return Err(EntryError::short_buf()),
                        Err(err) => return Err(EntryError::bad_symbol(err)),
                    };

                let res = match want(sym)? {
                    Some(some) => some,
                    None => return Ok(None),
                };

                if sym == Symbol::Char('"') {
                    self.start = sym_end;
                    self.cat = ItemCat::None;
                    Ok(None)
                } else {
                    self.start = sym_end;
                    if sym == Symbol::Char('\n') {
                        self.line_num += 1;
                        self.line_start = self.start as isize;
                    }
                    Ok(Some(res))
                }
            }
        }
    }

    /// Prepares the next item.
    ///
    /// # Panics
    ///
    /// This method must only ever by called if the current item is
    /// not a token or if the current token has been read all the way to the
    /// end. The latter is true if [`Self::next_symbol`] has returned
    /// `Ok(None)` at least once.
    ///
    /// If the current item is a token and has not been read all the way to
    /// the end, the method will panic to maintain consistency of the data.
    fn next_item(&mut self) -> Result<(), EntryError> {
        assert!(
            matches!(self.cat, ItemCat::None | ItemCat::LineFeed),
            "token not completely read ({:?} at {}:{})",
            self.cat,
            self.line_num,
            ((self.start as isize) + 1 - self.line_start) as usize,
        );

        self.has_space = false;

        loop {
            let ch = match self.buf.get(self.start) {
                Some(&ch) => ch,
                None => {
                    self.cat = ItemCat::None;
                    return Ok(());
                }
            };

            // Skip and mark actual white space.
            if matches!(ch, b' ' | b'\t' | b'\r') {
                self.has_space = true;
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
                } else {
                    return Err(EntryError::unbalanced_parens());
                }
            }
            // Semicolon: comment -- skip to line end.
            else if ch == b';' {
                self.start += 1;
                while let Some(true) =
                    self.buf.get(self.start).map(|ch| *ch != b'\n')
                {
                    self.start += 1;
                }
                // Next iteration deals with the LF.
            }
            // Line end: skip over it. Ignore if we are inside a paren group.
            else if ch == b'\n' {
                self.start += 1;
                self.line_num += 1;
                self.line_start = self.start as isize;
                if self.parens == 0 {
                    self.cat = ItemCat::LineFeed;
                    break;
                }
            }
            // Double quote: quoted token
            else if ch == b'"' {
                self.start += 1;
                self.cat = ItemCat::Quoted;
                break;
            }
            // Else: unquoted token
            else {
                self.cat = ItemCat::Unquoted;
                break;
            }
        }
        Ok(())
    }

    /// Splits off the beginning of the buffer up to the given index.
    ///
    /// # Panics
    ///
    /// The method panics if `at` is greater than `self.start`.
    fn split_to(&mut self, at: usize) -> BytesMut {
        assert!(at <= self.start);
        let res = self.buf.split_to(at);
        self.start -= at;
        self.line_start -= at as isize;
        res
    }

    /// Splits off the beginning of the buffer but doesn’t return it.
    ///
    /// # Panics
    ///
    /// The method panics if `at` is greater than `self.start`.
    fn trim_to(&mut self, at: usize) {
        assert!(at <= self.start);
        self.buf.advance(at);
        self.start -= at;
        self.line_start -= at as isize;
    }
}

//------------ ItemCat -------------------------------------------------------

/// The category of the current item in a source buffer.
#[allow(dead_code)] // XXX
#[derive(Clone, Copy, Debug)]
enum ItemCat {
    /// We don’t currently have an item.
    ///
    /// This is used to indicate that we have reached the end of a token or
    /// that we have reached the end of the buffer.
    //
    // XXX: We might need a separate category for EOF. But let’s see if we
    //      can get away with mixing this up, first.
    None,

    /// An unquoted normal token.
    ///
    /// This is a token that did not start with a double quote and will end
    /// at the next white space.
    Unquoted,

    /// A quoted normal token.
    ///
    /// This is a token that did start with a double quote and will end at
    /// the next unescaped double quote.
    ///
    /// Note that the start position of the buffer indicates the first
    /// character that is part of the content, i.e., the position right after
    /// the opening double quote.
    Quoted,

    /// A line feed.
    ///
    /// This is an empty token. The start position is right after the actual
    /// line feed.
    LineFeed,
}

//------------ EntryError ----------------------------------------------------

/// An error returned by the entry scanner.
#[derive(Debug)]
struct EntryError(&'static str);

impl EntryError {
    fn bad_symbol(_err: SymbolOctetsError) -> Self {
        EntryError("bad symbol")
    }

    fn bad_charstr() -> Self {
        EntryError("bad charstr")
    }

    fn bad_name() -> Self {
        EntryError("bad name")
    }

    fn unbalanced_parens() -> Self {
        EntryError("unbalanced parens")
    }

    fn missing_last_owner() -> Self {
        EntryError("missing last owner")
    }

    fn missing_last_class() -> Self {
        EntryError("missing last class")
    }

    fn missing_last_ttl() -> Self {
        EntryError("missing last ttl")
    }

    fn missing_origin() -> Self {
        EntryError("missing origin")
    }

    fn expected_rtype() -> Self {
        EntryError("expected rtype")
    }

    fn unknown_control() -> Self {
        EntryError("unknown control")
    }
}

impl ScannerError for EntryError {
    fn custom(msg: &'static str) -> Self {
        EntryError(msg)
    }

    fn end_of_entry() -> Self {
        Self("unexpected end of entry")
    }

    fn short_buf() -> Self {
        Self("short buffer")
    }

    fn trailing_tokens() -> Self {
        Self("trailing tokens")
    }
}

impl From<SymbolOctetsError> for EntryError {
    fn from(_: SymbolOctetsError) -> Self {
        EntryError("symbol octets error")
    }
}

impl From<BadSymbol> for EntryError {
    fn from(_: BadSymbol) -> Self {
        EntryError("bad symbol")
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EntryError {}

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

#[cfg(feature = "std")]
impl std::error::Error for Error {}

//============ Tests =========================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::ParsedName;
    use octseq::Parser;
    use std::vec::Vec;

    fn with_entry(s: &str, op: impl FnOnce(EntryScanner)) {
        let mut zone = Zonefile::with_capacity(s.len());
        zone.extend_from_slice(s.as_bytes());
        let entry = EntryScanner::new(&mut zone).unwrap();
        entry.zonefile.buf.next_item().unwrap();
        op(entry)
    }

    #[test]
    fn scan_symbols() {
        fn test(zone: &str, tok: impl AsRef<[u8]>) {
            with_entry(zone, |mut entry| {
                let mut tok = tok.as_ref();
                entry
                    .scan_symbols(|sym| {
                        let sym = sym.into_octet().unwrap();
                        assert_eq!(sym, tok[0]);
                        tok = &tok[1..];
                        Ok(())
                    })
                    .unwrap();
            });
        }

        test(" unquoted\n", b"unquoted");
        test(" unquoted  ", b"unquoted");
        test("unquoted ", b"unquoted");
        test("unqu\\oted ", b"unquoted");
        test("unqu\\111ted ", b"unquoted");
        test(" \"quoted\"\n", b"quoted");
        test(" \"quoted\" ", b"quoted");
        test("\"quoted\" ", b"quoted");
    }

    #[derive(serde::Deserialize)]
    #[allow(clippy::type_complexity)]
    struct TestCase {
        origin: Name<Bytes>,
        zonefile: std::string::String,
        result: Vec<Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>>>,
    }

    impl TestCase {
        fn test(yaml: &str) {
            let case = serde_yaml::from_str::<Self>(yaml).unwrap();
            let mut input = case.zonefile.as_bytes();
            let mut zone = Zonefile::load(&mut input).unwrap();
            zone.set_origin(case.origin);
            let mut result = case.result.as_slice();
            while let Some(entry) = zone.next_entry().unwrap() {
                match entry {
                    Entry::Record(record) => {
                        let (first, tail) = result.split_first().unwrap();
                        assert_eq!(first, &record);
                        result = tail;

                        let mut buf = BytesMut::new();
                        record.compose(&mut buf).unwrap();
                        let buf = buf.freeze();
                        let mut parser = Parser::from_ref(&buf);
                        let parsed =
                            Record::<
                                ParsedName<Bytes>,
                                ZoneRecordData<Bytes, ParsedName<Bytes>>,
                            >::parse(&mut parser)
                            .unwrap()
                            .unwrap();

                        // The unknown test case has known type/class
                        // to current implementation. The parsed
                        // record will not be unknown again. So here
                        // we don't compare it with the original.
                        if !matches!(
                            record.data(),
                            ZoneRecordData::Unknown(_)
                        ) {
                            assert_eq!(first, &parsed);
                        }
                    }
                    _ => panic!(),
                }
            }
        }
    }

    #[test]
    fn test_basic_yaml() {
        TestCase::test(include_str!("../../test-data/zonefiles/basic.yaml"));
    }

    #[test]
    fn test_escape_yaml() {
        TestCase::test(include_str!("../../test-data/zonefiles/escape.yaml"));
    }

    #[test]
    fn test_unknown_yaml() {
        TestCase::test(include_str!(
            "../../test-data/zonefiles/unknown.yaml"
        ));
    }

    #[test]
    fn test_chrstr_decoding() {
        TestCase::test(include_str!("../../test-data/zonefiles/strlen.yaml"));
    }

    #[test]
    #[should_panic(expected = "character string with more than 255 octets")]
    fn test_chrstr_overflow_decoding() {
        TestCase::test(include_str!(
            "../../test-data/zonefiles/stroverflow.yaml"
        ));
    }
}
