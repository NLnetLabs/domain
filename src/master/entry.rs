/// A master file entry.

use std::rc::Rc;
use ::bits::DNameBuf;
use ::iana::Class;
use ::master::{Pos, ScanResult, Scanner, SyntaxError};
use ::master::record::{MasterRecord, map_origin};


//------------ Entry ---------------------------------------------------------

/// A master file entry.
///
/// Master files consist of a sequence of entries. An entry contains data for
/// a resource record or instructions on how to build resource records from
/// the data.
///
/// This enum has variants for each type of master file entries currently
/// defined. It also knows how to scan itself from a scanner via the
/// `scan()` function.
///
/// The variants are defined in seciton 5 of [RFC 1035] except where
/// otherwise stated below.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone, Debug)]
pub enum Entry {
    /// An `$ORIGIN` control entry.
    ///
    /// This entry contains the origin for relative domain names encountered
    /// in subsequent entries.
    Origin(Rc<DNameBuf>),
    
    /// An `$INCLUDE` control entry.
    ///
    /// This entry instructs the parser to insert the content of the given
    /// file at this position. The `path` attribute specifies the path to
    /// the file. The interpretation of the contents of this attribute is
    /// system dependent. The optional `origin` attribute contains the
    /// initial value of the origin of relative domain names when including
    /// the file.
    Include { path: Vec<u8>, origin: Option<Rc<DNameBuf>> },

    /// A `$TTL` control entry.
    ///
    /// This entry specifies the value of the TTL field for all subsequent
    /// records that do not have it explicitely stated.
    ///
    /// This entry is defined in section 4 of [RFC 2308].
    ///
    /// [RFC 2308]: https://tools.ietf.org/html/rfc2308
    Ttl(u32),

    /// Some other control entry.
    ///
    /// Any other entry starting with a dollar sign is a control entry we
    /// do not understand. This variant contains the name of the entry in
    /// the `name` attribute and its starting position in `start`. This can
    /// be used to produce a meaningful warning or error message.
    Control { name: Vec<u8>, start: Pos },

    /// A resource record.
    Record(MasterRecord),

    /// A blank entry.
    Blank
}

impl Entry {
    /// Scans an entry from a scanner.
    ///
    /// The four additional arguments contain the state of scanning for
    /// entries.
    ///
    /// The `last_owner` contains the domain name of the last
    /// record entry unless this is the first entry. This is used for the
    /// `owner` field if a record entry starts with blanks.
    /// The `last_class` is the class of the last resource record and is
    /// used if a class value is missing from a record entry.
    /// The `origin`
    /// argument is used for any relative names given in a record entry.
    /// The `default_ttl` value is used if a TTL value is missing from a
    /// record entry.
    ///
    /// If successful, the function returns some entry or `None` if it
    /// encountered an end of file before an entry even started.
    pub fn scan<S: Scanner>(stream: &mut S,
                             last_owner: Option<Rc<DNameBuf>>,
                             last_class: Option<Class>,
                             origin: &Option<Rc<DNameBuf>>,
                             default_ttl: Option<u32>)
                             -> ScanResult<Option<Self>> {
        if stream.is_eof() {
            Ok(None)
        }
        else if let Ok(entry) = Entry::scan_control(stream, origin) {
            Ok(Some(entry))
        }
        else if let Ok(record) = MasterRecord::scan(stream, last_owner,
                                                    last_class, origin,
                                                    default_ttl) {
            Ok(Some(Entry::Record(record)))
        }
        else {
            try!(stream.scan_opt_space());
            try!(stream.scan_newline());
            Ok(Some(Entry::Blank))
        }
    }

    /// Tries to scan a control entry.
    fn scan_control<S: Scanner>(stream: &mut S, origin: &Option<Rc<DNameBuf>>)
                                -> ScanResult<Self> {
        match try!(ControlType::scan(stream)) {
            ControlType::Origin => {
                let origin = map_origin(origin);
                let name = try!(stream.scan_dname(origin));
                try!(stream.scan_newline());
                Ok(Entry::Origin(Rc::new(name)))
            }
            ControlType::Include => {
                let path = try!(stream.scan_phrase_copy());
                let origin = stream.scan_dname(map_origin(origin))
                                      .map(Rc::new).ok();
                try!(stream.scan_newline());
                Ok(Entry::Include { path: path, origin: origin })
            }
            ControlType::Ttl => {
                let ttl = try!(stream.scan_u32());
                try!(stream.scan_newline());
                Ok(Entry::Ttl(ttl))
            }
            ControlType::Other(name, pos) => {
                try!(stream.skip_entry());
                Ok(Entry::Control { name: name, start: pos })
            }
        }
    }
}


//------------ ControlType ---------------------------------------------------

/// The type of a control entry.
#[derive(Clone, Debug)]
enum ControlType {
    Origin,
    Include,
    Ttl,
    Other(Vec<u8>, Pos)
}

impl ControlType {
    fn scan<S: Scanner>(stream: &mut S) -> ScanResult<Self> {
        let pos = stream.pos();
        stream.scan_word(|word| {
            if word.eq_ignore_ascii_case(b"$ORIGIN") {
                Ok(ControlType::Origin)
            }
            else if word.eq_ignore_ascii_case(b"$INCLUDE") {
                Ok(ControlType::Include)
            }
            else if word.eq_ignore_ascii_case(b"$TTL") {
                Ok(ControlType::Ttl)
            }
            else if let Some(&b'$') = word.get(0) {
                Ok(ControlType::Other(word.to_owned(), pos))
            }
            else {
                Err(SyntaxError::Expected(vec![b'$']))
            }
        })
    }
}

