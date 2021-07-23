use super::scan::{CharSource, Pos, Scanner};
use crate::base::iana::{Class, Rtype};
use crate::base::name::Dname;
use crate::base::record::Record;
use crate::rdata::MasterRecordData;
use crate::scan::{Scan, ScanError, SyntaxError};
use bytes::Bytes;
/// A master file entry.
use std::borrow::ToOwned;
use std::path::PathBuf;
use std::string::String;

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
    Origin(Dname<Bytes>),

    /// An `$INCLUDE` control entry.
    ///
    /// This entry instructs the parser to insert the content of the given
    /// file at this position. The `path` attribute specifies the path to
    /// the file. The interpretation of the contents of this attribute is
    /// system dependent. The optional `origin` attribute contains the
    /// initial value of the origin of relative domain names when including
    /// the file.
    Include {
        path: PathBuf,
        origin: Option<Dname<Bytes>>,
    },

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
    Control { name: String, start: Pos },

    /// A resource record.
    Record(MasterRecord),

    /// A blank entry.
    Blank,
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
    pub fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
        last_owner: Option<&Dname<Bytes>>,
        last_class: Option<Class>,
        default_ttl: Option<u32>,
    ) -> Result<Option<Self>, ScanError> {
        if scanner.eof_reached() {
            Ok(None)
        } else if let Ok(entry) = Self::scan_control(scanner) {
            Ok(Some(entry))
        } else if let Ok(()) = Self::scan_blank(scanner) {
            Ok(Some(Entry::Blank))
        } else {
            let record = Self::scan_record(
                scanner,
                last_owner,
                last_class,
                default_ttl,
            )?;
            Ok(Some(Entry::Record(record)))
        }
    }

    fn scan_blank<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<(), ScanError> {
        scanner.scan_opt_space()?;
        scanner.scan_newline()?;
        Ok(())
    }

    /// Tries to scan a control entry.
    fn scan_control<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        match ControlType::scan(scanner)? {
            ControlType::Origin => {
                let name = Dname::scan(scanner)?;
                scanner.scan_newline()?;
                Ok(Entry::Origin(name))
            }
            ControlType::Include => {
                let path = scanner.scan_string_phrase(|x| Ok(x.into()))?;
                let origin = Dname::scan(scanner).ok();
                scanner.scan_newline()?;
                Ok(Entry::Include { path, origin })
            }
            ControlType::Ttl => {
                let ttl = u32::scan(scanner)?;
                scanner.scan_newline()?;
                Ok(Entry::Ttl(ttl))
            }
            ControlType::Other(name, pos) => {
                scanner.skip_entry()?;
                Ok(Entry::Control { name, start: pos })
            }
        }
    }

    fn scan_record<C: CharSource>(
        scanner: &mut Scanner<C>,
        last_owner: Option<&Dname<Bytes>>,
        last_class: Option<Class>,
        default_ttl: Option<u32>,
    ) -> Result<MasterRecord, ScanError> {
        let owner = Self::scan_owner(scanner, last_owner)?;
        let (ttl, class) =
            Self::scan_ttl_class(scanner, last_class, default_ttl)?;
        let rtype = Rtype::scan(scanner)?;
        let rdata = MasterRecordData::scan(rtype, scanner)?;
        scanner.scan_newline()?;
        Ok(Record::new(owner, class, ttl, rdata))
    }

    fn scan_owner<C: CharSource>(
        scanner: &mut Scanner<C>,
        last_owner: Option<&Dname<Bytes>>,
    ) -> Result<Dname<Bytes>, ScanError> {
        let pos = scanner.pos();
        if let Ok(()) = scanner.scan_space() {
            if let Some(owner) = last_owner {
                Ok(owner.clone())
            } else {
                Err(ScanError::Syntax(SyntaxError::NoLastOwner, pos))
            }
        } else if let Ok(()) = scanner.skip_literal("@") {
            if let Some(ref origin) = *scanner.origin() {
                Ok(origin.clone())
            } else {
                Err(ScanError::Syntax(SyntaxError::NoOrigin, pos))
            }
        } else {
            Dname::scan(scanner)
        }
    }

    fn scan_ttl_class<C: CharSource>(
        scanner: &mut Scanner<C>,
        last_class: Option<Class>,
        default_ttl: Option<u32>,
    ) -> Result<(u32, Class), ScanError> {
        let pos = scanner.pos();
        let (ttl, class) = match u32::scan(scanner) {
            Ok(ttl) => match Class::scan(scanner) {
                Ok(class) => (Some(ttl), Some(class)),
                Err(_) => (Some(ttl), None),
            },
            Err(_) => match Class::scan(scanner) {
                Ok(class) => match u32::scan(scanner) {
                    Ok(ttl) => (Some(ttl), Some(class)),
                    Err(_) => (None, Some(class)),
                },
                Err(_) => (None, None),
            },
        };
        let ttl = match ttl.or(default_ttl) {
            Some(ttl) => ttl,
            None => {
                return Err(ScanError::Syntax(SyntaxError::NoDefaultTtl, pos))
            }
        };
        let class = match class.or(last_class) {
            Some(class) => class,
            None => {
                return Err(ScanError::Syntax(SyntaxError::NoLastClass, pos))
            }
        };
        Ok((ttl, class))
    }
}

//------------ ControlType ---------------------------------------------------

/// The type of a control entry.
#[derive(Clone, Debug)]
enum ControlType {
    Origin,
    Include,
    Ttl,
    Other(String, Pos),
}

impl Scan for ControlType {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        let pos = scanner.pos();
        scanner.scan_string_word(|word| {
            if word.eq_ignore_ascii_case("$ORIGIN") {
                Ok(ControlType::Origin)
            } else if word.eq_ignore_ascii_case("$INCLUDE") {
                Ok(ControlType::Include)
            } else if word.eq_ignore_ascii_case("$TTL") {
                Ok(ControlType::Ttl)
            } else if let Some('$') = word.chars().next() {
                Ok(ControlType::Other(word.to_owned(), pos))
            } else {
                Err(SyntaxError::Expected(String::from("$")))
            }
        })
    }
}

//------------ MasterRecord --------------------------------------------------

pub type MasterRecord =
    Record<Dname<Bytes>, MasterRecordData<Bytes, Dname<Bytes>>>;
